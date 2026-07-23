// Command agent is the entry point for the MYFW execution-plane service.
//
// It runs on each managed Linux host as a bare-metal systemd service:
//  1. Loads /etc/myfw-agent/agent.yaml.
//  2. Ensures a stable node id under /var/lib/myfw-agent.
//  3. Probes host capabilities (iptables/nftables/docker/kubernetes).
//  4. On first launch: registers with the Controller using a one-time
//     bootstrap token and persists the returned client certificate.
//  5. Opens an mTLS long-lived stream to the Controller and pushes heartbeats.
//
// The Firewall Drivers land in M5.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	myfwv1 "iptables-tool/api/myfw/v1"
	"iptables-tool/internal/agent/bootstrap"
	"iptables-tool/internal/agent/capability"
	agentcfg "iptables-tool/internal/agent/config"
	"iptables-tool/internal/agent/conn"
	agentdriver "iptables-tool/internal/agent/driver"
	iptdriver "iptables-tool/internal/agent/driver/iptables"
	"iptables-tool/internal/agent/handler"
	"iptables-tool/internal/agent/watchdog"
)

// version is overridden at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "agent:", err)
		os.Exit(1)
	}
}

func run() error {
	configPath := flag.String("config", "/etc/myfw-agent/agent.yaml", "path to config file")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("myfw-agent %s\n", version)
		return nil
	}

	cfg, err := agentcfg.Load(*configPath)
	if err != nil {
		return err
	}

	log := newLogger()
	log.Info("starting myfw-agent", "version", version, "config", *configPath)

	// 1. Stable node identity.
	id, err := bootstrap.LoadOrCreateIdentity(cfg.Node.DataDir)
	if err != nil {
		return err
	}
	log.Info("node identity ready", "node_id", id.NodeID)

	// 2. Capability probe.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	cap := capability.Detect(ctx)
	log.Info("capabilities detected",
		"distro", cap.Distro,
		"iptables", cap.IptablesVersion,
		"backend", cap.SelectedBackend.String(),
		"nft", cap.NftSupported,
		"docker", cap.DockerPresent,
		"k8s", cap.KubernetesPresent,
	)

	// 3. First-time bootstrap (only if we don't already have a client cert).
	nodeID := id.NodeID
	if !cfg.Bootstrapped() {
		if err := cfg.RequireForBootstrap(); err != nil {
			return err
		}
		log.Info("running first-time bootstrap")

		bootConn, err := conn.Dial(ctx, cfg.Controller.Endpoint, conn.TLSMaterial{
			CAFile:        cfg.Controller.TLS.CAFile,
			ServerName:    cfg.Controller.ServerName,
			BootstrapOnly: true,
		})
		if err != nil {
			return err
		}
		regClient := myfwv1.NewRegistrationClient(bootConn)

		regCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		res, err := bootstrap.Do(regCtx, regClient, id.NodeID, cfg.Controller.BootstrapToken,
			bootstrap.MachineFingerprint(), cap,
			bootstrap.Persist{
				CertFile: cfg.Controller.TLS.CertFile,
				KeyFile:  cfg.Controller.TLS.KeyFile,
			})
		cancel()
		_ = bootConn.Close()
		if err != nil {
			return err
		}
		nodeID = res.NodeID
		log.Info("bootstrap complete", "node_id", res.NodeID, "status", res.NodeStatus)

		// Best-effort: strip the now-consumed token from the config file so
		// a subsequent start doesn't try to re-use it.
		if err := clearBootstrapToken(*configPath); err != nil {
			log.Warn("could not clear bootstrap_token from config", "err", err)
		}
	}

	// 4. Long-lived mTLS stream (heartbeats + task rx).
	streamConn, err := conn.Dial(ctx, cfg.Controller.Endpoint, conn.TLSMaterial{
		CAFile:     cfg.Controller.TLS.CAFile,
		CertFile:   cfg.Controller.TLS.CertFile,
		KeyFile:    cfg.Controller.TLS.KeyFile,
		ServerName: cfg.Controller.ServerName,
	})
	if err != nil {
		return err
	}
	defer streamConn.Close()

	// 5. Build the Firewall Driver matching the detected backend. On non-Linux
	//    / undetected hosts we run without a driver — heartbeats still flow
	//    but ApplyTasks are refused with a clear error.
	drv := selectDriver(cap, log)
	if drv != nil {
		if err := drv.Init(ctx); err != nil {
			log.Warn("driver init failed; agent will run without an active driver", "err", err)
			drv = nil
		} else {
			log.Info("firewall driver ready", "backend", cap.SelectedBackend.String())
		}
	}

	// The handler needs the trimmed Driver interface, but selectDriver returns
	// the full one; nil is passed through so Apply is rejected politely.
	var h *handler.Handler
	if drv != nil {
		h = handler.New(drv, log)
	} else {
		h = handler.New(nil, log)
	}

	// Create a shared send channel for drift reports (persists across reconnections).
	sendCh := make(chan *myfwv1.AgentToController, 8)

	// Start Watchdog if driver is available.
	var wd *watchdog.Watchdog
	if drv != nil {
		reporter := conn.NewReporter(log, sendCh)
		wd = watchdog.New(drv, reporter, log, watchdog.Options{
			Interval:    30 * time.Second,
			NodeID:      nodeID,
			AutoRecover: true,
		})
		h.SetHashNotifier(wd)
		wd.Start()
		log.Info("watchdog started", "interval", "30s")
		defer wd.Stop()
	}

	// Start the connection loop (blocking).
	if err := conn.Loop(ctx, streamConn, log, nodeID, cap, h, conn.HeartbeatOptions{}, sendCh); err != nil {
		return err
	}

	// Wait for shutdown signal.
	<-ctx.Done()
	return nil
}

// selectDriver picks a driver.Driver based on the probed backend. Returns nil
// when nothing usable exists (macOS dev, or Linux without iptables/nftables).
func selectDriver(cap *myfwv1.Capability, log *slog.Logger) agentdriver.Driver {
	switch cap.SelectedBackend {
	case myfwv1.FirewallBackend_FIREWALL_BACKEND_IPTABLES_LEGACY,
		myfwv1.FirewallBackend_FIREWALL_BACKEND_IPTABLES_NFT:
		return iptdriver.New(iptdriver.ShellExec{}, cap.SelectedBackend)
	case myfwv1.FirewallBackend_FIREWALL_BACKEND_NFTABLES:
		// M9 will land NftablesDriver; for now, log and drop through.
		log.Warn("nftables backend detected but NftablesDriver not yet implemented (M9)")
		return nil
	}
	return nil
}

func newLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
}

// clearBootstrapToken strips the bootstrap_token line from the YAML config so
// a restart doesn't try to use the now-consumed one-time token. We do a
// line-oriented rewrite rather than YAML round-trip to preserve the operator's
// comments and formatting.
func clearBootstrapToken(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	out := make([]byte, 0, len(raw))
	// Walk line by line; drop lines whose trimmed prefix is bootstrap_token:
	start := 0
	for i := 0; i <= len(raw); i++ {
		if i == len(raw) || raw[i] == '\n' {
			line := raw[start:i]
			trim := ltrim(line)
			if !hasPrefix(trim, "bootstrap_token:") {
				out = append(out, line...)
				if i < len(raw) {
					out = append(out, '\n')
				}
			}
			start = i + 1
		}
	}
	return os.WriteFile(path, out, 0o600)
}

func ltrim(b []byte) []byte {
	for i := 0; i < len(b); i++ {
		if b[i] != ' ' && b[i] != '\t' {
			return b[i:]
		}
	}
	return nil
}

func hasPrefix(b []byte, p string) bool {
	if len(b) < len(p) {
		return false
	}
	return string(b[:len(p)]) == p
}
