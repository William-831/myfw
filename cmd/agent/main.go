// Command agent 是 MYFW 执行面服务的入口。
//
// 运行在每个受管 Linux 主机上，作为 systemd 服务：
//  1. 加载 /etc/myfw-agent/agent.yaml。
//  2. 确保 /var/lib/myfw-agent 下的稳定节点身份。
//  3. 探测主机能力（iptables/nftables/docker/kubernetes）。
//  4. 首次启动：使用一次性引导令牌向 Controller 注册，持久化返回的客户端证书。
//  5. 打开 mTLS 长连接流并推送心跳。
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	myfwv1 "iptables-tool/api/myfw/v1"
	"iptables-tool/internal/agent/bootstrap"
	"iptables-tool/internal/agent/capability"
	agentcfg "iptables-tool/internal/agent/config"
	"iptables-tool/internal/agent/collector"
	"iptables-tool/internal/agent/conn"
	agentdriver "iptables-tool/internal/agent/driver"
	iptdriver "iptables-tool/internal/agent/driver/iptables"
	nftdriver "iptables-tool/internal/agent/driver/nftables"
	"iptables-tool/internal/agent/handler"
	"iptables-tool/internal/agent/watchdog"
	"iptables-tool/internal/security"
)

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

	// 1. 稳定节点身份
	id, err := bootstrap.LoadOrCreateIdentity(cfg.Node.DataDir)
	if err != nil {
		return err
	}
	log.Info("node identity ready", "node_id", id.NodeID)

	// 2. 能力探测
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

	// 3. 首次引导注册（若尚无客户端证书）
	nodeID := id.NodeID
	if !cfg.Bootstrapped() {
		if err := cfg.RequireForBootstrap(); err != nil {
			return err
		}
		log.Info("running first-time bootstrap")

		bootConn, err := conn.Dial(ctx, cfg.Controller.Endpoint, conn.TLSMaterial{
			Disable:       cfg.Controller.TLS.Disable,
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

		if cfg.Controller.TLS.Disable {
			donePath := cfg.Node.DataDir + "/bootstrap_done"
			if err := os.WriteFile(donePath, []byte(res.NodeID), 0600); err != nil {
				log.Warn("could not create bootstrap_done marker", "err", err)
			}
		}

		if err := clearBootstrapToken(*configPath); err != nil {
			log.Warn("could not clear bootstrap_token from config", "err", err)
		}
	}

	// renewCh: 续签成功后通知连接循环重建（加载新证书）
	renewCh := make(chan struct{}, 1)
	var rotator *security.CertRotation
	// 4. 证书自动轮换：检查是否需要轮换
	if !cfg.Controller.TLS.Disable {
		rotator = security.NewCertRotation(security.RotationConfig{
			CertTTL:     24 * time.Hour,
			RenewBefore: 5 * time.Hour,
			KeyDir:      filepath.Dir(cfg.Controller.TLS.CertFile), // 与 conn.Dial 证书路径一致,避免续签后仍用旧证书
			Logger:      log,
		})
		if err := rotator.LoadExisting(); err == nil && rotator.NeedsRotation() {
			log.Info("certificate nearing expiry, requesting renewal")
			if err := requestCertRenewal(ctx, cfg, nodeID, rotator, cap, "auto"); err != nil {
				log.Warn("certificate renewal failed, will retry on next restart", "err", err)
			}
		}
		// 启动后台轮换循环
		rotator.StartRotationLoop(ctx, func(ctx context.Context) error {
			err := requestCertRenewal(ctx, cfg, nodeID, rotator, cap, "auto")
			if err == nil {
				log.Info("certificate renewed, reconnecting with new cert")
				select {
				case renewCh <- struct{}{}:
				default:
				}
			}
			return err
		})
	}

	// 5. mTLS 长连接流在连接循环中建立（续签后重建，见末尾连接循环）

	// 5. 根据探测结果构建防火墙驱动，并验证后端是否可正常执行命令
	drv := selectDriver(cap, log)
	if drv != nil {
		if err := drv.Init(ctx); err != nil {
			log.Warn("driver init failed; agent will run without an active driver", "err", err)
			drv = nil
			markBackendAvailability(cap, false, "后端初始化失败: "+err.Error())
		} else {
			log.Info("firewall driver ready", "backend", cap.SelectedBackend.String())
			markBackendAvailability(cap, true, "")
		}
	} else {
		// 未检测到可用后端（非 Linux 主机或 iptables/nftables 均缺失）
		markBackendAvailability(cap, false, "未检测到可用防火墙后端")
	}

	// 6. 上报 iptables 规则到 Controller
	go reportIptablesRules(ctx, cfg, nodeID, log)
	// 6.1 周期上报 MYFW 规则命中率到 Controller(规则活性分析)
	go reportRuleHits(ctx, cfg, nodeID, log)

	// 7. 构建任务处理器
	var h *handler.Handler
	if drv != nil {
		h = handler.New(drv, log)
	} else {
		h = handler.New(nil, log)
	}
	// 注入规则采集器：Controller 拉取规则时，Agent 实时采集当前 iptables 规则回传
	coll := collector.New(60*time.Second, log)
	h.RulesCollector = coll.CollectIptablesRulesForHTTP
	// 注入规则执行器：节点规则页增删改插时，执行 iptables 命令
	h.RuleExecutor = func(ctx context.Context, args []string) (string, error) {
		cmd := exec.CommandContext(ctx, "iptables", args...)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	// 注入专家模式执行器：执行任意 iptables 族命令（白名单校验由 handler.OnExec 保证）
	h.ExecExecutor = func(ctx context.Context, name string, args []string) (string, error) {
		cmd := exec.CommandContext(ctx, name, args...)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}

	// 注入证书续签回调：Controller 下发 RenewCert 指令时触发
	if rotator != nil {
		h.RenewCertFn = func(ctx context.Context, trigger string) error {
			return requestCertRenewal(ctx, cfg, nodeID, rotator, cap, trigger)
		}
	}
	// 注入注销自毁回调：Controller 下发 Decommission 指令时触发（删节点场景）
	h.DecommissionFn = func(ctx context.Context, reason string) error {
		selfDestruct(cfg, log, reason)
		return nil // 不会执行到，selfDestruct 内部 os.Exit
	}

	// 8. 共享发送通道（漂移报告等跨重连消息）
	sendCh := make(chan *myfwv1.AgentToController, 8)

	// 9. 启动看门狗（若驱动可用）
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

	// 10. 连接循环：续签后重建 ClientConn 加载新证书
	for {
		if ctx.Err() != nil {
			return nil
		}
		streamConn, err := conn.Dial(ctx, cfg.Controller.Endpoint, conn.TLSMaterial{
			Disable:    cfg.Controller.TLS.Disable,
			CAFile:     cfg.Controller.TLS.CAFile,
			CertFile:   cfg.Controller.TLS.CertFile,
			KeyFile:    cfg.Controller.TLS.KeyFile,
			ServerName: cfg.Controller.ServerName,
		})
		if err != nil {
			log.Warn("dial failed, backing off", "err", err)
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(5 * time.Second):
			}
			continue
		}
		err = conn.Loop(ctx, streamConn, log, nodeID, cap, h, conn.HeartbeatOptions{}, sendCh, renewCh)
		streamConn.Close()
		if ctx.Err() != nil {
			return nil
		}
		// Controller 明确拒绝（证书吊销/未知、节点删除）或下发 Decommission：自毁
		if errors.Is(err, conn.ErrSelfDestruct) {
			selfDestruct(cfg, log, "controller rejected node")
			return nil
		}
	}
}

// reportIptablesRules 收集并上报 iptables 规则
func reportIptablesRules(ctx context.Context, cfg agentcfg.Config, nodeID string, log *slog.Logger) {
	time.Sleep(2 * time.Second) // 等待连接稳定

	c := collector.New(60*time.Second, log)
	rules, err := c.CollectIptablesRulesForHTTP()
	if err != nil {
		log.Warn("collect iptables rules failed", "err", err)
		return
	}
	if len(rules) == 0 {
		log.Info("no iptables rules found")
		return
	}

	type chainData struct {
		Table string   `json:"table"`
		Chain string   `json:"chain"`
		Rules []string `json:"rules"`
	}
	var chains []chainData
	for table, tableChains := range rules {
		for chain, chainRules := range tableChains {
			chains = append(chains, chainData{Table: table, Chain: chain, Rules: chainRules})
		}
	}

	body, _ := json.Marshal(map[string]any{"chains": chains})
	url := buildControllerWebURL(cfg.Controller.Endpoint) + "/api/v1/iptables/report/" + nodeID

	resp, err := http.Post(url, "application/json", strings.NewReader(string(body)))
	if err != nil {
		log.Warn("report iptables rules failed", "err", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		log.Info("iptables rules reported successfully", "node_id", nodeID)
	} else {
		log.Warn("report iptables rules failed", "status", resp.StatusCode)
	}
}

// reportRuleHits 周期采集 MYFW 规则命中率(pkts/bytes + comment 反解实例 ID)并上报到
// Controller。规则活性分析:Controller 据此标记死规则(启用且 packets=0 且超阈值)。
func reportRuleHits(ctx context.Context, cfg agentcfg.Config, nodeID string, log *slog.Logger) {
	time.Sleep(5 * time.Second) // 等待连接稳定
	coll := collector.New(60*time.Second, log)

	report := func() {
		hits, err := coll.CollectRuleHits()
		if err != nil {
			log.Warn("collect rule hits failed", "err", err)
			return
		}
		if len(hits) == 0 {
			return
		}
		body, _ := json.Marshal(map[string]any{"hits": hits})
		url := buildControllerWebURL(cfg.Controller.Endpoint) + "/api/v1/iptables/hits/" + nodeID
		resp, err := http.Post(url, "application/json", strings.NewReader(string(body)))
		if err != nil {
			log.Warn("report rule hits failed", "err", err)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			log.Warn("report rule hits failed", "status", resp.StatusCode)
		}
	}

	report()
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			report()
		case <-ctx.Done():
			return
		}
	}
}

// buildControllerWebURL 将 gRPC endpoint 转换为 Web API URL
func buildControllerWebURL(endpoint string) string {
	if idx := strings.LastIndex(endpoint, ":"); idx > 0 {
		return "http://" + endpoint[:idx] + ":8080"
	}
	return "http://" + endpoint
}

// selfDestruct 注销自毁：禁用 systemd 服务 + 删除本地全部文件 + 退出进程。
// 触发场景：
//   - Controller 删除节点时下发 Decommission 指令（在线节点）
//   - Agent 重连被 Controller 拒绝（证书吊销/未知、节点删除，离线节点兜底）
//
// 注意：不能 systemctl stop —— 当前进程就是 myfw-agent，stop 会杀掉自身导致后续删文件
// 不执行。先 disable（防机器重启后自动拉起），再删文件，最后 os.Exit 让进程正常退出
// （exit 0，systemd Restart=on-failure 不会重启）。所有清理操作尽力而为。
func selfDestruct(cfg agentcfg.Config, log *slog.Logger, reason string) {
	log.Error("self-destructing", "reason", reason)
	// 禁用 systemd 服务（unit 文件需存在，故在删 unit 之前）
	_ = exec.Command("systemctl", "disable", "myfw-agent").Run()
	// 删除配置/证书目录、状态目录、二进制、unit 文件
	_ = os.RemoveAll(filepath.Dir(cfg.Controller.TLS.CertFile))
	_ = os.RemoveAll(cfg.Node.DataDir)
	_ = os.Remove("/usr/local/bin/myfw-agent")
	_ = os.Remove("/etc/systemd/system/myfw-agent.service")
	_ = exec.Command("systemctl", "daemon-reload").Run()
	log.Error("self-destruct complete, exiting", "reason", reason)
	os.Exit(0)
}

// selectDriver 根据探测结果选择防火墙驱动
func selectDriver(cap *myfwv1.Capability, log *slog.Logger) agentdriver.Driver {
	switch cap.SelectedBackend {
	case myfwv1.FirewallBackend_FIREWALL_BACKEND_IPTABLES_LEGACY,
		myfwv1.FirewallBackend_FIREWALL_BACKEND_IPTABLES_NFT:
		return iptdriver.New(iptdriver.ShellExec{}, cap.SelectedBackend)
	case myfwv1.FirewallBackend_FIREWALL_BACKEND_NFTABLES:
		return nftdriver.New(nftdriver.ShellExec{}, cap.SelectedBackend)
	}
	return nil
}

// markBackendAvailability 将后端可用性探测结果写入 capability.extra，
// Controller 据此将节点置为"异常"并展示具体原因。复用 extra 字段以避免改 proto。
// 驱动初始化成功即代表后端可正常执行命令；失败或无后端则标记不可用并附带原因。
func markBackendAvailability(cap *myfwv1.Capability, ok bool, reason string) {
	if cap == nil {
		return
	}
	if ok {
		cap.Extra = append(cap.Extra, "backend_available=true")
		return
	}
	cap.Extra = append(cap.Extra, "backend_available=false")
	if reason != "" {
		cap.Extra = append(cap.Extra, "backend_reason:"+reason)
	}
}

func newLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
}

// clearBootstrapToken 从配置文件中移除已消费的一次性令牌
func clearBootstrapToken(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	out := make([]byte, 0, len(raw))
	start := 0
	for i := 0; i <= len(raw); i++ {
		if i == len(raw) || raw[i] == '\n' {
			line := raw[start:i]
			if !strings.HasPrefix(strings.TrimLeft(string(line), " \t"), "bootstrap_token:") {
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

// requestCertRenewal 向Controller请求证书轮换。
// 流程：生成新密钥对 → 发送CSR → 获取新证书 → 原子写入磁盘。
var renewMu sync.Mutex

func requestCertRenewal(ctx context.Context, cfg agentcfg.Config, nodeID string, rotator *security.CertRotation, cap *myfwv1.Capability, trigger string) error {
	if !renewMu.TryLock() {
		return fmt.Errorf("renewal already in progress (trigger=%s)", trigger)
	}
	defer renewMu.Unlock()
	// 连接到Controller（使用旧证书）
	conn, err := conn.Dial(ctx, cfg.Controller.Endpoint, conn.TLSMaterial{
		Disable:    cfg.Controller.TLS.Disable,
		CAFile:     cfg.Controller.TLS.CAFile,
		CertFile:   cfg.Controller.TLS.CertFile,
		KeyFile:    cfg.Controller.TLS.KeyFile,
		ServerName: cfg.Controller.ServerName,
	})
	if err != nil {
		return fmt.Errorf("dial for renewal: %w", err)
	}
	defer conn.Close()

	// 生成新密钥对和CSR
	csrPEM, newKeyPEM, err := rotator.GenerateCSR(nodeID)
	if err != nil {
		return fmt.Errorf("generate csr: %w", err)
	}

	// 调用Register RPC进行证书轮换（复用注册接口，token用空字符串）
	regClient := myfwv1.NewRegistrationClient(conn)
	regCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	resp, err := regClient.Register(regCtx, &myfwv1.RegisterRequest{
		BootstrapToken: "", // 空token，Controller会识别为续签请求
		CandidateId:    nodeID,
		CsrPem:         csrPEM,
		Fingerprint:    bootstrap.MachineFingerprint(),
		Capability:     cap,
		Trigger:        trigger, // auto / manual,Controller 审计区分来源
	})
	if err != nil {
		return fmt.Errorf("renewal RPC: %w", err)
	}

	if resp.ClientCertPem == nil || len(resp.ClientCertPem) == 0 {
		return fmt.Errorf("empty certificate in renewal response")
	}

	// 持久化新证书和密钥
	if err := rotator.ApplyNewCert(resp.ClientCertPem, newKeyPEM); err != nil {
		return fmt.Errorf("apply new cert: %w", err)
	}

	return nil
}
