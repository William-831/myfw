// Package capability probes the local machine at Agent startup to decide
// which Firewall Driver to select and to give the Controller a fingerprint
// of the environment. See docs/design.md § 5.
//
// The probing is intentionally best-effort and non-fatal: on macOS / dev
// machines most probes report "unavailable" and the Agent still starts —
// selection then defaults to FIREWALL_BACKEND_UNSPECIFIED and the Controller
// simply won't dispatch rules until a real Linux host takes over.
package capability

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"time"

	myfwv1 "iptables-tool/api/myfw/v1"
)

// Detect probes the host and returns a filled-in Capability message. It never
// returns an error; unknown fields are just left empty.
func Detect(ctx context.Context) *myfwv1.Capability {
	cap := &myfwv1.Capability{
		Distro:            detectDistro(),
		KernelVersion:     detectKernel(),
		IptablesVersion:   "",
		IptablesBackend:   myfwv1.FirewallBackend_FIREWALL_BACKEND_UNSPECIFIED,
		NftSupported:      false,
		DockerPresent:     detectDocker(ctx),
		KubernetesPresent: detectKubernetes(),
		SelectedBackend:   myfwv1.FirewallBackend_FIREWALL_BACKEND_UNSPECIFIED,
	}

	iptVer, iptBackend := detectIptables(ctx)
	cap.IptablesVersion = iptVer
	cap.IptablesBackend = iptBackend

	cap.NftSupported = detectNft(ctx)

	cap.SelectedBackend = chooseBackend(cap)

	if cap.SelectedBackend == myfwv1.FirewallBackend_FIREWALL_BACKEND_UNSPECIFIED {
		cap.Extra = append(cap.Extra, "no supported firewall backend detected (dev/non-linux host?)")
	}
	return cap
}

// chooseBackend picks the driver the Agent should use. Preferences:
//  1. Modern kernels with native nftables -> NFTABLES
//  2. iptables with nft backend -> IPTABLES_NFT
//  3. Fall back to legacy iptables -> IPTABLES_LEGACY
//  4. Nothing usable -> UNSPECIFIED
func chooseBackend(c *myfwv1.Capability) myfwv1.FirewallBackend {
	if runtime.GOOS != "linux" {
		return myfwv1.FirewallBackend_FIREWALL_BACKEND_UNSPECIFIED
	}
	// Prefer whatever iptables reports as its backend, since that's what most
	// existing hosts already use (Docker/K8s wire into it). Only jump to
	// pure nftables when there is no iptables at all.
	switch c.IptablesBackend {
	case myfwv1.FirewallBackend_FIREWALL_BACKEND_IPTABLES_NFT:
		return myfwv1.FirewallBackend_FIREWALL_BACKEND_IPTABLES_NFT
	case myfwv1.FirewallBackend_FIREWALL_BACKEND_IPTABLES_LEGACY:
		return myfwv1.FirewallBackend_FIREWALL_BACKEND_IPTABLES_LEGACY
	}
	if c.NftSupported {
		return myfwv1.FirewallBackend_FIREWALL_BACKEND_NFTABLES
	}
	return myfwv1.FirewallBackend_FIREWALL_BACKEND_UNSPECIFIED
}

// --- individual probes ------------------------------------------------------

func detectDistro() string {
	// /etc/os-release is the modern standard.
	raw, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return runtime.GOOS
	}
	pretty := parseKV(string(raw), "PRETTY_NAME")
	if pretty != "" {
		return pretty
	}
	return runtime.GOOS
}

func detectKernel() string {
	out, err := runCmd(context.Background(), 500*time.Millisecond, "uname", "-r")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

// detectIptables returns the version string and the backend flavour, parsing
// the classic "iptables v1.8.7 (nf_tables)" / "(legacy)" markers.
func detectIptables(ctx context.Context) (string, myfwv1.FirewallBackend) {
	out, err := runCmd(ctx, 1*time.Second, "iptables", "-V")
	if err != nil {
		return "", myfwv1.FirewallBackend_FIREWALL_BACKEND_UNSPECIFIED
	}
	line := strings.TrimSpace(out)
	backend := myfwv1.FirewallBackend_FIREWALL_BACKEND_UNSPECIFIED
	switch {
	case strings.Contains(line, "nf_tables"):
		backend = myfwv1.FirewallBackend_FIREWALL_BACKEND_IPTABLES_NFT
	case strings.Contains(line, "legacy"):
		backend = myfwv1.FirewallBackend_FIREWALL_BACKEND_IPTABLES_LEGACY
	default:
		// No marker: assume legacy — pre-1.8 iptables didn't print one.
		backend = myfwv1.FirewallBackend_FIREWALL_BACKEND_IPTABLES_LEGACY
	}

	if m := iptablesVersionRE.FindStringSubmatch(line); len(m) >= 2 {
		return m[1], backend
	}
	return line, backend
}

var iptablesVersionRE = regexp.MustCompile(`v(\d+\.\d+\.\d+)`)

func detectNft(ctx context.Context) bool {
	// `nft list ruleset` requires root and touches the kernel; a lighter probe
	// is just "nft --version" — its presence is enough evidence.
	_, err := runCmd(ctx, 500*time.Millisecond, "nft", "--version")
	return err == nil
}

func detectDocker(ctx context.Context) bool {
	// The socket is a stronger signal than the binary — the daemon might be
	// installed but stopped.
	if _, err := os.Stat("/var/run/docker.sock"); err == nil {
		return true
	}
	// Fall back to CLI presence, which at least confirms it's expected here.
	_, err := exec.LookPath("docker")
	return err == nil
}

func detectKubernetes() bool {
	// Being INSIDE a pod is the common case where kube-proxy has messed with
	// iptables and we should be extra careful.
	if _, err := os.Stat("/var/run/secrets/kubernetes.io/serviceaccount/token"); err == nil {
		return true
	}
	// kubelet on the host node.
	if _, err := os.Stat("/var/lib/kubelet"); err == nil {
		return true
	}
	return false
}

// --- helpers ----------------------------------------------------------------

func runCmd(ctx context.Context, timeout time.Duration, name string, args ...string) (string, error) {
	if _, err := exec.LookPath(name); err != nil {
		return "", errors.New("not found: " + name)
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	out, err := exec.CommandContext(cctx, name, args...).CombinedOutput()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// parseKV pulls a `KEY=value` line out of os-release-style content, stripping
// surrounding quotes on the value.
func parseKV(s, key string) string {
	for _, line := range strings.Split(s, "\n") {
		if !strings.HasPrefix(line, key+"=") {
			continue
		}
		v := strings.TrimPrefix(line, key+"=")
		v = strings.TrimSpace(v)
		v = strings.Trim(v, `"'`)
		return v
	}
	return ""
}
