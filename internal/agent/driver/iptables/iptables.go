// Package iptables implements the Firewall Driver for hosts running iptables
// (either legacy or nft backend). All rules are confined to the MYFW-* custom
// chains; the driver never modifies system chains other than to insert a
// single jump from INPUT/OUTPUT/FORWARD/PREROUTING/POSTROUTING into MYFW.
// See docs/design.md § 4 / § 7 / § 8.
package iptables

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os/exec"
	"sort"
	"strings"

	myfwv1 "iptables-tool/api/myfw/v1"
	"iptables-tool/internal/agent/driver"
)

// The MYFW namespace inside iptables.
const (
	tableFilter  = "filter"
	tableNat     = "nat"
	tableMangle  = "mangle"
	chainInput   = "MYFW-INPUT"
	chainOutput  = "MYFW-OUTPUT"
	chainForward = "MYFW-FORWARD"
	chainNatPre  = "MYFW-PREROUTING"
	chainNatPost = "MYFW-POSTROUTING"
	chainMangle  = "MYFW-MANGLE"
)

// systemJumps maps (table, system chain) -> managed MYFW chain. Init inserts
// a jump at position 1 of the system chain if not already present.
var systemJumps = []struct {
	table, sysChain, myfwChain string
}{
	{tableFilter, "INPUT", chainInput},
	{tableFilter, "OUTPUT", chainOutput},
	{tableFilter, "FORWARD", chainForward},
	{tableNat, "PREROUTING", chainNatPre},
	{tableNat, "POSTROUTING", chainNatPost},
	{tableMangle, "PREROUTING", chainMangle},
}

// managedChains lists every MYFW chain the driver owns, in a stable order so
// snapshot/hash output is deterministic.
var managedChains = []struct{ table, chain string }{
	{tableFilter, chainInput},
	{tableFilter, chainOutput},
	{tableFilter, chainForward},
	{tableNat, chainNatPre},
	{tableNat, chainNatPost},
	{tableMangle, chainMangle},
}

// Exec is the minimal iptables execution surface the driver depends on. Real
// deployments inject a shell-backed implementation; tests inject a fake.
type Exec interface {
	// Run invokes the tool with args and returns (stdout, err). stderr is
	// merged into the returned error message when Run fails.
	Run(ctx context.Context, args ...string) (string, error)
}

// ShellExec runs the real `iptables` binary. Used on Linux hosts.
type ShellExec struct {
	Binary string // e.g. "iptables"; defaults to "iptables"
}

func (s ShellExec) Run(ctx context.Context, args ...string) (string, error) {
	bin := s.Binary
	if bin == "" {
		bin = "iptables"
	}
	cmd := exec.CommandContext(ctx, bin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return stdout.String(), fmt.Errorf("%s %s: %w: %s",
			bin, strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}

// Driver is a Firewall Driver backed by an Exec (real or fake).
type Driver struct {
	Exec     Exec
	Backend_ myfwv1.FirewallBackend // set at construction time; usually IPTABLES_NFT or IPTABLES_LEGACY
}

// New builds a Driver. Backend is only used for reporting via Backend().
func New(e Exec, backend myfwv1.FirewallBackend) *Driver {
	return &Driver{Exec: e, Backend_: backend}
}

func (d *Driver) Backend() myfwv1.FirewallBackend { return d.Backend_ }

// Init creates every MYFW chain and inserts the system-chain jumps. The
// operation is idempotent: existing chains are left untouched, existing
// jumps are not duplicated.
func (d *Driver) Init(ctx context.Context) error {
	// 1. Create managed chains if they don't exist.
	for _, mc := range managedChains {
		if err := d.ensureChain(ctx, mc.table, mc.chain); err != nil {
			return err
		}
	}
	// 2. Insert jumps at position 1 of each system chain (idempotent).
	for _, j := range systemJumps {
		if err := d.ensureJump(ctx, j.table, j.sysChain, j.myfwChain); err != nil {
			return err
		}
	}
	return nil
}

// Apply syncs the address sets to ipset, flushes each managed chain and
// refills it from ruleSet.Rules, preserving system chains and their jumps.
// Returns the hash of the resulting normalized state.
func (d *Driver) Apply(ctx context.Context, ruleSet *myfwv1.RuleSet) (string, error) {
	// Sanity: Init must have been called at least once, but we don't want to
	// silently re-init here — that could hide operator mistakes. However
	// Apply should still be usable end-to-end, so ensure chains exist.
	if err := d.Init(ctx); err != nil {
		return "", err
	}

	// 先同步地址组到 ipset(期望态)。空 sets 时为空操作,不触碰 ipset。
	if err := d.syncSets(ctx, ruleSet.GetSets()); err != nil {
		return "", err
	}

	// Flush all managed chains first so leftover rules from the previous
	// version cannot survive.
	for _, mc := range managedChains {
		if _, err := d.Exec.Run(ctx, "-t", mc.table, "-F", mc.chain); err != nil {
			return "", fmt.Errorf("flush %s/%s: %w", mc.table, mc.chain, err)
		}
	}

	// Sort by priority (asc) then by ID for determinism, so identical inputs
	// produce identical iptables state (and identical hashes).
	rules := ruleSet.GetRules()
	sorted := make([]*myfwv1.CompiledRule, len(rules))
	copy(sorted, rules)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].Priority != sorted[j].Priority {
			return sorted[i].Priority < sorted[j].Priority
		}
		return sorted[i].Id < sorted[j].Id
	})

	// Emit each rule as an -A into the corresponding managed chain.
	for _, r := range sorted {
		table, chain, err := targetChainFor(r)
		if err != nil {
			return "", err
		}
		args, err := compileRule(r, chain)
		if err != nil {
			return "", err
		}
		full := append([]string{"-t", table}, args...)
		if _, err := d.Exec.Run(ctx, full...); err != nil {
			return "", fmt.Errorf("append rule %s: %w", r.Id, err)
		}
	}

	return d.Hash(ctx)
}

// syncSets 把期望地址组态同步到节点 ipset。每个 set 名为 MYFW-<name>,
// 类型 hash:net(支持 CIDR)。先 create(-exist 幂等)再 flush+add 成员。
// 简化实现:flush+add 非原子,大集合有短暂窗口;后续可改 ipset swap 原子切换。
func (d *Driver) syncSets(ctx context.Context, sets []*myfwv1.AddressSet) error {
	for _, s := range sets {
		name := "MYFW-" + s.Name
		if _, err := d.ipsetRun(ctx, "create", name, "hash:net", "-exist"); err != nil {
			return fmt.Errorf("ipset create %s: %w", name, err)
		}
		if _, err := d.ipsetRun(ctx, "flush", name); err != nil {
			return fmt.Errorf("ipset flush %s: %w", name, err)
		}
		for _, m := range s.Members {
			if _, err := d.ipsetRun(ctx, "add", name, m, "-exist"); err != nil {
				return fmt.Errorf("ipset add %s %s: %w", name, m, err)
			}
		}
	}
	return nil
}

// ipsetRun 执行 ipset 命令,返回 stdout;stderr 合并入错误。
func (d *Driver) ipsetRun(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "ipset", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return stdout.String(), fmt.Errorf("ipset %s: %w: %s",
			strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}

// Snapshot dumps every managed chain via `-S` and joins the output into a
// single deterministic payload. Format: for each chain in managedChains, a
// header line "# table/chain" followed by the -S output. MYFW-* ipset 内容一并
// 纳入,使 drift/Hash 覆盖地址组成员变化。
func (d *Driver) Snapshot(ctx context.Context) (string, string, error) {
	var b strings.Builder
	for _, mc := range managedChains {
		out, err := d.Exec.Run(ctx, "-t", mc.table, "-S", mc.chain)
		if err != nil {
			// A missing chain is not a snapshot failure — it just means the
			// namespace hasn't been initialised on this host yet.
			if isChainMissing(err) {
				continue
			}
			return "", "", fmt.Errorf("snapshot %s/%s: %w", mc.table, mc.chain, err)
		}
		fmt.Fprintf(&b, "# %s/%s\n%s", mc.table, mc.chain, out)
		if !strings.HasSuffix(out, "\n") {
			b.WriteByte('\n')
		}
	}
	// 纳入 MYFW-* ipset 内容,使 Hash 覆盖地址组成员变化。
	if names, err := d.ipsetListNames(ctx); err == nil {
		for _, name := range names {
			if !strings.HasPrefix(name, "MYFW-") {
				continue
			}
			out, err := d.ipsetRun(ctx, "list", name)
			if err != nil {
				continue
			}
			fmt.Fprintf(&b, "# ipset/%s\n%s", name, out)
			if !strings.HasSuffix(out, "\n") {
				b.WriteByte('\n')
			}
		}
	}
	payload := b.String()
	return payload, hashString(payload), nil
}

// ipsetListNames 列出节点上所有 ipset 名称。
func (d *Driver) ipsetListNames(ctx context.Context) ([]string, error) {
	out, err := d.ipsetRun(ctx, "list", "-name")
	if err != nil {
		return nil, err
	}
	var names []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			names = append(names, line)
		}
	}
	return names, nil
}

// Restore re-applies a Snapshot payload. It flushes every managed chain and
// re-issues each rule line captured in the snapshot.
func (d *Driver) Restore(ctx context.Context, payload string) error {
	if err := d.Init(ctx); err != nil {
		return err
	}
	// Flush every managed chain first.
	for _, mc := range managedChains {
		if _, err := d.Exec.Run(ctx, "-t", mc.table, "-F", mc.chain); err != nil {
			return err
		}
	}
	// Walk the payload; each `# table/chain` header switches the target,
	// each other non-empty line is fed back to iptables verbatim.
	var curTable, curChain string
	for _, line := range strings.Split(payload, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "# ") {
			parts := strings.SplitN(strings.TrimPrefix(line, "# "), "/", 2)
			if len(parts) != 2 {
				return fmt.Errorf("restore: malformed header %q", line)
			}
			curTable, curChain = parts[0], parts[1]
			continue
		}
		if curTable == "" || curChain == "" {
			return fmt.Errorf("restore: rule outside a chain block: %q", line)
		}
		// -S prints chain-declaration lines like "-N MYFW-INPUT" which we
		// skip (Init already created the chain).
		if strings.HasPrefix(line, "-N ") {
			continue
		}
		// Every other -S line should be a "-A CHAIN ..." rule; feed to iptables.
		if _, err := d.Exec.Run(ctx, append([]string{"-t", curTable}, strings.Fields(line)...)...); err != nil {
			return fmt.Errorf("restore rule %q: %w", line, err)
		}
	}
	return nil
}

// Hash reproduces Snapshot's payload and returns just its digest.
func (d *Driver) Hash(ctx context.Context) (string, error) {
	_, h, err := d.Snapshot(ctx)
	return h, err
}

// Teardown removes the jump rules from system chains, then flushes and
// deletes every managed chain. Non-fatal if pieces are already gone.
func (d *Driver) Teardown(ctx context.Context) error {
	for _, j := range systemJumps {
		// Remove any lingering jumps into our chain.
		for {
			if _, err := d.Exec.Run(ctx, "-t", j.table, "-D", j.sysChain, "-j", j.myfwChain); err != nil {
				break
			}
		}
	}
	for _, mc := range managedChains {
		_, _ = d.Exec.Run(ctx, "-t", mc.table, "-F", mc.chain)
		_, _ = d.Exec.Run(ctx, "-t", mc.table, "-X", mc.chain)
	}
	return nil
}

// --- internal helpers -------------------------------------------------------

// ensureChain creates chain in table if it does not exist.
func (d *Driver) ensureChain(ctx context.Context, table, chain string) error {
	if _, err := d.Exec.Run(ctx, "-t", table, "-N", chain); err != nil {
		if isChainExists(err) {
			return nil
		}
		return fmt.Errorf("ensure chain %s/%s: %w", table, chain, err)
	}
	return nil
}

// ensureJump inserts "-j myfwChain" at position 1 of the system chain if the
// same jump isn't already present anywhere in that chain.
func (d *Driver) ensureJump(ctx context.Context, table, sysChain, myfwChain string) error {
	// -C returns 0 if the rule exists.
	if _, err := d.Exec.Run(ctx, "-t", table, "-C", sysChain, "-j", myfwChain); err == nil {
		return nil
	}
	if _, err := d.Exec.Run(ctx, "-t", table, "-I", sysChain, "1", "-j", myfwChain); err != nil {
		return fmt.Errorf("insert jump %s -> %s: %w", sysChain, myfwChain, err)
	}
	return nil
}

// targetChainFor returns the (table, chain) that a compiled rule belongs in.
func targetChainFor(r *myfwv1.CompiledRule) (string, string, error) {
	switch r.Action {
	case myfwv1.Action_ACTION_DNAT:
		return tableNat, chainNatPre, nil
	case myfwv1.Action_ACTION_SNAT:
		return tableNat, chainNatPost, nil
	case myfwv1.Action_ACTION_MARK:
		return tableMangle, chainMangle, nil
	}
	switch r.Direction {
	case myfwv1.Direction_DIRECTION_INBOUND:
		return tableFilter, chainInput, nil
	case myfwv1.Direction_DIRECTION_OUTBOUND:
		return tableFilter, chainOutput, nil
	case myfwv1.Direction_DIRECTION_FORWARD:
		return tableFilter, chainForward, nil
	}
	return "", "", fmt.Errorf("cannot map rule %q: direction=%v action=%v",
		r.Id, r.Direction, r.Action)
}

// compileRule turns a CompiledRule into a list of iptables args (starting
// with the -A into `chain`). The order of match/target flags matches the
// order iptables itself uses when printing rules, so a subsequent -S output
// hashes stably.
func compileRule(r *myfwv1.CompiledRule, chain string) ([]string, error) {
	args := []string{"-A", chain}
	if r.Source != "" {
		args = append(args, "-s", r.Source)
	}
	if r.Destination != "" {
		args = append(args, "-d", r.Destination)
	}
	proto := ""
	switch r.Protocol {
	case myfwv1.Protocol_PROTOCOL_TCP:
		proto = "tcp"
	case myfwv1.Protocol_PROTOCOL_UDP:
		proto = "udp"
	case myfwv1.Protocol_PROTOCOL_ICMP:
		proto = "icmp"
	}
	if proto != "" {
		args = append(args, "-p", proto)
	}
	if r.PortRange != "" {
		if proto == "" {
			return nil, fmt.Errorf("rule %q: port range requires a protocol", r.Id)
		}
		args = append(args, "--dport", strings.ReplaceAll(r.PortRange, "-", ":"))
	}
	// 地址组匹配(多 CIDR,经 ipset)。SourceGroup/DestinationGroup 引用 MYFW-<name>。
	if r.SourceGroup != "" {
		args = append(args, "-m", "set", "--match-set", "MYFW-"+r.SourceGroup, "src")
	}
	if r.DestinationGroup != "" {
		args = append(args, "-m", "set", "--match-set", "MYFW-"+r.DestinationGroup, "dst")
	}
	// 匹配已打标记的流量(与 Action=MARK 打标正交)。
	if r.MatchMark != 0 {
		args = append(args, "-m", "mark", "--mark", fmt.Sprintf("%d", r.MatchMark))
	}

	// Target.
	switch r.Action {
	case myfwv1.Action_ACTION_ACCEPT:
		args = append(args, "-j", "ACCEPT")
	case myfwv1.Action_ACTION_DROP:
		args = append(args, "-j", "DROP")
	case myfwv1.Action_ACTION_REJECT:
		args = append(args, "-j", "REJECT")
	case myfwv1.Action_ACTION_MARK:
		args = append(args, "-j", "MARK", "--set-mark", fmt.Sprintf("%d", r.Mark))
	case myfwv1.Action_ACTION_DNAT:
		if r.NatTo == "" {
			return nil, fmt.Errorf("rule %q: DNAT requires nat_to", r.Id)
		}
		args = append(args, "-j", "DNAT", "--to-destination", r.NatTo)
	case myfwv1.Action_ACTION_SNAT:
		if r.NatTo == "" {
			return nil, fmt.Errorf("rule %q: SNAT requires nat_to", r.Id)
		}
		args = append(args, "-j", "SNAT", "--to-source", r.NatTo)
	default:
		return nil, fmt.Errorf("rule %q: unsupported action %v", r.Id, r.Action)
	}
	return args, nil
}

// isChainExists / isChainMissing recognize the two most common iptables
// idempotency signals from stderr text. This is intentionally a substring
// check because different iptables versions phrase things slightly differently.
func isChainExists(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "Chain already exists") ||
		strings.Contains(s, "iptables: Chain already exists") ||
		strings.Contains(s, "File exists")
}

func isChainMissing(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "No chain/target/match by that name") ||
		strings.Contains(s, "does not exist")
}

func hashString(s string) string {
	sum := sha256.Sum256([]byte(s))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// compile-time interface conformance check.
var _ driver.Driver = (*Driver)(nil)

// re-export for callers who want to construct a real ShellExec inline.
var _ = errors.New
