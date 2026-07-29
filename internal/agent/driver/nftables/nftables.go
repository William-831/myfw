package nftables

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os/exec"
	"sort"
	"strings"

	myfwv1 "iptables-tool/api/myfw/v1"
	"iptables-tool/internal/agent/driver"
)

const (
	tableName = "myfw"
)

var managedChains = []struct {
	chain  string
	family string
	hook   string
	priority int
}{
	{"INPUT", "inet", "input", 0},
	{"OUTPUT", "inet", "output", 0},
	{"FORWARD", "inet", "forward", 0},
	{"PREROUTING", "ip", "prerouting", 0},
	{"POSTROUTING", "ip", "postrouting", 0},
}

type Exec interface {
	Run(ctx context.Context, args ...string) (string, error)
}

type ShellExec struct {
	Binary string
}

func (s ShellExec) Run(ctx context.Context, args ...string) (string, error) {
	bin := s.Binary
	if bin == "" {
		bin = "nft"
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

type Driver struct {
	Exec     Exec
	Backend_ myfwv1.FirewallBackend
}

func New(e Exec, backend myfwv1.FirewallBackend) *Driver {
	return &Driver{Exec: e, Backend_: backend}
}

func (d *Driver) Backend() myfwv1.FirewallBackend { return d.Backend_ }

func (d *Driver) Init(ctx context.Context) error {
	if err := d.ensureTable(ctx); err != nil {
		return err
	}
	for _, mc := range managedChains {
		if err := d.ensureChain(ctx, mc.family, mc.chain, mc.hook, mc.priority); err != nil {
			return err
		}
	}
	return nil
}

// EnsureJumps 对 nftables 为空操作:nft 用 hook chain 直接接管,不插 iptables 系统链,
// 无 jump 顺序问题。存在仅为满足 watchdog.Driver 接口。
func (d *Driver) EnsureJumps(ctx context.Context) error {
	return nil
}

func (d *Driver) Apply(ctx context.Context, ruleSet *myfwv1.RuleSet) (string, error) {
	if err := d.Init(ctx); err != nil {
		return "", err
	}
	if err := d.syncSets(ctx, ruleSet.GetSets()); err != nil {
		return "", err
	}
	for _, mc := range managedChains {
		if err := d.flushChain(ctx, mc.family, mc.chain); err != nil {
			return "", err
		}
	}
	// 过滤链首条放行已建立连接,避免策略 DROP 误伤回包(对应 iptables driver 的
	// ESTABLISHED ACCEPT)。
	for _, mc := range managedChains {
		if mc.chain != "INPUT" && mc.chain != "OUTPUT" && mc.chain != "FORWARD" {
			continue
		}
		if err := d.addRule(ctx, mc.family, mc.chain, "ct state established,related accept"); err != nil {
			return "", fmt.Errorf("ensure established accept %s/%s: %w", mc.family, mc.chain, err)
		}
	}

	// 同步用户自定义子链(nft 后端当前为 no-op,待 nft 环境联调)
	if err := d.syncCustomChains(ctx, ruleSet.GetCustomChains()); err != nil {
		return "", err
	}
	chainToTable := make(map[string]string)
	for _, cc := range ruleSet.GetCustomChains() {
		chainToTable[cc.Name] = cc.Table
	}
	rules := ruleSet.GetRules()
	sorted := make([]*myfwv1.CompiledRule, len(rules))
	copy(sorted, rules)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].Priority != sorted[j].Priority {
			return sorted[i].Priority < sorted[j].Priority
		}
		return sorted[i].Id < sorted[j].Id
	})

	for _, r := range sorted {
		family, chain, err := targetChainForRule(r, chainToTable)
		if err != nil {
			return "", err
		}
		exprs, err := compileRule(r)
		if err != nil {
			return "", err
		}
		if err := d.addRule(ctx, family, chain, exprs); err != nil {
			return "", fmt.Errorf("add rule %s: %w", r.Id, err)
		}
	}

	return d.Hash(ctx)
}

// syncSets 把期望地址组态同步到节点 nft set。每个 set 在 myfw 表内,类型
// ipv4_addr + flags interval(支持 CIDR 范围)。已存在则复用,flush 后重灌成员。
func (d *Driver) syncSets(ctx context.Context, sets []*myfwv1.AddressSet) error {
	for _, s := range sets {
		if _, err := d.Exec.Run(ctx, "add", "set", "inet", tableName, s.Name, "{ type ipv4_addr; flags interval; }"); err != nil {
			// set 已存在则复用(nft 报 "already exists",复用 isChainExists 判定)。
			if !isChainExists(err) {
				return fmt.Errorf("nft add set %s: %w", s.Name, err)
			}
		}
		// 清空成员后重新灌入。
		_, _ = d.Exec.Run(ctx, "flush", "set", "inet", tableName, s.Name)
		if len(s.Members) > 0 {
			elem := make([]string, len(s.Members))
			for i, m := range s.Members {
				elem[i] = m
			}
			if _, err := d.Exec.Run(ctx, "add", "element", "inet", tableName, s.Name, "{ "+strings.Join(elem, ", ")+" }"); err != nil {
				return fmt.Errorf("nft add element %s: %w", s.Name, err)
			}
		}
	}
	return nil
}

func (d *Driver) Snapshot(ctx context.Context) (string, string, error) {
	var b strings.Builder
	familiesSeen := make(map[string]bool)
	for _, mc := range managedChains {
		if familiesSeen[mc.family] {
			continue
		}
		familiesSeen[mc.family] = true
		out, err := d.Exec.Run(ctx, "list", "table", mc.family, tableName)
		if err != nil {
			if isTableMissing(err) {
				continue
			}
			return "", "", fmt.Errorf("snapshot %s: %w", mc.family, err)
		}
		var curChain string
		for _, line := range strings.Split(out, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.Contains(line, "table ") || strings.Contains(line, "type filter") || 
				strings.Contains(line, "priority") || strings.Contains(line, "}") {
				continue
			}
			if strings.HasPrefix(line, "chain ") {
				curChain = strings.SplitN(strings.TrimPrefix(line, "chain "), " ", 2)[0]
				continue
			}
			if curChain != "" && line != "" {
				fmt.Fprintf(&b, "%s/%s %s\n", mc.family, curChain, line)
			}
		}
	}
	payload := b.String()
	if payload == "" {
		return "", "", nil
	}
	return payload, hashString(payload), nil
}

func (d *Driver) Restore(ctx context.Context, payload string) error {
	if err := d.Init(ctx); err != nil {
		return err
	}
	for _, mc := range managedChains {
		if err := d.flushChain(ctx, mc.family, mc.chain); err != nil {
			return err
		}
	}
	for _, line := range strings.Split(payload, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, " ", 2)
		if len(parts) != 2 {
			continue
		}
		familyChain := parts[0]
		exprs := parts[1]
		fcParts := strings.SplitN(familyChain, "/", 2)
		if len(fcParts) != 2 {
			continue
		}
		family, chain := fcParts[0], fcParts[1]
		if err := d.addRule(ctx, family, chain, exprs); err != nil {
			return fmt.Errorf("restore rule %q: %w", line, err)
		}
	}
	return nil
}

func (d *Driver) Hash(ctx context.Context) (string, error) {
	_, h, err := d.Snapshot(ctx)
	return h, err
}

func (d *Driver) Teardown(ctx context.Context) error {
	_, _ = d.Exec.Run(ctx, "delete", "table", "inet", tableName)
	_, _ = d.Exec.Run(ctx, "delete", "table", "ip", tableName)
	return nil
}

func (d *Driver) ensureTable(ctx context.Context) error {
	if _, err := d.Exec.Run(ctx, "add", "table", "inet", tableName); err != nil {
		if isTableExists(err) {
			return nil
		}
		return fmt.Errorf("ensure table: %w", err)
	}
	if _, err := d.Exec.Run(ctx, "add", "table", "ip", tableName); err != nil {
		if isTableExists(err) {
			return nil
		}
		return fmt.Errorf("ensure ip table: %w", err)
	}
	return nil
}

func (d *Driver) ensureChain(ctx context.Context, family, chain, hook string, priority int) error {
	if _, err := d.Exec.Run(ctx, "add", "chain", family, tableName, chain,
		fmt.Sprintf("{ type filter hook %s priority %d; policy accept; }", hook, priority)); err != nil {
		if isChainExists(err) {
			return nil
		}
		return fmt.Errorf("ensure chain %s/%s: %w", family, chain, err)
	}
	return nil
}

func (d *Driver) flushChain(ctx context.Context, family, chain string) error {
	if _, err := d.Exec.Run(ctx, "flush", "chain", family, tableName, chain); err != nil {
		return fmt.Errorf("flush %s/%s: %w", family, chain, err)
	}
	return nil
}

func (d *Driver) addRule(ctx context.Context, family, chain, exprs string) error {
	if _, err := d.Exec.Run(ctx, "add", "rule", family, tableName, chain, exprs); err != nil {
		return err
	}
	return nil
}

func targetChainFor(r *myfwv1.CompiledRule) (string, string, error) {
	switch r.Action {
	case myfwv1.Action_ACTION_DNAT:
		return "ip", "PREROUTING", nil
	case myfwv1.Action_ACTION_SNAT:
		return "ip", "POSTROUTING", nil
	}
	switch r.Direction {
	case myfwv1.Direction_DIRECTION_INBOUND:
		return "inet", "INPUT", nil
	case myfwv1.Direction_DIRECTION_OUTBOUND:
		return "inet", "OUTPUT", nil
	case myfwv1.Direction_DIRECTION_FORWARD:
		return "inet", "FORWARD", nil
	}
	return "", "", fmt.Errorf("cannot map rule %q: direction=%v action=%v",
		r.Id, r.Direction, r.Action)
}

// targetChainForRule nft 后端暂不支持自定义子链(table/family 映射待联调),
// 回退到 targetChainFor。chainToTable 参数保留以对齐 iptables driver 签名。
func targetChainForRule(r *myfwv1.CompiledRule, chainToTable map[string]string) (string, string, error) {
	return targetChainFor(r)
}

// syncCustomChains nft 后端同步自定义子链:当前为 no-op(nft family/table 映射待联调)。
func (d *Driver) syncCustomChains(ctx context.Context, chains []*myfwv1.CustomChainDef) error {
	return nil
}

func compileRule(r *myfwv1.CompiledRule) (string, error) {
	var exprs []string
	if r.Source != "" {
		exprs = append(exprs, fmt.Sprintf("ip saddr %s", r.Source))
	}
	if r.Destination != "" {
		exprs = append(exprs, fmt.Sprintf("ip daddr %s", r.Destination))
	}
	switch r.Protocol {
	case myfwv1.Protocol_PROTOCOL_TCP:
		exprs = append(exprs, "tcp")
	case myfwv1.Protocol_PROTOCOL_UDP:
		exprs = append(exprs, "udp")
	case myfwv1.Protocol_PROTOCOL_ICMP:
		exprs = append(exprs, "icmp")
	}
	if r.PortRange != "" {
		if r.Protocol == myfwv1.Protocol_PROTOCOL_UNSPECIFIED {
			return "", fmt.Errorf("rule %q: port range requires a protocol", r.Id)
		}
		portParts := strings.SplitN(r.PortRange, "-", 2)
		if len(portParts) == 1 {
			exprs = append(exprs, fmt.Sprintf("tcp dport %s", portParts[0]))
		} else {
			exprs = append(exprs, fmt.Sprintf("tcp dport %s-%s", portParts[0], portParts[1]))
		}
	}
	// 地址组匹配(多 CIDR,经 nft set)。
	if r.SourceGroup != "" {
		exprs = append(exprs, fmt.Sprintf("ip saddr @%s", r.SourceGroup))
	}
	if r.DestinationGroup != "" {
		exprs = append(exprs, fmt.Sprintf("ip daddr @%s", r.DestinationGroup))
	}
	// 匹配已打标记的流量(与 ACTION_MARK 打标正交)。
	if r.MatchMark != 0 {
		exprs = append(exprs, fmt.Sprintf("meta mark %d", r.MatchMark))
	}
	switch r.Action {
	case myfwv1.Action_ACTION_ACCEPT:
		exprs = append(exprs, "accept")
	case myfwv1.Action_ACTION_DROP:
		exprs = append(exprs, "drop")
	case myfwv1.Action_ACTION_REJECT:
		exprs = append(exprs, "reject")
	case myfwv1.Action_ACTION_MARK:
		exprs = append(exprs, fmt.Sprintf("meta mark set 0x%x", r.Mark))
	case myfwv1.Action_ACTION_DNAT:
		if r.NatTo == "" {
			return "", fmt.Errorf("rule %q: DNAT requires nat_to", r.Id)
		}
		exprs = append(exprs, fmt.Sprintf("dnat to %s", r.NatTo))
	case myfwv1.Action_ACTION_SNAT:
		if r.NatTo == "" {
			return "", fmt.Errorf("rule %q: SNAT requires nat_to", r.Id)
		}
		exprs = append(exprs, fmt.Sprintf("snat to %s", r.NatTo))
	default:
		return "", fmt.Errorf("rule %q: unsupported action %v", r.Id, r.Action)
	}
	return strings.Join(exprs, " "), nil
}

func isTableExists(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "File exists") ||
		strings.Contains(s, "already exists")
}

func isTableMissing(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "No such file or directory") ||
		strings.Contains(s, "does not exist")
}

func isChainExists(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "File exists") ||
		strings.Contains(s, "already exists")
}

func normalizeOutput(out string) string {
	var lines []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			lines = append(lines, line)
		}
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n") + "\n"
}

func hashString(s string) string {
	sum := sha256.Sum256([]byte(s))
	return "sha256:" + hex.EncodeToString(sum[:])
}

var _ driver.Driver = (*Driver)(nil)