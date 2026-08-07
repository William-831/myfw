package iptables

import (
	"context"
	"strings"
	"testing"

	myfwv1 "iptables-tool/api/myfw/v1"
	"iptables-tool/internal/agent/driver/iptables/fakeexec"
)

func newDriver(t *testing.T) (*Driver, *fakeexec.Fake) {
	t.Helper()
	f := fakeexec.New()
	return New(f, myfwv1.FirewallBackend_FIREWALL_BACKEND_IPTABLES_NFT), f
}

func TestInitCreatesChainsAndJumps(t *testing.T) {
	d, fake := newDriver(t)
	ctx := context.Background()
	if err := d.Init(ctx); err != nil {
		t.Fatalf("Init: %v", err)
	}
	// All managed chains must exist.
	for _, mc := range managedChains {
		if _, ok := fake.Tables[mc.table][mc.chain]; !ok {
			t.Fatalf("chain %s/%s not created", mc.table, mc.chain)
		}
	}
	// All system jumps must exist exactly once.
	for _, j := range systemJumps {
		count := 0
		for _, r := range fake.Tables[j.table][j.sysChain] {
			if strings.Contains(r, "-j "+j.myfwChain) {
				count++
			}
		}
		if count != 1 {
			t.Fatalf("expected exactly one jump %s -> %s in %s/%s, got %d",
				j.sysChain, j.myfwChain, j.table, j.sysChain, count)
		}
	}
	// Init a second time should be idempotent (still exactly one jump each).
	if err := d.Init(ctx); err != nil {
		t.Fatalf("second Init: %v", err)
	}
	for _, j := range systemJumps {
		count := 0
		for _, r := range fake.Tables[j.table][j.sysChain] {
			if strings.Contains(r, "-j "+j.myfwChain) {
				count++
			}
		}
		if count != 1 {
			t.Fatalf("jump %s -> %s not idempotent: count=%d", j.sysChain, j.myfwChain, count)
		}
	}
}

func TestApplyPlacesRulesInRightChains(t *testing.T) {
	d, fake := newDriver(t)
	ctx := context.Background()

	// 两级模型:业务规则归属策略组(自定义子链),driver 落 MYFW-<组名> 链。
	cc := []*myfwv1.CustomChainDef{
		{Name: "acl-in", Parent: "MYFW-INPUT", Table: "filter"},
		{Name: "acl-out", Parent: "MYFW-OUTPUT", Table: "filter"},
		{Name: "acl-fwd", Parent: "MYFW-FORWARD", Table: "filter"},
		{Name: "nat-pre", Parent: "MYFW-PREROUTING", Table: "nat"},
		{Name: "mark-mg", Parent: "MYFW-MANGLE", Table: "mangle"},
	}
	rules := []*myfwv1.CompiledRule{
		{
			Id: "r-in", Chain: "acl-in", Direction: myfwv1.Direction_DIRECTION_INBOUND,
			Source: "10.0.0.0/24", Protocol: myfwv1.Protocol_PROTOCOL_TCP,
			PortRange: "22", Action: myfwv1.Action_ACTION_ACCEPT, Priority: 10,
		},
		{
			Id: "r-out", Chain: "acl-out", Direction: myfwv1.Direction_DIRECTION_OUTBOUND,
			Destination: "0.0.0.0/0", Action: myfwv1.Action_ACTION_ACCEPT, Priority: 20,
		},
		{
			Id: "r-fwd", Chain: "acl-fwd", Direction: myfwv1.Direction_DIRECTION_FORWARD,
			Source: "192.168.0.0/16", Action: myfwv1.Action_ACTION_DROP, Priority: 5,
		},
		{
			Id: "r-dnat", Chain: "nat-pre", Action: myfwv1.Action_ACTION_DNAT,
			Protocol: myfwv1.Protocol_PROTOCOL_TCP, PortRange: "80",
			NatTo: "10.0.0.5:8080", Priority: 30,
		},
		{
			Id: "r-mark", Chain: "mark-mg", Action: myfwv1.Action_ACTION_MARK, Mark: 42,
			Protocol: myfwv1.Protocol_PROTOCOL_TCP, PortRange: "443", Priority: 40,
		},
	}

	hash, err := d.Apply(ctx, &myfwv1.RuleSet{Rules: rules, CustomChains: cc})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !strings.HasPrefix(hash, "sha256:") {
		t.Fatalf("bad hash prefix: %s", hash)
	}

	// Check placement:规则落组链(带 MYFW- 前缀),表取自组定义。
	assertHas := func(t *testing.T, table, chain, needle string) {
		t.Helper()
		for _, r := range fake.Tables[table][chain] {
			if strings.Contains(r, needle) {
				return
			}
		}
		t.Fatalf("expected %q in %s/%s, chain contents: %v", needle, table, chain, fake.Tables[table][chain])
	}
	assertHas(t, tableFilter, "MYFW-acl-in", "-s 10.0.0.0/24")
	assertHas(t, tableFilter, "MYFW-acl-out", "-d 0.0.0.0/0")
	assertHas(t, tableFilter, "MYFW-acl-fwd", "-j DROP")
	assertHas(t, tableNat, "MYFW-nat-pre", "-j DNAT")
	assertHas(t, tableMangle, "MYFW-mark-mg", "-j MARK")
}

func TestApplyFlushesBeforeRefilling(t *testing.T) {
	d, fake := newDriver(t)
	ctx := context.Background()

	// 业务规则落组链 MYFW-acl-in,断言针对组链而非系统链。
	cc := []*myfwv1.CustomChainDef{{Name: "acl-in", Parent: "MYFW-INPUT", Table: "filter"}}
	first := []*myfwv1.CompiledRule{
		{Id: "a", Chain: "acl-in", Direction: myfwv1.Direction_DIRECTION_INBOUND, Source: "1.1.1.1", Action: myfwv1.Action_ACTION_ACCEPT},
		{Id: "b", Chain: "acl-in", Direction: myfwv1.Direction_DIRECTION_INBOUND, Source: "2.2.2.2", Action: myfwv1.Action_ACTION_ACCEPT},
	}
	if _, err := d.Apply(ctx, &myfwv1.RuleSet{Rules: first, CustomChains: cc}); err != nil {
		t.Fatal(err)
	}
	if got := len(fake.Tables[tableFilter]["MYFW-acl-in"]); got != 2 {
		t.Fatalf("first apply: want 2 rules in MYFW-acl-in, got %d", got)
	}

	// Apply a smaller ruleset — the old rules must NOT survive.
	second := []*myfwv1.CompiledRule{
		{Id: "c", Chain: "acl-in", Direction: myfwv1.Direction_DIRECTION_INBOUND, Source: "3.3.3.3", Action: myfwv1.Action_ACTION_ACCEPT},
	}

	if _, err := d.Apply(ctx, &myfwv1.RuleSet{Rules: second, CustomChains: cc}); err != nil {
		t.Fatal(err)
	}
	if got := len(fake.Tables[tableFilter]["MYFW-acl-in"]); got != 1 {
		t.Fatalf("second apply: want 1 rule in MYFW-acl-in, got %d: %v",
			got, fake.Tables[tableFilter]["MYFW-acl-in"])
	}
	if !strings.Contains(fake.Tables[tableFilter]["MYFW-acl-in"][0], "3.3.3.3") {
		t.Fatalf("second apply: MYFW-acl-in should hold the new rule, got %v",
			fake.Tables[tableFilter]["MYFW-acl-in"])
	}
}

func TestSnapshotAndRestoreRoundTrip(t *testing.T) {
	d, _ := newDriver(t)
	ctx := context.Background()

	// Snapshot/Restore 覆盖 managedChains(系统 MYFW-* 链);业务规则落组链不参与
	// snapshot,故 round-trip 验证的是系统链层(ESTABLISHED+jump)恢复后 hash 一致。
	cc := []*myfwv1.CustomChainDef{{Name: "acl-in", Parent: "MYFW-INPUT", Table: "filter"}}
	rules := []*myfwv1.CompiledRule{
		{Id: "a", Chain: "acl-in", Direction: myfwv1.Direction_DIRECTION_INBOUND, Source: "5.6.7.8", Action: myfwv1.Action_ACTION_ACCEPT},
		{Id: "b", Chain: "acl-in", Direction: myfwv1.Direction_DIRECTION_INBOUND, Source: "9.10.11.12", Action: myfwv1.Action_ACTION_DROP},
	}
	if _, err := d.Apply(ctx, &myfwv1.RuleSet{Rules: rules, CustomChains: cc}); err != nil {
		t.Fatal(err)
	}

	payload, h1, err := d.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// Change state, then restore.
	if _, err := d.Apply(ctx, &myfwv1.RuleSet{}); err != nil {
		t.Fatal(err)
	}
	if err := d.Restore(ctx, payload); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	h2, err := d.Hash(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 {
		t.Fatalf("hash after restore differs: %s vs %s", h1, h2)
	}
}

// TestSnapshotRestoreCoversCustomChains 验证两级模型下 Snapshot 包含自定义组链,
// Restore 能完整重建组链业务规则(保护期回滚完整性)。
func TestSnapshotRestoreCoversCustomChains(t *testing.T) {
	d1, _ := newDriver(t)
	ctx := context.Background()

	cc := []*myfwv1.CustomChainDef{{Name: "acl-in", Parent: "MYFW-INPUT", Table: "filter"}}
	rules := []*myfwv1.CompiledRule{
		{Id: "a", Chain: "acl-in", Direction: myfwv1.Direction_DIRECTION_INBOUND, Source: "5.6.7.8", Action: myfwv1.Action_ACTION_ACCEPT},
		{Id: "b", Chain: "acl-in", Direction: myfwv1.Direction_DIRECTION_INBOUND, Source: "9.10.11.12", Action: myfwv1.Action_ACTION_DROP},
	}
	if _, err := d1.Apply(ctx, &myfwv1.RuleSet{Rules: rules, CustomChains: cc}); err != nil {
		t.Fatal(err)
	}
	payload, h1, err := d1.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// payload 必须包含组链声明与规则
	if !strings.Contains(payload, "# filter/MYFW-acl-in") {
		t.Fatalf("snapshot should include custom chain MYFW-acl-in:\n%s", payload)
	}
	if !strings.Contains(payload, "-A MYFW-acl-in -s 5.6.7.8") {
		t.Fatalf("snapshot should include group chain rule:\n%s", payload)
	}

	// 新 driver 直接 Restore(模拟保护期回滚):组链应完整重建
	d2, fake2 := newDriver(t)
	if err := d2.Restore(ctx, payload); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if got := len(fake2.Tables["filter"]["MYFW-acl-in"]); got != 2 {
		t.Fatalf("restore: want 2 rules in MYFW-acl-in, got %d: %v", got, fake2.Tables["filter"]["MYFW-acl-in"])
	}
	h2, err := d2.Hash(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 {
		t.Fatalf("hash after restore differs: %s vs %s", h1, h2)
	}
}

func TestHashIsDeterministicAcrossRuleOrder(t *testing.T) {
	d1, _ := newDriver(t)
	d2, _ := newDriver(t)
	ctx := context.Background()

	cc := []*myfwv1.CustomChainDef{{Name: "acl-in", Parent: "MYFW-INPUT", Table: "filter"}}
	base := []*myfwv1.CompiledRule{
		{Id: "a", Chain: "acl-in", Priority: 1, Direction: myfwv1.Direction_DIRECTION_INBOUND, Source: "1.1.1.1", Action: myfwv1.Action_ACTION_ACCEPT},
		{Id: "b", Chain: "acl-in", Priority: 2, Direction: myfwv1.Direction_DIRECTION_INBOUND, Source: "2.2.2.2", Action: myfwv1.Action_ACTION_ACCEPT},
	}
	reversed := []*myfwv1.CompiledRule{base[1], base[0]}

	h1, err := d1.Apply(ctx, &myfwv1.RuleSet{Rules: base, CustomChains: cc})
	if err != nil {
		t.Fatal(err)
	}
	h2, err := d2.Apply(ctx, &myfwv1.RuleSet{Rules: reversed, CustomChains: cc})
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 {
		t.Fatalf("hash should not depend on input order, got %s vs %s", h1, h2)
	}
}

func TestTeardownRemovesEverything(t *testing.T) {
	d, fake := newDriver(t)
	ctx := context.Background()
	if err := d.Init(ctx); err != nil {
		t.Fatal(err)
	}
	if err := d.Teardown(ctx); err != nil {
		t.Fatal(err)
	}
	for _, mc := range managedChains {
		if _, ok := fake.Tables[mc.table][mc.chain]; ok {
			t.Fatalf("chain %s/%s should be gone after Teardown", mc.table, mc.chain)
		}
	}
	for _, j := range systemJumps {
		for _, r := range fake.Tables[j.table][j.sysChain] {
			if strings.Contains(r, "-j "+j.myfwChain) {
				t.Fatalf("residual jump into %s in %s/%s: %s", j.myfwChain, j.table, j.sysChain, r)
			}
		}
	}
}
