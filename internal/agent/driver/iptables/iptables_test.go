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

	rules := []*myfwv1.CompiledRule{
		{
			Id: "r-in", Direction: myfwv1.Direction_DIRECTION_INBOUND,
			Source: "10.0.0.0/24", Protocol: myfwv1.Protocol_PROTOCOL_TCP,
			PortRange: "22", Action: myfwv1.Action_ACTION_ACCEPT, Priority: 10,
		},
		{
			Id: "r-out", Direction: myfwv1.Direction_DIRECTION_OUTBOUND,
			Destination: "0.0.0.0/0", Action: myfwv1.Action_ACTION_ACCEPT, Priority: 20,
		},
		{
			Id: "r-fwd", Direction: myfwv1.Direction_DIRECTION_FORWARD,
			Source: "192.168.0.0/16", Action: myfwv1.Action_ACTION_DROP, Priority: 5,
		},
		{
			Id: "r-dnat", Action: myfwv1.Action_ACTION_DNAT,
			Protocol: myfwv1.Protocol_PROTOCOL_TCP, PortRange: "80",
			NatTo: "10.0.0.5:8080", Priority: 30,
		},
		{
			Id: "r-mark", Action: myfwv1.Action_ACTION_MARK, Mark: 42,
			Protocol: myfwv1.Protocol_PROTOCOL_TCP, PortRange: "443", Priority: 40,
		},
	}

	hash, err := d.Apply(ctx, rules)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !strings.HasPrefix(hash, "sha256:") {
		t.Fatalf("bad hash prefix: %s", hash)
	}

	// Check placement.
	assertHas := func(t *testing.T, table, chain, needle string) {
		t.Helper()
		for _, r := range fake.Tables[table][chain] {
			if strings.Contains(r, needle) {
				return
			}
		}
		t.Fatalf("expected %q in %s/%s, chain contents: %v", needle, table, chain, fake.Tables[table][chain])
	}
	assertHas(t, tableFilter, chainInput, "-s 10.0.0.0/24")
	assertHas(t, tableFilter, chainOutput, "-d 0.0.0.0/0")
	assertHas(t, tableFilter, chainForward, "-j DROP")
	assertHas(t, tableNat, chainNatPre, "-j DNAT")
	assertHas(t, tableMangle, chainMangle, "-j MARK")
}

func TestApplyFlushesBeforeRefilling(t *testing.T) {
	d, fake := newDriver(t)
	ctx := context.Background()

	first := []*myfwv1.CompiledRule{
		{Id: "a", Direction: myfwv1.Direction_DIRECTION_INBOUND, Source: "1.1.1.1", Action: myfwv1.Action_ACTION_ACCEPT},
		{Id: "b", Direction: myfwv1.Direction_DIRECTION_INBOUND, Source: "2.2.2.2", Action: myfwv1.Action_ACTION_ACCEPT},
	}
	if _, err := d.Apply(ctx, first); err != nil {
		t.Fatal(err)
	}
	if got := len(fake.Tables[tableFilter][chainInput]); got != 2 {
		t.Fatalf("first apply: want 2 rules in MYFW-INPUT, got %d", got)
	}

	// Apply a smaller ruleset — the old rules must NOT survive.
	second := []*myfwv1.CompiledRule{
		{Id: "c", Direction: myfwv1.Direction_DIRECTION_INBOUND, Source: "3.3.3.3", Action: myfwv1.Action_ACTION_ACCEPT},
	}

	if _, err := d.Apply(ctx, second); err != nil {
		t.Fatal(err)
	}
	if got := len(fake.Tables[tableFilter][chainInput]); got != 1 {
		t.Fatalf("second apply: want 1 rule in MYFW-INPUT, got %d: %v",
			got, fake.Tables[tableFilter][chainInput])
	}
	if !strings.Contains(fake.Tables[tableFilter][chainInput][0], "3.3.3.3") {
		t.Fatalf("second apply: MYFW-INPUT should hold the new rule, got %v",
			fake.Tables[tableFilter][chainInput])
	}
}

func TestSnapshotAndRestoreRoundTrip(t *testing.T) {
	d, _ := newDriver(t)
	ctx := context.Background()

	rules := []*myfwv1.CompiledRule{
		{Id: "a", Direction: myfwv1.Direction_DIRECTION_INBOUND, Source: "5.6.7.8", Action: myfwv1.Action_ACTION_ACCEPT},
		{Id: "b", Direction: myfwv1.Direction_DIRECTION_INBOUND, Source: "9.10.11.12", Action: myfwv1.Action_ACTION_DROP},
	}
	if _, err := d.Apply(ctx, rules); err != nil {
		t.Fatal(err)
	}

	payload, h1, err := d.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// Change state, then restore.
	if _, err := d.Apply(ctx, nil); err != nil {
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

func TestHashIsDeterministicAcrossRuleOrder(t *testing.T) {
	d1, _ := newDriver(t)
	d2, _ := newDriver(t)
	ctx := context.Background()

	base := []*myfwv1.CompiledRule{
		{Id: "a", Priority: 1, Direction: myfwv1.Direction_DIRECTION_INBOUND, Source: "1.1.1.1", Action: myfwv1.Action_ACTION_ACCEPT},
		{Id: "b", Priority: 2, Direction: myfwv1.Direction_DIRECTION_INBOUND, Source: "2.2.2.2", Action: myfwv1.Action_ACTION_ACCEPT},
	}
	reversed := []*myfwv1.CompiledRule{base[1], base[0]}

	h1, err := d1.Apply(ctx, base)
	if err != nil {
		t.Fatal(err)
	}
	h2, err := d2.Apply(ctx, reversed)
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
