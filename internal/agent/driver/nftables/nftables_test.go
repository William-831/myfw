package nftables

import (
	"context"
	"testing"

	myfwv1 "iptables-tool/api/myfw/v1"
	"iptables-tool/internal/agent/driver/nftables/fakeexec"
)

func TestInit(t *testing.T) {
	fake := fakeexec.New()
	d := New(fake, myfwv1.FirewallBackend_FIREWALL_BACKEND_NFTABLES)
	if err := d.Init(context.Background()); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	if len(fake.Tables) == 0 {
		t.Fatal("Init did not create any tables")
	}
	if fake.Tables["inet"] == nil {
		t.Fatal("Init did not create inet table")
	}
	if fake.Tables["inet"].Chains["INPUT"] == nil {
		t.Fatal("Init did not create INPUT chain")
	}
}

func TestInitIdempotent(t *testing.T) {
	fake := fakeexec.New()
	d := New(fake, myfwv1.FirewallBackend_FIREWALL_BACKEND_NFTABLES)
	if err := d.Init(context.Background()); err != nil {
		t.Fatalf("first Init failed: %v", err)
	}
	if err := d.Init(context.Background()); err != nil {
		t.Fatalf("second Init failed (not idempotent): %v", err)
	}
}

func TestApply(t *testing.T) {
	fake := fakeexec.New()
	d := New(fake, myfwv1.FirewallBackend_FIREWALL_BACKEND_NFTABLES)
	rules := []*myfwv1.CompiledRule{
		{
			Id:       "r1",
			Direction: myfwv1.Direction_DIRECTION_INBOUND,
			Source:   "10.0.0.0/24",
			Protocol: myfwv1.Protocol_PROTOCOL_TCP,
			PortRange: "22",
			Action:   myfwv1.Action_ACTION_ACCEPT,
			Priority: 10,
		},
	}
	hash, err := d.Apply(context.Background(), &myfwv1.RuleSet{Rules: rules})
	if err != nil {
		t.Fatalf("Apply failed: %v", err)
	}
	if hash == "" {
		t.Fatal("Apply returned empty hash")
	}
	if len(fake.Tables["inet"].Chains["INPUT"].Rules) != 1 {
		t.Fatalf("expected 1 rule in INPUT, got %d", len(fake.Tables["inet"].Chains["INPUT"].Rules))
	}
}

func TestSnapshot(t *testing.T) {
	fake := fakeexec.New()
	d := New(fake, myfwv1.FirewallBackend_FIREWALL_BACKEND_NFTABLES)
	rules := []*myfwv1.CompiledRule{
		{
			Id:       "r1",
			Direction: myfwv1.Direction_DIRECTION_INBOUND,
			Source:   "10.0.0.0/24",
			Protocol: myfwv1.Protocol_PROTOCOL_TCP,
			PortRange: "22",
			Action:   myfwv1.Action_ACTION_ACCEPT,
			Priority: 10,
		},
	}
	if _, err := d.Apply(context.Background(), &myfwv1.RuleSet{Rules: rules}); err != nil {
		t.Fatalf("Apply failed: %v", err)
	}
	payload, hash, err := d.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("Snapshot failed: %v", err)
	}
	if payload == "" {
		t.Fatal("Snapshot returned empty payload")
	}
	if hash == "" {
		t.Fatal("Snapshot returned empty hash")
	}
}

func TestSnapshotEmpty(t *testing.T) {
	fake := fakeexec.New()
	d := New(fake, myfwv1.FirewallBackend_FIREWALL_BACKEND_NFTABLES)
	payload, hash, err := d.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("Snapshot on empty should not fail: %v", err)
	}
	if payload != "" {
		t.Fatalf("expected empty payload, got %q", payload)
	}
	if hash != "" {
		t.Fatalf("expected empty hash, got %q", hash)
	}
}

func TestRestore(t *testing.T) {
	fake := fakeexec.New()
	d := New(fake, myfwv1.FirewallBackend_FIREWALL_BACKEND_NFTABLES)
	rules := []*myfwv1.CompiledRule{
		{
			Id:       "r1",
			Direction: myfwv1.Direction_DIRECTION_INBOUND,
			Source:   "10.0.0.0/24",
			Protocol: myfwv1.Protocol_PROTOCOL_TCP,
			PortRange: "22",
			Action:   myfwv1.Action_ACTION_ACCEPT,
			Priority: 10,
		},
	}
	if _, err := d.Apply(context.Background(), &myfwv1.RuleSet{Rules: rules}); err != nil {
		t.Fatalf("Apply failed: %v", err)
	}
	payload, _, err := d.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("Snapshot failed: %v", err)
	}
	fake2 := fakeexec.New()
	d2 := New(fake2, myfwv1.FirewallBackend_FIREWALL_BACKEND_NFTABLES)
	if err := d2.Restore(context.Background(), payload); err != nil {
		t.Fatalf("Restore failed: %v", err)
	}
	if len(fake2.Tables["inet"].Chains["INPUT"].Rules) != 1 {
		t.Fatalf("expected 1 rule after restore, got %d", len(fake2.Tables["inet"].Chains["INPUT"].Rules))
	}
}

func TestHash(t *testing.T) {
	fake := fakeexec.New()
	d := New(fake, myfwv1.FirewallBackend_FIREWALL_BACKEND_NFTABLES)
	rules := []*myfwv1.CompiledRule{
		{
			Id:       "r1",
			Direction: myfwv1.Direction_DIRECTION_INBOUND,
			Source:   "10.0.0.0/24",
			Protocol: myfwv1.Protocol_PROTOCOL_TCP,
			PortRange: "22",
			Action:   myfwv1.Action_ACTION_ACCEPT,
			Priority: 10,
		},
	}
	if _, err := d.Apply(context.Background(), &myfwv1.RuleSet{Rules: rules}); err != nil {
		t.Fatalf("Apply failed: %v", err)
	}
	hash1, err := d.Hash(context.Background())
	if err != nil {
		t.Fatalf("first Hash failed: %v", err)
	}
	hash2, err := d.Hash(context.Background())
	if err != nil {
		t.Fatalf("second Hash failed: %v", err)
	}
	if hash1 != hash2 {
		t.Fatalf("Hash is not stable: %q != %q", hash1, hash2)
	}
}

func TestTeardown(t *testing.T) {
	fake := fakeexec.New()
	d := New(fake, myfwv1.FirewallBackend_FIREWALL_BACKEND_NFTABLES)
	if err := d.Init(context.Background()); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	if err := d.Teardown(context.Background()); err != nil {
		t.Fatalf("Teardown failed: %v", err)
	}
	if fake.Tables["inet"] != nil {
		t.Fatal("Teardown did not remove inet table")
	}
}

func TestApplyTwoRules(t *testing.T) {
	fake := fakeexec.New()
	d := New(fake, myfwv1.FirewallBackend_FIREWALL_BACKEND_NFTABLES)
	rules := []*myfwv1.CompiledRule{
		{
			Id:       "r1",
			Direction: myfwv1.Direction_DIRECTION_INBOUND,
			Source:   "10.0.0.0/24",
			Protocol: myfwv1.Protocol_PROTOCOL_TCP,
			PortRange: "22",
			Action:   myfwv1.Action_ACTION_ACCEPT,
			Priority: 10,
		},
		{
			Id:       "r2",
			Direction: myfwv1.Direction_DIRECTION_OUTBOUND,
			Destination: "192.168.0.0/24",
			Protocol: myfwv1.Protocol_PROTOCOL_UDP,
			PortRange: "53",
			Action:   myfwv1.Action_ACTION_ACCEPT,
			Priority: 20,
		},
	}
	_, err := d.Apply(context.Background(), &myfwv1.RuleSet{Rules: rules})
	if err != nil {
		t.Fatalf("Apply failed: %v", err)
	}
	if len(fake.Tables["inet"].Chains["INPUT"].Rules) != 1 {
		t.Fatalf("expected 1 rule in INPUT, got %d", len(fake.Tables["inet"].Chains["INPUT"].Rules))
	}
	if len(fake.Tables["inet"].Chains["OUTPUT"].Rules) != 1 {
		t.Fatalf("expected 1 rule in OUTPUT, got %d", len(fake.Tables["inet"].Chains["OUTPUT"].Rules))
	}
}

func TestFlushBeforeFill(t *testing.T) {
	fake := fakeexec.New()
	d := New(fake, myfwv1.FirewallBackend_FIREWALL_BACKEND_NFTABLES)
	rules1 := []*myfwv1.CompiledRule{
		{
			Id:       "r1",
			Direction: myfwv1.Direction_DIRECTION_INBOUND,
			Source:   "10.0.0.0/24",
			Protocol: myfwv1.Protocol_PROTOCOL_TCP,
			PortRange: "22",
			Action:   myfwv1.Action_ACTION_ACCEPT,
			Priority: 10,
		},
	}
	if _, err := d.Apply(context.Background(), &myfwv1.RuleSet{Rules: rules1}); err != nil {
		t.Fatalf("first Apply failed: %v", err)
	}
	rules2 := []*myfwv1.CompiledRule{
		{
			Id:       "r2",
			Direction: myfwv1.Direction_DIRECTION_INBOUND,
			Source:   "172.16.0.0/12",
			Protocol: myfwv1.Protocol_PROTOCOL_TCP,
			PortRange: "80",
			Action:   myfwv1.Action_ACTION_ACCEPT,
			Priority: 10,
		},
	}
	if _, err := d.Apply(context.Background(), &myfwv1.RuleSet{Rules: rules2}); err != nil {
		t.Fatalf("second Apply failed: %v", err)
	}
	if len(fake.Tables["inet"].Chains["INPUT"].Rules) != 1 {
		t.Fatalf("expected 1 rule after second Apply, got %d", len(fake.Tables["inet"].Chains["INPUT"].Rules))
	}
	if !containsRule(fake.Tables["inet"].Chains["INPUT"].Rules, "172.16.0.0/12") {
		t.Fatal("second rule not found")
	}
}

func TestSnapshotFormat(t *testing.T) {
	fake := fakeexec.New()
	d := New(fake, myfwv1.FirewallBackend_FIREWALL_BACKEND_NFTABLES)
	rules := []*myfwv1.CompiledRule{
		{
			Id:         "r1",
			Direction:  myfwv1.Direction_DIRECTION_INBOUND,
			Source:     "10.0.0.0/24",
			Protocol:   myfwv1.Protocol_PROTOCOL_TCP,
			PortRange:  "22",
			Action:     myfwv1.Action_ACTION_ACCEPT,
			Priority:   10,
		},
	}
	if _, err := d.Apply(context.Background(), &myfwv1.RuleSet{Rules: rules}); err != nil {
		t.Fatalf("Apply failed: %v", err)
	}
	payload, _, err := d.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("Snapshot failed: %v", err)
	}
	t.Logf("Snapshot payload:\n%s", payload)
}

func containsRule(rules []string, needle string) bool {
	for _, r := range rules {
		if contains(r, needle) {
			return true
		}
	}
	return false
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}