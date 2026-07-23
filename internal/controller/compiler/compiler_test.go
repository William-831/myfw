package compiler

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"gorm.io/gorm/logger"

	myfwv1 "iptables-tool/api/myfw/v1"
	"iptables-tool/internal/controller/policy"
	"iptables-tool/internal/db"
	"iptables-tool/internal/model"
)

func newTestCompiler(t *testing.T) (*Compiler, *policy.Service) {
	t.Helper()
	// Use an on-disk temp DB so parallel/serial tests don't share state via
	// SQLite's shared-cache mode.
	t.Setenv("MYFW_DB_DRIVER", "sqlite")
	t.Setenv("MYFW_DB_DSN", t.TempDir()+"/comp.db")
	cfg, err := db.ConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	cfg.LogLevel = logger.Silent
	gdb, err := db.Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(gdb); err != nil {
		t.Fatal(err)
	}
	return New(gdb), policy.New(gdb)
}

func mustCreateNode(t *testing.T, c *Compiler, id string, labels ...string) {
	t.Helper()
	labelsJSON, _ := json.Marshal(labels)
	err := c.DB.Create(&model.Node{
		ID: id, Status: model.NodeStatusActive, Hostname: id,
		Labels: string(labelsJSON),
	}).Error
	if err != nil {
		t.Fatal(err)
	}
}

func TestCompileForNodePicksExplicitTargets(t *testing.T) {
	c, ps := newTestCompiler(t)
	ctx := context.Background()

	mustCreateNode(t, c, "n_a")
	mustCreateNode(t, c, "n_b")

	// Policy on n_a only.
	_, err := ps.Create(ctx, policy.PolicyInput{
		Name: "allow-ssh", Direction: "INBOUND",
		Source: "10.0.0.0/24", Protocol: "TCP", PortRange: "22",
		Action: "ACCEPT", Priority: 10,
		Targets: policy.TargetsSpec{NodeIDs: []string{"n_a"}},
		Enabled: true,
	}, "t")
	if err != nil {
		t.Fatal(err)
	}

	// n_a should see it, n_b should not.
	got, err := c.CompileForNode(ctx, "n_a")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].PortRange != "22" {
		t.Fatalf("n_a: unexpected: %+v", got)
	}
	got, err = c.CompileForNode(ctx, "n_b")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("n_b: expected 0 rules, got %+v", got)
	}
}

func TestCompileForNodeSkipsDisabled(t *testing.T) {
	c, ps := newTestCompiler(t)
	ctx := context.Background()
	mustCreateNode(t, c, "n_a")

	_, err := ps.Create(ctx, policy.PolicyInput{
		Name: "off", Direction: "INBOUND", Action: "DROP",
		Targets: policy.TargetsSpec{NodeIDs: []string{"n_a"}},
		Enabled: false,
	}, "t")
	if err != nil {
		t.Fatal(err)
	}

	got, err := c.CompileForNode(ctx, "n_a")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("expected 0 rules for a disabled policy, got %+v", got)
	}
}

func TestCompileForNodeStableOrder(t *testing.T) {
	c, ps := newTestCompiler(t)
	ctx := context.Background()
	mustCreateNode(t, c, "n_a")

	// Insert with priorities out of order; expect ascending order in output.
	mkOne := func(name string, prio int) {
		_, err := ps.Create(ctx, policy.PolicyInput{
			Name: name, Direction: "INBOUND", Action: "ACCEPT", Priority: prio,
			Targets: policy.TargetsSpec{NodeIDs: []string{"n_a"}},
			Enabled: true,
		}, "t")
		if err != nil {
			t.Fatal(err)
		}
	}
	mkOne("second", 20)
	mkOne("first", 10)
	mkOne("third", 30)

	got, err := c.CompileForNode(ctx, "n_a")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 rules, got %d", len(got))
	}
	if got[0].Priority != 10 || got[1].Priority != 20 || got[2].Priority != 30 {
		t.Fatalf("bad order: %d %d %d", got[0].Priority, got[1].Priority, got[2].Priority)
	}
}

func TestLabelSelectorMatchesIntersection(t *testing.T) {
	c, ps := newTestCompiler(t)
	ctx := context.Background()

	mustCreateNode(t, c, "n_prod_edge", "prod", "edge")
	mustCreateNode(t, c, "n_prod", "prod")
	mustCreateNode(t, c, "n_edge", "edge")

	_, err := ps.Create(ctx, policy.PolicyInput{
		Name: "prod-edge-only", Direction: "INBOUND", Action: "ACCEPT",
		Targets: policy.TargetsSpec{Labels: []string{"prod", "edge"}},
		Enabled: true,
	}, "t")
	if err != nil {
		t.Fatal(err)
	}

	// Only n_prod_edge has BOTH labels.
	cases := map[string]int{
		"n_prod_edge": 1,
		"n_prod":      0,
		"n_edge":      0,
	}
	for id, want := range cases {
		got, err := c.CompileForNode(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != want {
			t.Fatalf("%s: want %d rules, got %d", id, want, len(got))
		}
	}
}

func TestCompileActionsMapCorrectly(t *testing.T) {
	c, ps := newTestCompiler(t)
	ctx := context.Background()
	mustCreateNode(t, c, "n_a")

	cases := []struct {
		action string
		want   myfwv1.Action
		extra  policy.PolicyInput
	}{
		{"ACCEPT", myfwv1.Action_ACTION_ACCEPT, policy.PolicyInput{}},
		{"DROP", myfwv1.Action_ACTION_DROP, policy.PolicyInput{}},
		{"REJECT", myfwv1.Action_ACTION_REJECT, policy.PolicyInput{}},
		{"DNAT", myfwv1.Action_ACTION_DNAT, policy.PolicyInput{NatTo: "10.0.0.5:8080"}},
		{"SNAT", myfwv1.Action_ACTION_SNAT, policy.PolicyInput{NatTo: "203.0.113.1"}},
	}
	prio := 0
	for _, tc := range cases {
		in := policy.PolicyInput{
			Name: tc.action + "-test", Direction: "INBOUND",
			Action: tc.action, Priority: prio,
			NatTo:   tc.extra.NatTo,
			Targets: policy.TargetsSpec{NodeIDs: []string{"n_a"}},
			Enabled: true,
		}
		prio++
		if _, err := ps.Create(ctx, in, "t"); err != nil {
			t.Fatalf("create %s: %v", tc.action, err)
		}
	}

	got, err := c.CompileForNode(ctx, "n_a")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(cases) {
		t.Fatalf("want %d rules, got %d", len(cases), len(got))
	}
	for i, tc := range cases {
		if got[i].Action != tc.want {
			t.Errorf("case %d (%s): want %v, got %v", i, tc.action, tc.want, got[i].Action)
		}
	}
	_ = time.Now // silence unused if we ever remove time
}
