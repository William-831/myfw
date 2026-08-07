package compiler

import (
	"context"
	"encoding/json"
	"testing"

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
	t.Cleanup(func() { // 关闭 db 句柄,避免 Windows 下 TempDir 清理时文件占用
		if sqlDB, err := gdb.DB(); err == nil {
			sqlDB.Close()
		}
	})
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

// mustCreateChain 建一个测试策略组并返回 ID(实例/策略必须归属有效组)。
func mustCreateChain(t *testing.T, c *Compiler) uint {
	t.Helper()
	ch := model.CustomChain{Name: "acl-fwd", Parent: "MYFW-FORWARD", Table: "filter", Priority: 1, Enabled: true}
	if err := c.DB.Create(&ch).Error; err != nil {
		t.Fatal(err)
	}
	return ch.ID
}

// mustCreateInstance 直接建一条节点策略实例(新模型:编译读 NodePolicyInstance,不读 Policy)。
func mustCreateInstance(t *testing.T, c *Compiler, inst model.NodePolicyInstance) {
	t.Helper()
	if err := c.DB.Create(&inst).Error; err != nil {
		t.Fatal(err)
	}
}

func TestCompileForNodePicksExplicitTargets(t *testing.T) {
	c, _ := newTestCompiler(t)
	ctx := context.Background()

	mustCreateNode(t, c, "n_a")
	mustCreateNode(t, c, "n_b")
	gid := mustCreateChain(t, c)

	// 实例只绑 n_a,编译按 node_id 查实例。
	mustCreateInstance(t, c, model.NodePolicyInstance{
		NodeID: "n_a", Name: "allow-ssh", GroupID: gid,
		Source: "10.0.0.0/24", Protocol: "TCP", PortRange: "22",
		Action: "ACCEPT", Priority: 10, Enabled: true,
	})

	// n_a should see it, n_b should not.
	got, _, _, err := c.CompileForNode(ctx, "n_a")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].PortRange != "22" {
		t.Fatalf("n_a: unexpected: %+v", got)
	}
	got, _, _, err = c.CompileForNode(ctx, "n_b")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("n_b: expected 0 rules, got %+v", got)
	}
}

func TestCompileForNodeSkipsDisabled(t *testing.T) {
	c, _ := newTestCompiler(t)
	ctx := context.Background()
	mustCreateNode(t, c, "n_a")
	gid := mustCreateChain(t, c)

	mustCreateInstance(t, c, model.NodePolicyInstance{
		NodeID: "n_a", Name: "off", GroupID: gid, Action: "DROP",
		Enabled: false,
	})

	got, _, _, err := c.CompileForNode(ctx, "n_a")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("expected 0 rules for a disabled instance, got %+v", got)
	}
}

func TestCompileForNodeStableOrder(t *testing.T) {
	c, _ := newTestCompiler(t)
	ctx := context.Background()
	mustCreateNode(t, c, "n_a")
	gid := mustCreateChain(t, c)

	// Insert with priorities out of order; expect ascending order in output.
	for _, prio := range []int{20, 10, 30} {
		mustCreateInstance(t, c, model.NodePolicyInstance{
			NodeID: "n_a", Name: "r", GroupID: gid, Action: "ACCEPT",
			Priority: prio, Enabled: true,
		})
	}

	got, _, _, err := c.CompileForNode(ctx, "n_a")
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
	gid := mustCreateChain(t, c)

	// 标签选择属于 Policy 层(TargetNodes):创建带标签目标的 Policy 验证交集匹配。
	p, err := ps.Create(ctx, policy.PolicyInput{
		Name: "prod-edge-only", GroupID: gid, Action: "ACCEPT",
		Targets: policy.TargetsSpec{Labels: []string{"prod", "edge"}},
		Enabled: true,
	}, "t")
	if err != nil {
		t.Fatal(err)
	}

	ids, err := c.TargetNodes(ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 || ids[0] != "n_prod_edge" {
		t.Fatalf("want only n_prod_edge, got %v", ids)
	}
}

func TestCompileActionsMapCorrectly(t *testing.T) {
	c, _ := newTestCompiler(t)
	ctx := context.Background()
	mustCreateNode(t, c, "n_a")
	gid := mustCreateChain(t, c)

	cases := []struct {
		action string
		want   myfwv1.Action
		natTo  string
	}{
		{"ACCEPT", myfwv1.Action_ACTION_ACCEPT, ""},
		{"DROP", myfwv1.Action_ACTION_DROP, ""},
		{"REJECT", myfwv1.Action_ACTION_REJECT, ""},
		{"DNAT", myfwv1.Action_ACTION_DNAT, "10.0.0.5:8080"},
		{"SNAT", myfwv1.Action_ACTION_SNAT, "203.0.113.1"},
	}
	prio := 0
	for _, tc := range cases {
		mustCreateInstance(t, c, model.NodePolicyInstance{
			NodeID: "n_a", Name: tc.action + "-test", GroupID: gid,
			Action: tc.action, NatTo: tc.natTo, Priority: prio, Enabled: true,
		})
		prio++
	}

	got, _, _, err := c.CompileForNode(ctx, "n_a")
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
}
