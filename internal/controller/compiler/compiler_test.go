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

// mustCreateChainNamed 建指定名字/表的测试策略组(P1b 多挂载/落点链/表校验测试用)。
// mounts 空时按表回退单挂载:filter→MYFW-FORWARD, nat→MYFW-PREROUTING。
func mustCreateChainNamed(t *testing.T, c *Compiler, name, table string, mounts []model.ChainMount) uint {
	t.Helper()
	ch := model.CustomChain{Name: name, Table: table, Priority: 1, Enabled: true}
	if len(mounts) > 0 {
		b, _ := json.Marshal(mounts)
		ch.Mounts = string(b)
		ch.Parent, ch.Priority = mounts[0].Parent, mounts[0].Priority // 镜像同步
	} else if table == "nat" {
		ch.Parent = "MYFW-PREROUTING"
	} else {
		ch.Parent = "MYFW-FORWARD"
	}
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
	gidFilter := mustCreateChain(t, c)                                 // filter 表组链
	gidNat := mustCreateChainNamed(t, c, "nat-fwd", "nat", nil)        // nat 表组链(PREROUTING)

	cases := []struct {
		action string
		want   myfwv1.Action
		natTo  string
		gid    uint // DNAT/SNAT 须落 nat 表链(表一致性 P3)
	}{
		{"ACCEPT", myfwv1.Action_ACTION_ACCEPT, "", gidFilter},
		{"DROP", myfwv1.Action_ACTION_DROP, "", gidFilter},
		{"REJECT", myfwv1.Action_ACTION_REJECT, "", gidFilter},
		{"DNAT", myfwv1.Action_ACTION_DNAT, "10.0.0.5:8080", gidNat},
		{"SNAT", myfwv1.Action_ACTION_SNAT, "203.0.113.1", gidNat},
	}
	prio := 0
	for _, tc := range cases {
		mustCreateInstance(t, c, model.NodePolicyInstance{
			NodeID: "n_a", Name: tc.action + "-test", GroupID: tc.gid,
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

// TestCompileRejectsDNATOnFilterChain 验证编译期动作-链表一致性(P3):
// DNAT 实例落 filter 表链应在编译期报错(而非 Agent 执行 iptables -j DNAT 才失败)。
func TestCompileRejectsDNATOnFilterChain(t *testing.T) {
	c, _ := newTestCompiler(t)
	ctx := context.Background()
	mustCreateNode(t, c, "n_a")
	gidFilter := mustCreateChain(t, c) // filter 表组链

	mustCreateInstance(t, c, model.NodePolicyInstance{
		NodeID: "n_a", Name: "nat-wrong", GroupID: gidFilter,
		Action: "DNAT", NatTo: "10.0.0.5:8080", Priority: 10, Enabled: true,
	})

	if _, _, _, err := c.CompileForNode(ctx, "n_a"); err == nil {
		t.Fatal("DNAT 落 filter 链应编译期报错, got nil")
	}
}

// TestCompileCustomChainsMultiMount 验证多挂载展开(P1b 多钩子):
// 链带多挂载时, CompileForNode 的 customChains 输出同名多条(不同 parent),
// driver 据此创建多 jump, 实现"同一链同时挂多个父链"。
func TestCompileCustomChainsMultiMount(t *testing.T) {
	c, _ := newTestCompiler(t)
	ctx := context.Background()
	mustCreateNode(t, c, "n_a")
	groupID := mustCreateChain(t, c) // 单挂载组链 acl-fwd
	// dmz 链双挂载:FORWARD(优先级 10)+ INPUT(优先级 20)
	mustCreateChainNamed(t, c, "dmz", "filter", []model.ChainMount{
		{Parent: "MYFW-FORWARD", Priority: 10},
		{Parent: "MYFW-INPUT", Priority: 20},
	})
	_ = groupID
	mustCreateInstance(t, c, model.NodePolicyInstance{
		NodeID: "n_a", Name: "dmz-rule", GroupID: groupID,
		Protocol: "TCP", PortRange: "443", Action: "ACCEPT", Priority: 10, Enabled: true,
	})

	_, _, chains, err := c.CompileForNode(ctx, "n_a")
	if err != nil {
		t.Fatal(err)
	}
	// 收集 dmz 链的挂载:应展开为同名 2 条(FORWARD + INPUT)
	fwd, in := false, false
	for _, cc := range chains {
		if cc.Name != "dmz" {
			continue
		}
		switch cc.Parent {
		case "MYFW-FORWARD":
			fwd = true
		case "MYFW-INPUT":
			in = true
		}
	}
	if !fwd || !in {
		t.Fatalf("dmz 链应展开为 FORWARD+INPUT 双挂载, got fwd=%v in=%v (chains=%+v)", fwd, in, chains)
	}
	// 单挂载组链 acl-fwd 仍只展开 1 条
	if n := countChainDef(chains, "acl-fwd"); n != 1 {
		t.Fatalf("acl-fwd 单挂载应展开 1 条, got %d", n)
	}
}

// countChainDef 统计 customChains 中指定链名的条目数。
func countChainDef(chains []*myfwv1.CustomChainDef, name string) int {
	n := 0
	for _, cc := range chains {
		if cc.Name == name {
			n++
		}
	}
	return n
}
