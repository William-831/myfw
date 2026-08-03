package compiler

import (
	"context"
	"testing"

	myfwv1 "iptables-tool/api/myfw/v1"
	"iptables-tool/internal/model"
)

// TestCompileMarkWhitelist 验证 MARK 白名单实例(容器转发 FORWARD)编译为 3 条规则:
// 打标落 MARKMANGLE(mangle),白名单放行+兜底 DROP 落 MARKACL-FWD(filter FORWARD)。
// 打标规则清空 source_group(只按端口),白名单用 source_group 控制放行。group_id=0。
func TestCompileMarkWhitelist(t *testing.T) {
	c, _ := newTestCompiler(t)
	ctx := context.Background()
	mustCreateNode(t, c, "n_a")

	inst := model.NodePolicyInstance{
		NodeID: "n_a", Name: "docker-acl", Action: "MARK", Mark: 15,
		Direction: "FORWARD", Protocol: "TCP", SourceGroup: "whitelist", PortRange: "8080",
		Priority: 50, Enabled: true,
	}
	if err := c.DB.Create(&inst).Error; err != nil {
		t.Fatal(err)
	}

	rules, _, chains, err := c.CompileForNode(ctx, "n_a")
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 3 {
		t.Fatalf("want 3 rules, got %d: %+v", len(rules), rules)
	}
	// 1. 打标:落 MARKMANGLE,清空 source_group(只按端口),动作 MARK
	markRule := rules[0]
	if markRule.Chain != "MARKMANGLE" || markRule.SourceGroup != "" || markRule.Action != myfwv1.Action_ACTION_MARK {
		t.Fatalf("打标规则错误: chain=%s source_group=%q action=%v", markRule.Chain, markRule.SourceGroup, markRule.Action)
	}
	// 2. 白名单 ACCEPT:落 MARKACL-FWD,带 source_group,match_mark=15
	acceptRule := rules[1]
	if acceptRule.Chain != "MARKACL-FWD" || acceptRule.SourceGroup != "whitelist" ||
		acceptRule.MatchMark != 15 || acceptRule.Action != myfwv1.Action_ACTION_ACCEPT {
		t.Fatalf("放行规则错误: %+v", acceptRule)
	}
	// 3. 兜底 DROP:落 MARKACL-FWD,优先级 = 打标+1
	dropRule := rules[2]
	if dropRule.Chain != "MARKACL-FWD" || dropRule.MatchMark != 15 || dropRule.Action != myfwv1.Action_ACTION_DROP {
		t.Fatalf("兜底规则错误: %+v", dropRule)
	}
	if dropRule.Priority != markRule.Priority+1 {
		t.Fatalf("兜底 DROP 优先级应 = 打标+1, got %d vs %d", dropRule.Priority, markRule.Priority)
	}
	// 内置链:下发 MARKMANGLE + MARKACL-FWD,不下发 MARKACL-IN
	chainNames := map[string]bool{}
	for _, cc := range chains {
		chainNames[cc.Name] = true
	}
	if !chainNames["MARKMANGLE"] || !chainNames["MARKACL-FWD"] {
		t.Fatalf("期望下发 MARKMANGLE/MARKACL-FWD, got %v", chainNames)
	}
	if chainNames["MARKACL-IN"] {
		t.Fatal("FORWARD 方向不应下发 MARKACL-IN")
	}
}

// TestCompileMarkWhitelistInput 验证主机入站(INPUT)方向:打标仍落 MARKMANGLE,
// 过滤链落 MARKACL-IN(挂 MYFW-INPUT)。
func TestCompileMarkWhitelistInput(t *testing.T) {
	c, _ := newTestCompiler(t)
	ctx := context.Background()
	mustCreateNode(t, c, "n_a")

	inst := model.NodePolicyInstance{
		NodeID: "n_a", Name: "host-acl", Action: "MARK", Mark: 255,
		Direction: "INPUT", Protocol: "TCP", SourceGroup: "whitelist", PortRange: "22",
		Priority: 50, Enabled: true,
	}
	if err := c.DB.Create(&inst).Error; err != nil {
		t.Fatal(err)
	}

	rules, _, chains, err := c.CompileForNode(ctx, "n_a")
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 3 {
		t.Fatalf("want 3 rules, got %d", len(rules))
	}
	// 打标仍在 mangle MARKMANGLE
	if rules[0].Chain != "MARKMANGLE" {
		t.Fatalf("打标应落 MARKMANGLE, got %s", rules[0].Chain)
	}
	// 过滤落 MARKACL-IN(INPUT 方向)
	if rules[1].Chain != "MARKACL-IN" || rules[2].Chain != "MARKACL-IN" {
		t.Fatalf("INPUT 方向过滤应落 MARKACL-IN, got %s/%s", rules[1].Chain, rules[2].Chain)
	}
	chainNames := map[string]bool{}
	for _, cc := range chains {
		chainNames[cc.Name] = true
	}
	if !chainNames["MARKMANGLE"] || !chainNames["MARKACL-IN"] {
		t.Fatalf("期望下发 MARKMANGLE/MARKACL-IN, got %v", chainNames)
	}
	if chainNames["MARKACL-FWD"] {
		t.Fatal("INPUT 方向不应下发 MARKACL-FWD")
	}
}
