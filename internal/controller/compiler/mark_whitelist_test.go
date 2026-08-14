package compiler

import (
	"context"
	"testing"

	myfwv1 "iptables-tool/api/myfw/v1"
	"iptables-tool/internal/controller/simulator"
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
	// 1. 打标:落 MARKMANGLE,保留 source_group(只给白名单源打标,多实例不覆盖),动作 MARK
	markRule := rules[0]
	if markRule.Chain != "MARKMANGLE" || markRule.SourceGroup != "whitelist" || markRule.Action != myfwv1.Action_ACTION_MARK {
		t.Fatalf("打标规则错误: chain=%s source_group=%q action=%v", markRule.Chain, markRule.SourceGroup, markRule.Action)
	}
	// 2. 白名单 ACCEPT:落 MARKACL-FWD,带 source_group,match_mark=15
	acceptRule := rules[1]
	if acceptRule.Chain != "MARKACL-FWD" || acceptRule.SourceGroup != "whitelist" ||
		acceptRule.MatchMark != 15 || acceptRule.Action != myfwv1.Action_ACTION_ACCEPT {
		t.Fatalf("放行规则错误: %+v", acceptRule)
	}
	// 3. 兜底 DROP:落 MARKACL-FWD,带端口、不带 mark,优先级 = 打标+offset(确保在所有 ACCEPT 之后)
	dropRule := rules[2]
	if dropRule.Chain != "MARKACL-FWD" || dropRule.MatchMark != 0 || dropRule.PortRange != "8080" || dropRule.Action != myfwv1.Action_ACTION_DROP {
		t.Fatalf("兜底规则错误: %+v", dropRule)
	}
	if dropRule.Priority != markRule.Priority+markAclDropOffset {
		t.Fatalf("兜底 DROP 优先级应 = 打标+offset, got %d vs %d", dropRule.Priority, markRule.Priority)
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

// TestCompileMarkWhitelistWithGroupIDIgnoresGroupChain 验证 MARK 白名单实例即使带
// GroupID(历史数据/前端误选),也不消费组链:编译仍落内置链。
// 修复前(僵尸链):MARK 实例 GroupID=999 且组不存在 -> 预加载 groupByID 无 999 ->
// 循环体 `if !ok { continue }` 静默跳过,白名单拦截整条失效。
// 修复后:MARK 白名单实例不查组链,规则落内置链不受组影响。
func TestCompileMarkWhitelistWithGroupIDIgnoresGroupChain(t *testing.T) {
	c, _ := newTestCompiler(t)
	ctx := context.Background()
	mustCreateNode(t, c, "n_a")

	// MARK 白名单实例带 GroupID=999,但组 999 不存在(存量数据残留/前端误选)
	inst := model.NodePolicyInstance{
		NodeID: "n_a", Name: "docker-acl", Action: "MARK", Mark: 15,
		Direction: "FORWARD", Protocol: "TCP", SourceGroup: "whitelist", PortRange: "8080",
		GroupID: 999, Priority: 50, Enabled: true,
	}
	if err := c.DB.Create(&inst).Error; err != nil {
		t.Fatal(err)
	}

	rules, _, chains, err := c.CompileForNode(ctx, "n_a")
	if err != nil {
		t.Fatal(err)
	}
	// 仍产出 3 条 MARK 白名单规则,不被"组不存在"跳过
	if len(rules) != 3 {
		t.Fatalf("want 3 rules, got %d: %+v", len(rules), rules)
	}
	if rules[0].Chain != "MARKMANGLE" {
		t.Fatalf("打标应落 MARKMANGLE(忽略组), got %s", rules[0].Chain)
	}
	if rules[1].Chain != "MARKACL-FWD" || rules[2].Chain != "MARKACL-FWD" {
		t.Fatalf("过滤应落 MARKACL-FWD(忽略组), got %s/%s", rules[1].Chain, rules[2].Chain)
	}
	// 内置链仍下发
	chainNames := map[string]bool{}
	for _, cc := range chains {
		chainNames[cc.Name] = true
	}
	if !chainNames["MARKMANGLE"] || !chainNames["MARKACL-FWD"] {
		t.Fatalf("期望下发 MARKMANGLE/MARKACL-FWD, got %v", chainNames)
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

// TestCompileMarkWhitelistWithAddressGroup 复现 248 节点"允许ssh"实例场景:
// 源白名单用地址组(组名 192.168.80.248,成员为范围展开的每个 IP)而非单 CIDR。
// 验证:编译仍产出 3 条规则(打标落 MARKMANGLE、放行/兜底落 MARKACL-IN),
// 地址组正确进入 AddressSet 期望态,仿真组内 IP(248/249/250)访问 :22 放行、
// 组外 IP 兜底 DROP。确认规则逻辑无 bug(节点绑定错位不属此处)。
func TestCompileMarkWhitelistWithAddressGroup(t *testing.T) {
	c, _ := newTestCompiler(t)
	ctx := context.Background()
	mustCreateNode(t, c, "n_x")

	// 地址组:名字即 192.168.80.248,成员为 IP 范围展开后的每个 /32。
	if err := c.DB.Create(&model.AddressGroup{
		Name:    "192.168.80.248",
		Kind:    "blacklist",
		Members: `["192.168.80.248/32","192.168.80.249/32","192.168.80.250/32"]`,
	}).Error; err != nil {
		t.Fatal(err)
	}

	inst := model.NodePolicyInstance{
		NodeID: "n_x", Name: "允许ssh", Action: "MARK", Mark: 15,
		Direction: "INPUT", Protocol: "TCP", SourceGroup: "192.168.80.248", PortRange: "22",
		Priority: 10, Enabled: true,
	}
	if err := c.DB.Create(&inst).Error; err != nil {
		t.Fatal(err)
	}

	rules, sets, chains, err := c.CompileForNode(ctx, "n_x")
	if err != nil {
		t.Fatal(err)
	}
	// 3 条规则:打标 + 白名单放行 + 兜底 DROP
	if len(rules) != 3 {
		t.Fatalf("want 3 rules, got %d: %+v", len(rules), rules)
	}
	// 打标规则:保留源组(只给白名单源打标,多实例不覆盖),落 MARKMANGLE
	if rules[0].Chain != "MARKMANGLE" || rules[0].SourceGroup != "192.168.80.248" {
		t.Fatalf("打标规则应带源组且落 MARKMANGLE, got chain=%s source=%q source_group=%q", rules[0].Chain, rules[0].Source, rules[0].SourceGroup)
	}
	// 放行规则:带地址组 + match_mark
	if rules[1].Chain != "MARKACL-IN" || rules[1].SourceGroup != "192.168.80.248" || rules[1].MatchMark != 15 {
		t.Fatalf("放行规则错误: %+v", rules[1])
	}
	// 地址组进入 AddressSet 期望态
	if len(sets) != 1 || sets[0].Name != "192.168.80.248" || len(sets[0].Members) != 3 {
		t.Fatalf("地址组期望态错误: %+v", sets)
	}
	// 内置链下发
	chainNames := map[string]bool{}
	for _, cc := range chains {
		chainNames[cc.Name] = true
	}
	if !chainNames["MARKMANGLE"] || !chainNames["MARKACL-IN"] {
		t.Fatalf("期望下发 MARKMANGLE/MARKACL-IN, got %v", chainNames)
	}

	// 仿真:组内 IP -> ACCEPT,组外 IP -> DROP。
	flowIn := simulator.Flow{Direction: "INPUT", SourceIP: "192.168.80.249", DestIP: "192.168.80.248", Protocol: "tcp", DstPort: 22}
	rIn, err := simulator.Evaluate(flowIn, rules, chains, sets)
	if err != nil {
		t.Fatal(err)
	}
	if rIn.Verdict != simulator.VerdictAccept {
		t.Fatalf("组内 IP 访问 :22 应 ACCEPT, got %q steps=%+v", rIn.Verdict, rIn.Steps)
	}
	flowOut := simulator.Flow{Direction: "INPUT", SourceIP: "192.168.80.5", DestIP: "192.168.80.248", Protocol: "tcp", DstPort: 22}
	rOut, err := simulator.Evaluate(flowOut, rules, chains, sets)
	if err != nil {
		t.Fatal(err)
	}
	if rOut.Verdict != simulator.VerdictDrop {
		t.Fatalf("组外 IP 访问 :22 应 DROP, got %q steps=%+v", rOut.Verdict, rOut.Steps)
	}
}

// TestCompileMarkWhitelist_MultiSamePortConflict 复现多 MARK 白名单实例同端口冲突:
// 打标规则不携带 match_mark 条件(无条件按 dport 打标),后匹配实例会把先打的标覆盖,
// 导致先配置的白名单失效。实例 A(源组 g_a,mark 15,priority 10)与实例 B(源组 g_b,
// mark 255,priority 20)同保护 :22。源在 g_a 访问 :22:
//   mangle: A 打标 15 -> B 无条件打标 255(覆盖)
//   filter: A ACCEPT(mark15) 不命中 -> B DROP(mark255) 命中 => 期望 ACCEPT,实际 DROP。
func TestCompileMarkWhitelist_MultiSamePortConflict(t *testing.T) {
	c, _ := newTestCompiler(t)
	ctx := context.Background()
	mustCreateNode(t, c, "n_x")

	// 两个地址组作为不同白名单源
	if err := c.DB.Create(&model.AddressGroup{Name: "g_a", Kind: "blacklist", Members: `["192.168.80.100/32"]`}).Error; err != nil {
		t.Fatal(err)
	}
	if err := c.DB.Create(&model.AddressGroup{Name: "g_b", Kind: "blacklist", Members: `["192.168.80.200/32"]`}).Error; err != nil {
		t.Fatal(err)
	}
	// 两条同端口 :22 的 MARK 白名单实例,mark 不同,priority 不同
	instA := model.NodePolicyInstance{
		NodeID: "n_x", Name: "acl-a", Action: "MARK", Mark: 15,
		Direction: "INPUT", Protocol: "TCP", SourceGroup: "g_a", PortRange: "22",
		Priority: 10, Enabled: true,
	}
	instB := model.NodePolicyInstance{
		NodeID: "n_x", Name: "acl-b", Action: "MARK", Mark: 255,
		Direction: "INPUT", Protocol: "TCP", SourceGroup: "g_b", PortRange: "22",
		Priority: 20, Enabled: true,
	}
	if err := c.DB.Create(&instA).Error; err != nil {
		t.Fatal(err)
	}
	if err := c.DB.Create(&instB).Error; err != nil {
		t.Fatal(err)
	}

	rules, sets, chains, err := c.CompileForNode(ctx, "n_x")
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 6 {
		t.Fatalf("want 6 rules(2 实例 × 3), got %d: %+v", len(rules), rules)
	}
	// 打标规则确认不带 match_mark(无条件打标 -> 覆盖冲突)
	for _, r := range rules {
		if r.Chain == "MARKMANGLE" && r.MatchMark != 0 {
			t.Fatalf("打标规则不应带 match_mark 条件(冲突根因), got %+v", r)
		}
	}

	// 三态验证(同端口 :22 两条不同 mark 白名单):
	//   源在 g_a -> 被 A 白名单放行;源在 g_b -> 被 B 白名单放行;其他源 -> 兜底 DROP。
	cases := []struct {
		name string
		src  string
		want simulator.Verdict
	}{
		{"g_a成员_实例A放行", "192.168.80.100", simulator.VerdictAccept},
		{"g_b成员_实例B放行", "192.168.80.200", simulator.VerdictAccept},
		{"其他源_兜底拦截", "192.168.80.50", simulator.VerdictDrop},
	}
	for _, tc := range cases {
		flow := simulator.Flow{Direction: "INPUT", SourceIP: tc.src, DestIP: "10.0.0.1", Protocol: "tcp", DstPort: 22}
		got, err := simulator.Evaluate(flow, rules, chains, sets)
		if err != nil {
			t.Fatal(err)
		}
		if got.Verdict != tc.want {
			t.Fatalf("%s: 访问 :22 应 %s, got %q steps=%+v", tc.name, tc.want, got.Verdict, got.Steps)
		}
	}
}
