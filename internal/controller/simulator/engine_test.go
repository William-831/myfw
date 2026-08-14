package simulator

import (
	"strings"
	"testing"

	myfwv1 "iptables-tool/api/myfw/v1"
)

// 测试基建:构造规则/链/地址组的简写函数,让用例聚焦行为而非样板。

func rule(id, chain string, action myfwv1.Action, muts ...func(*myfwv1.CompiledRule)) *myfwv1.CompiledRule {
	r := &myfwv1.CompiledRule{
		Id: id, Chain: chain, Action: action,
		Protocol: myfwv1.Protocol_PROTOCOL_TCP,
	}
	for _, m := range muts {
		m(r)
	}
	return r
}

func chain(name, parent, table string) *myfwv1.CustomChainDef {
	return &myfwv1.CustomChainDef{Name: name, Parent: parent, Table: table}
}

func set(name string, members ...string) *myfwv1.AddressSet {
	return &myfwv1.AddressSet{Name: name, Kind: "custom", Members: members}
}

func tcpFlow(dir, src, dst string, sport, dport int) Flow {
	return Flow{Direction: dir, SourceIP: src, DestIP: dst, Protocol: "tcp", SrcPort: sport, DstPort: dport}
}

// 断言最终判定。
func assertVerdict(t *testing.T, got *Result, want Verdict) {
	t.Helper()
	if got.Verdict != want {
		t.Fatalf("verdict: got %q, want %q, steps=%+v note=%q", got.Verdict, want, got.Steps, got.Note)
	}
}

// 断言存在某条命中规则(且其判定动作正确)。
func assertMatchedRule(t *testing.T, got *Result, ruleID string) {
	t.Helper()
	for _, s := range got.Steps {
		if s.RuleID == ruleID && s.Matched {
			return
		}
	}
	t.Fatalf("期望命中规则 %q,但未命中,steps=%+v verdict=%q", ruleID, got.Steps, got.Verdict)
}

// TestEvaluate_ACCEPT_MatchRule: 端口匹配的 ACCEPT 规则命中即放行。
func TestEvaluate_ACCEPT_MatchRule(t *testing.T) {
	rules := []*myfwv1.CompiledRule{
		rule("i-http", "business-input", myfwv1.Action_ACTION_ACCEPT, func(r *myfwv1.CompiledRule) {
			r.PortRange = "8080"
		}),
	}
	chains := []*myfwv1.CustomChainDef{chain("business-input", "MYFW-INPUT", "filter")}

	got, err := Evaluate(tcpFlow("INPUT", "1.2.3.4", "10.0.0.1", 12345, 8080), rules, chains, nil)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	assertVerdict(t, got, VerdictAccept)
	assertMatchedRule(t, got, "i-http")
}

// TestEvaluate_Pass_NoMatch: 无规则命中 -> PASS(系统默认策略放行)。
func TestEvaluate_Pass_NoMatch(t *testing.T) {
	rules := []*myfwv1.CompiledRule{
		rule("i-http", "business-input", myfwv1.Action_ACTION_ACCEPT, func(r *myfwv1.CompiledRule) {
			r.PortRange = "8080"
		}),
	}
	chains := []*myfwv1.CustomChainDef{chain("business-input", "MYFW-INPUT", "filter")}

	got, err := Evaluate(tcpFlow("INPUT", "1.2.3.4", "10.0.0.1", 12345, 22), rules, chains, nil)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	assertVerdict(t, got, VerdictPass)
}

// TestEvaluate_Drop: DROP 规则命中即丢弃。
func TestEvaluate_Drop(t *testing.T) {
	rules := []*myfwv1.CompiledRule{
		rule("i-drop", "acl-fwd", myfwv1.Action_ACTION_DROP, func(r *myfwv1.CompiledRule) {
			r.PortRange = "443"
		}),
	}
	chains := []*myfwv1.CustomChainDef{chain("acl-fwd", "MYFW-FORWARD", "filter")}

	got, err := Evaluate(tcpFlow("FORWARD", "10.0.0.2", "172.16.0.1", 40000, 443), rules, chains, nil)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	assertVerdict(t, got, VerdictDrop)
	assertMatchedRule(t, got, "i-drop")
}

// TestEvaluate_Reject: REJECT 规则命中即拒绝。
func TestEvaluate_Reject(t *testing.T) {
	rules := []*myfwv1.CompiledRule{
		rule("i-rej", "business-input", myfwv1.Action_ACTION_REJECT, func(r *myfwv1.CompiledRule) {
			r.PortRange = "3389"
		}),
	}
	chains := []*myfwv1.CustomChainDef{chain("business-input", "MYFW-INPUT", "filter")}

	got, err := Evaluate(tcpFlow("INPUT", "1.2.3.4", "10.0.0.1", 50000, 3389), rules, chains, nil)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	assertVerdict(t, got, VerdictReject)
}

// TestEvaluate_PriorityOrder: 同链内 priority 小的先评估,DROP(10) 先于 ACCEPT(20) 生效。
func TestEvaluate_PriorityOrder(t *testing.T) {
	rules := []*myfwv1.CompiledRule{
		rule("i-accept", "business-input", myfwv1.Action_ACTION_ACCEPT, func(r *myfwv1.CompiledRule) {
			r.Priority = 20
		}),
		rule("i-drop", "business-input", myfwv1.Action_ACTION_DROP, func(r *myfwv1.CompiledRule) {
			r.Priority = 10
		}),
	}
	chains := []*myfwv1.CustomChainDef{chain("business-input", "MYFW-INPUT", "filter")}

	got, err := Evaluate(tcpFlow("INPUT", "1.2.3.4", "10.0.0.1", 11111, 80), rules, chains, nil)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	assertVerdict(t, got, VerdictDrop)
	assertMatchedRule(t, got, "i-drop")
}

// TestEvaluate_SourceCIDR: 源 CIDR 匹配/不匹配。
func TestEvaluate_SourceCIDR(t *testing.T) {
	rules := []*myfwv1.CompiledRule{
		rule("i-intranet", "business-input", myfwv1.Action_ACTION_ACCEPT, func(r *myfwv1.CompiledRule) {
			r.Source = "192.168.1.0/24"
			r.PortRange = "22"
		}),
	}
	chains := []*myfwv1.CustomChainDef{chain("business-input", "MYFW-INPUT", "filter")}

	// 网段内命中
	got, err := Evaluate(tcpFlow("INPUT", "192.168.1.5", "10.0.0.1", 30000, 22), rules, chains, nil)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	assertVerdict(t, got, VerdictAccept)

	// 网段外不命中 -> PASS
	got, err = Evaluate(tcpFlow("INPUT", "10.0.0.5", "10.0.0.1", 30000, 22), rules, chains, nil)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	assertVerdict(t, got, VerdictPass)
}

// TestEvaluate_SourceGroup: 地址组成员匹配/不匹配(ipset 无状态语义)。
func TestEvaluate_SourceGroup(t *testing.T) {
	sets := []*myfwv1.AddressSet{set("internal", "10.0.0.0/8", "192.168.0.0/16")}
	rules := []*myfwv1.CompiledRule{
		rule("i-internal", "business-input", myfwv1.Action_ACTION_ACCEPT, func(r *myfwv1.CompiledRule) {
			r.SourceGroup = "internal"
			r.PortRange = "8080"
		}),
	}
	chains := []*myfwv1.CustomChainDef{chain("business-input", "MYFW-INPUT", "filter")}

	got, err := Evaluate(tcpFlow("INPUT", "10.1.2.3", "10.0.0.1", 40000, 8080), rules, chains, sets)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	assertVerdict(t, got, VerdictAccept)

	// 组成员外 -> PASS
	got, err = Evaluate(tcpFlow("INPUT", "8.8.8.8", "10.0.0.1", 40000, 8080), rules, chains, sets)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	assertVerdict(t, got, VerdictPass)
}

// TestEvaluate_DestinationGroup: 目的地址组匹配。
func TestEvaluate_DestinationGroup(t *testing.T) {
	sets := []*myfwv1.AddressSet{set("web-servers", "172.16.0.0/16")}
	rules := []*myfwv1.CompiledRule{
		rule("i-web", "business-input", myfwv1.Action_ACTION_ACCEPT, func(r *myfwv1.CompiledRule) {
			r.DestinationGroup = "web-servers"
			r.PortRange = "443"
		}),
	}
	chains := []*myfwv1.CustomChainDef{chain("business-input", "MYFW-INPUT", "filter")}

	got, err := Evaluate(tcpFlow("INPUT", "1.2.3.4", "172.16.9.9", 50000, 443), rules, chains, sets)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	assertVerdict(t, got, VerdictAccept)
}

// TestEvaluate_MarkFlow: MARK 规则打标后,后续 match_mark 规则匹配该标记。
func TestEvaluate_MarkFlow(t *testing.T) {
	rules := []*myfwv1.CompiledRule{
		rule("i-mark", "mark-in", myfwv1.Action_ACTION_MARK, func(r *myfwv1.CompiledRule) {
			r.PortRange = "22"
			r.Mark = 15
		}),
		rule("i-marked-accept", "mark-in", myfwv1.Action_ACTION_ACCEPT, func(r *myfwv1.CompiledRule) {
			r.MatchMark = 15
		}),
	}
	chains := []*myfwv1.CustomChainDef{chain("mark-in", "MYFW-INPUT", "filter")}

	// 22 端口:先打标 15,再被 match_mark=15 放行
	got, err := Evaluate(tcpFlow("INPUT", "1.2.3.4", "10.0.0.1", 30000, 22), rules, chains, nil)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	assertVerdict(t, got, VerdictAccept)
	assertMatchedRule(t, got, "i-mark")

	// 8080 端口:不打标,不被放行 -> PASS
	got, err = Evaluate(tcpFlow("INPUT", "1.2.3.4", "10.0.0.1", 30000, 8080), rules, chains, nil)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	assertVerdict(t, got, VerdictPass)
}

// TestEvaluate_PortRange: 端口区间匹配。
func TestEvaluate_PortRange(t *testing.T) {
	rules := []*myfwv1.CompiledRule{
		rule("i-range", "business-input", myfwv1.Action_ACTION_ACCEPT, func(r *myfwv1.CompiledRule) {
			r.PortRange = "1000-2000"
		}),
	}
	chains := []*myfwv1.CustomChainDef{chain("business-input", "MYFW-INPUT", "filter")}

	got, err := Evaluate(tcpFlow("INPUT", "1.2.3.4", "10.0.0.1", 10000, 1500), rules, chains, nil)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	assertVerdict(t, got, VerdictAccept)

	got, err = Evaluate(tcpFlow("INPUT", "1.2.3.4", "10.0.0.1", 10000, 3000), rules, chains, nil)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	assertVerdict(t, got, VerdictPass)
}

// TestEvaluate_ProtocolMismatch: 协议不匹配不命中。
func TestEvaluate_ProtocolMismatch(t *testing.T) {
	rules := []*myfwv1.CompiledRule{
		rule("i-udp", "business-input", myfwv1.Action_ACTION_ACCEPT, func(r *myfwv1.CompiledRule) {
			r.Protocol = myfwv1.Protocol_PROTOCOL_UDP
			r.PortRange = "53"
		}),
	}
	chains := []*myfwv1.CustomChainDef{chain("business-input", "MYFW-INPUT", "filter")}

	// tcp 流量对 udp 规则不命中
	got, err := Evaluate(tcpFlow("INPUT", "1.2.3.4", "10.0.0.1", 20000, 53), rules, chains, nil)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	assertVerdict(t, got, VerdictPass)
}

// TestEvaluate_ChainOrder: 链定义顺序决定遍历顺序,前链 ACCEPT 优先于后链 DROP。
func TestEvaluate_ChainOrder(t *testing.T) {
	rules := []*myfwv1.CompiledRule{
		rule("i-accept", "allow-first", myfwv1.Action_ACTION_ACCEPT),
		rule("i-drop", "deny-second", myfwv1.Action_ACTION_DROP),
	}
	chains := []*myfwv1.CustomChainDef{
		chain("allow-first", "MYFW-INPUT", "filter"),
		chain("deny-second", "MYFW-INPUT", "filter"),
	}

	got, err := Evaluate(tcpFlow("INPUT", "1.2.3.4", "10.0.0.1", 10000, 80), rules, chains, nil)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	assertVerdict(t, got, VerdictAccept)
}

// TestEvaluate_InvalidDirection: 未知方向报错。
func TestEvaluate_InvalidDirection(t *testing.T) {
	rules := []*myfwv1.CompiledRule{
		rule("i-http", "business-input", myfwv1.Action_ACTION_ACCEPT, func(r *myfwv1.CompiledRule) {
			r.PortRange = "8080"
		}),
	}
	chains := []*myfwv1.CustomChainDef{chain("business-input", "MYFW-INPUT", "filter")}

	if _, err := Evaluate(tcpFlow("PREROUTING", "1.2.3.4", "10.0.0.1", 10000, 8080), rules, chains, nil); err == nil {
		t.Fatal("PREROUTING 方向应报错(首版仅支持 filter 表 INPUT/FORWARD/OUTPUT)")
	}
}

// TestEvaluate_MarkWhitelist_Accepted: MARK 白名单主场景——mangle 打标预遍(INPUT)
// 给 :22 打标,filter MARKACL 白名单源命中放行。
func TestEvaluate_MarkWhitelist_Accepted(t *testing.T) {
	rules := []*myfwv1.CompiledRule{
		// 1. mangle 打标:任何源到 :22 打标 15
		rule("i5", "MARKMANGLE", myfwv1.Action_ACTION_MARK, func(r *myfwv1.CompiledRule) {
			r.PortRange = "22"
			r.Mark = 15
		}),
		// 2. filter 白名单:源在 192.168.1.0/24 且带标 15 -> ACCEPT
		rule("i5-acl", "MARKACL-IN", myfwv1.Action_ACTION_ACCEPT, func(r *myfwv1.CompiledRule) {
			r.Source = "192.168.1.0/24"
			r.MatchMark = 15
		}),
		// 3. filter 兜底:带标 15 -> DROP
		rule("i5-drop", "MARKACL-IN", myfwv1.Action_ACTION_DROP, func(r *myfwv1.CompiledRule) {
			r.MatchMark = 15
			r.Priority = 1
		}),
	}
	chains := []*myfwv1.CustomChainDef{
		chain("MARKMANGLE", "MYFW-MANGLE", "mangle"),
		chain("MARKACL-IN", "MYFW-INPUT", "filter"),
	}

	// 白名单源 -> ACCEPT
	got, err := Evaluate(tcpFlow("INPUT", "192.168.1.5", "10.0.0.1", 30000, 22), rules, chains, nil)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	assertVerdict(t, got, VerdictAccept)
	assertMatchedRule(t, got, "i5-acl")
}

// TestEvaluate_MarkWhitelist_Dropped: 非白名单源到 :22 被兜底 DROP。
func TestEvaluate_MarkWhitelist_Dropped(t *testing.T) {
	rules := []*myfwv1.CompiledRule{
		rule("i5", "MARKMANGLE", myfwv1.Action_ACTION_MARK, func(r *myfwv1.CompiledRule) {
			r.PortRange = "22"
			r.Mark = 15
		}),
		rule("i5-acl", "MARKACL-IN", myfwv1.Action_ACTION_ACCEPT, func(r *myfwv1.CompiledRule) {
			r.Source = "192.168.1.0/24"
			r.MatchMark = 15
		}),
		rule("i5-drop", "MARKACL-IN", myfwv1.Action_ACTION_DROP, func(r *myfwv1.CompiledRule) {
			r.MatchMark = 15
			r.Priority = 1
		}),
	}
	chains := []*myfwv1.CustomChainDef{
		chain("MARKMANGLE", "MYFW-MANGLE", "mangle"),
		chain("MARKACL-IN", "MYFW-INPUT", "filter"),
	}

	got, err := Evaluate(tcpFlow("INPUT", "8.8.8.8", "10.0.0.1", 30000, 22), rules, chains, nil)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	assertVerdict(t, got, VerdictDrop)
	assertMatchedRule(t, got, "i5-drop")
}

// TestEvaluate_MarkWhitelist_Fwd: FORWARD 方向 MARKACL-FWD 白名单同样生效(容器转发场景)。
func TestEvaluate_MarkWhitelist_Fwd(t *testing.T) {
	rules := []*myfwv1.CompiledRule{
		rule("i7", "MARKMANGLE", myfwv1.Action_ACTION_MARK, func(r *myfwv1.CompiledRule) {
			r.PortRange = "8080"
			r.Mark = 15
		}),
		rule("i7-acl", "MARKACL-FWD", myfwv1.Action_ACTION_ACCEPT, func(r *myfwv1.CompiledRule) {
			r.Source = "10.0.0.0/8"
			r.MatchMark = 15
		}),
		rule("i7-drop", "MARKACL-FWD", myfwv1.Action_ACTION_DROP, func(r *myfwv1.CompiledRule) {
			r.MatchMark = 15
			r.Priority = 1
		}),
	}
	chains := []*myfwv1.CustomChainDef{
		chain("MARKMANGLE", "MYFW-MANGLE", "mangle"),
		chain("MARKACL-FWD", "MYFW-FORWARD", "filter"),
	}

	got, err := Evaluate(tcpFlow("FORWARD", "10.1.2.3", "172.16.0.1", 40000, 8080), rules, chains, nil)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	assertVerdict(t, got, VerdictAccept)

	got, err = Evaluate(tcpFlow("FORWARD", "172.16.9.9", "172.16.0.1", 40000, 8080), rules, chains, nil)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	assertVerdict(t, got, VerdictDrop)
}

// TestEvaluate_MarkOnly_NoFilter: 仅 mangle 打标、无 filter 规则 -> 打标不产生终止,PASS。
func TestEvaluate_MarkOnly_NoFilter(t *testing.T) {
	rules := []*myfwv1.CompiledRule{
		rule("i-mangle", "MARKMANGLE", myfwv1.Action_ACTION_MARK, func(r *myfwv1.CompiledRule) {
			r.Mark = 15
			r.PortRange = "22"
		}),
	}
	chains := []*myfwv1.CustomChainDef{chain("MARKMANGLE", "MYFW-MANGLE", "mangle")}

	got, err := Evaluate(tcpFlow("INPUT", "1.2.3.4", "10.0.0.1", 10000, 22), rules, chains, nil)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	// mangle 打标规则已评估(记录命中步),无 filter 终止规则 -> PASS
	assertVerdict(t, got, VerdictPass)
	assertMatchedRule(t, got, "i-mangle")
}

// TestEvaluate_MangleDnat_Note: mangle 链上出现 DNAT 等非打标动作,提示并忽略,不终止。
func TestEvaluate_MangleDnat_Note(t *testing.T) {
	rules := []*myfwv1.CompiledRule{
		rule("i-mdnat", "MARKMANGLE", myfwv1.Action_ACTION_DNAT, func(r *myfwv1.CompiledRule) {
			r.NatTo = "10.0.0.9:8080"
			r.PortRange = "80"
		}),
	}
	chains := []*myfwv1.CustomChainDef{chain("MARKMANGLE", "MYFW-MANGLE", "mangle")}

	got, err := Evaluate(tcpFlow("INPUT", "1.2.3.4", "10.0.0.1", 10000, 80), rules, chains, nil)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	assertVerdict(t, got, VerdictPass)
}

// TestEvaluate_DnatNote: filter 表内出现 DNAT 不支持的规则,记录提示并继续。
func TestEvaluate_DnatNote(t *testing.T) {
	rules := []*myfwv1.CompiledRule{
		rule("i-dnat", "business-input", myfwv1.Action_ACTION_DNAT, func(r *myfwv1.CompiledRule) {
			r.NatTo = "10.0.0.9:8080"
		}),
	}
	chains := []*myfwv1.CustomChainDef{chain("business-input", "MYFW-INPUT", "filter")}

	got, err := Evaluate(tcpFlow("INPUT", "1.2.3.4", "10.0.0.1", 10000, 80), rules, chains, nil)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	assertVerdict(t, got, VerdictPass)
	if got.Note == "" {
		t.Fatal("DNAT 不支持应输出说明性 note")
	}
}

// TestEvaluate_ICMP: ICMP 协议匹配。
func TestEvaluate_ICMP(t *testing.T) {
	rules := []*myfwv1.CompiledRule{
		rule("i-icmp", "business-input", myfwv1.Action_ACTION_ACCEPT, func(r *myfwv1.CompiledRule) {
			r.Protocol = myfwv1.Protocol_PROTOCOL_ICMP
		}),
	}
	chains := []*myfwv1.CustomChainDef{chain("business-input", "MYFW-INPUT", "filter")}

	got, err := Evaluate(Flow{Direction: "INPUT", SourceIP: "1.2.3.4", DestIP: "10.0.0.1", Protocol: "icmp"}, rules, chains, nil)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	assertVerdict(t, got, VerdictAccept)
	assertMatchedRule(t, got, "i-icmp")
}

// assertResultMeta 断言仿真产物的完整度:每步带命令预览、整体带自然语言结论。
func assertResultMeta(t *testing.T, res *Result) {
	t.Helper()
	if res.Conclusion == "" {
		t.Fatalf("结论为空:verdict=%q steps=%+v note=%q", res.Verdict, res.Steps, res.Note)
	}
	for _, s := range res.Steps {
		if s.Command == "" {
			t.Fatalf("步骤 %q(chain=%s action=%s)缺少命令预览", s.RuleID, s.Chain, s.Action)
		}
	}
}

// TestEvaluate_ProducesMeta: Evaluate 端到端保证——每个步骤带命令预览、结果带结论。
func TestEvaluate_ProducesMeta(t *testing.T) {
	rules := []*myfwv1.CompiledRule{
		rule("i5", "MARKMANGLE", myfwv1.Action_ACTION_MARK, func(r *myfwv1.CompiledRule) {
			r.PortRange = "22"
			r.Mark = 15
		}),
		rule("i5-acl", "MARKACL-IN", myfwv1.Action_ACTION_ACCEPT, func(r *myfwv1.CompiledRule) {
			r.Source = "192.168.1.0/24"
			r.MatchMark = 15
		}),
		rule("i5-drop", "MARKACL-IN", myfwv1.Action_ACTION_DROP, func(r *myfwv1.CompiledRule) {
			r.MatchMark = 15
			r.Priority = 1
		}),
	}
	chains := []*myfwv1.CustomChainDef{
		chain("MARKMANGLE", "MYFW-MANGLE", "mangle"),
		chain("MARKACL-IN", "MYFW-INPUT", "filter"),
	}

	// 命中场景:打标步 + 白名单放行步都应有命令预览。
	got, err := Evaluate(tcpFlow("INPUT", "192.168.1.5", "10.0.0.1", 30000, 22), rules, chains, nil)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	assertVerdict(t, got, VerdictAccept)
	assertResultMeta(t, got)
	assertMatchedRule(t, got, "i5-acl")

	// 未命中场景:所有步骤(未命中)也应有命令预览。
	got, err = Evaluate(tcpFlow("INPUT", "1.2.3.4", "10.0.0.1", 30000, 22), rules, chains, nil)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	assertVerdict(t, got, VerdictDrop)
	assertResultMeta(t, got)
}

// TestEvaluate_StepActionPlain: Step.Action 应为简洁动作名(去 ACTION_ 枚举前缀),
// 供 terminatingStep/buildConclusion 的字符串比较与前端 class 使用。
func TestEvaluate_StepActionPlain(t *testing.T) {
	rules := []*myfwv1.CompiledRule{
		rule("i5", "MARKMANGLE", myfwv1.Action_ACTION_MARK, func(r *myfwv1.CompiledRule) {
			r.PortRange = "22"
			r.Mark = 15
		}),
		rule("i5-acl", "MARKACL-IN", myfwv1.Action_ACTION_ACCEPT, func(r *myfwv1.CompiledRule) {
			r.Source = "192.168.1.0/24"
			r.MatchMark = 15
		}),
	}
	chains := []*myfwv1.CustomChainDef{
		chain("MARKMANGLE", "MYFW-MANGLE", "mangle"),
		chain("MARKACL-IN", "MYFW-INPUT", "filter"),
	}

	got, err := Evaluate(tcpFlow("INPUT", "192.168.1.5", "10.0.0.1", 30000, 22), rules, chains, nil)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	// MARK→ACCEPT 两段式:打标步 + 白名单放行步,结论应含"打标"且含"放行"。
	for _, s := range got.Steps {
		if strings.HasPrefix(s.Action, "ACTION_") {
			t.Errorf("step %q action 应去枚举前缀,got %q", s.RuleID, s.Action)
		}
	}
	if !strings.Contains(got.Conclusion, "打标") || !strings.Contains(got.Conclusion, "放行") {
		t.Errorf("MARK→ACCEPT 两段式结论缺失,got %q", got.Conclusion)
	}
}

// TestFormatCommand: 命令预览对齐 driver compileRule 输出。
func TestFormatCommand(t *testing.T) {
	cases := []struct {
		name  string
		rule  *myfwv1.CompiledRule
		table string
		want  []string // 命令中必须包含的片段
	}{
		{
			name: "ACCEPT",
			rule: rule("i1", "business-input", myfwv1.Action_ACTION_ACCEPT, func(r *myfwv1.CompiledRule) {
				r.Source = "192.168.1.0/24"
				r.PortRange = "22"
			}),
			table: "filter",
			want:  []string{"iptables", "-A", "MYFW-business-input", "-s", "192.168.1.0/24", "-p", "tcp", "--dport", "22", "-j", "ACCEPT"},
		},
		{
			name: "DROP",
			rule: rule("i2", "acl-fwd", myfwv1.Action_ACTION_DROP, func(r *myfwv1.CompiledRule) {
				r.PortRange = "443"
			}),
			table: "filter",
			want:  []string{"iptables", "-A", "MYFW-acl-fwd", "-j", "DROP"},
		},
		{
			name: "MARK_带mangle表",
			rule: rule("i3", "MARKMANGLE", myfwv1.Action_ACTION_MARK, func(r *myfwv1.CompiledRule) {
				r.Mark = 15
			}),
			table: "mangle",
			want:  []string{"iptables", "-t", "mangle", "-A", "MYFW-MARKMANGLE", "-j", "MARK", "--set-mark", "15"},
		},
		{
			name: "match_mark条件",
			rule: rule("i4", "MARKACL-IN", myfwv1.Action_ACTION_ACCEPT, func(r *myfwv1.CompiledRule) {
				r.MatchMark = 15
			}),
			table: "filter",
			want:  []string{"-m", "mark", "--mark", "15", "-j", "ACCEPT"},
		},
		{
			name: "地址组源匹配",
			rule: rule("i5", "business-input", myfwv1.Action_ACTION_ACCEPT, func(r *myfwv1.CompiledRule) {
				r.SourceGroup = "internal"
			}),
			table: "filter",
			want:  []string{"-m", "set", "--match-set", "MYFW-internal", "src", "-j", "ACCEPT"},
		},
		{
			name: "DNAT",
			rule: rule("i6", "nat-pre", myfwv1.Action_ACTION_DNAT, func(r *myfwv1.CompiledRule) {
				r.NatTo = "10.0.0.9:8080"
			}),
			table: "nat",
			want:  []string{"iptables", "-t", "nat", "-j", "DNAT", "--to-destination", "10.0.0.9:8080"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := formatCommand(tc.rule, tc.table)
			for _, frag := range tc.want {
				if !strings.Contains(got, frag) {
					t.Errorf("命令 %q 缺少片段 %q", got, frag)
				}
			}
		})
	}
}

// TestBuildConclusion: 自然语言结论覆盖五类最终判定。
func TestBuildConclusion(t *testing.T) {
	cases := []struct {
		name string
		flow Flow
		res  *Result
		want []string // 结论中必须包含的片段
	}{
		{
			name: "ACCEPT",
			flow: tcpFlow("INPUT", "1.2.3.4", "10.0.0.1", 40000, 443),
			res: &Result{
				Verdict: VerdictAccept,
				Steps: []Step{
					{Chain: "MYFW-business-input", RuleID: "i-http", Action: "ACCEPT", Matched: true},
				},
			},
			want: []string{"源 1.2.3.4", "443", "MYFW-business-input", "i-http", "放行"},
		},
		{
			name: "DROP",
			flow: tcpFlow("FORWARD", "10.0.0.2", "172.16.0.1", 40000, 443),
			res: &Result{
				Verdict: VerdictDrop,
				Steps: []Step{
					{Chain: "MYFW-acl-fwd", RuleID: "i-drop", Action: "DROP", Matched: true},
				},
			},
			want: []string{"172.16.0.1", "MYFW-acl-fwd", "i-drop", "拦截"},
		},
		{
			name: "REJECT",
			flow: tcpFlow("INPUT", "1.2.3.4", "10.0.0.1", 40000, 3389),
			res: &Result{
				Verdict: VerdictReject,
				Steps: []Step{
					{Chain: "MYFW-business-input", RuleID: "i-rej", Action: "REJECT", Matched: true},
				},
			},
			want: []string{"3389", "i-rej", "拒绝"},
		},
		{
			name: "PASS",
			flow: tcpFlow("INPUT", "1.2.3.4", "10.0.0.1", 40000, 22),
			res:  &Result{Verdict: VerdictPass, Steps: nil},
			want: []string{"未命中任何终止规则", "PASS"},
		},
		{
			name: "MARK后ACCEPT_两段式",
			flow: tcpFlow("INPUT", "192.168.1.5", "10.0.0.1", 30000, 22),
			res: &Result{
				Verdict: VerdictAccept,
				Steps: []Step{
					{Chain: "MYFW-MARKMANGLE", RuleID: "i5", Action: "MARK", Matched: true, Mark: 15},
					{Chain: "MYFW-MARKACL-IN", RuleID: "i5-acl", Action: "ACCEPT", Matched: true},
				},
			},
			want: []string{"打标", "15", "i5-acl", "放行"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := buildConclusion(tc.flow, tc.res)
			for _, frag := range tc.want {
				if !strings.Contains(got, frag) {
					t.Errorf("结论 %q 缺少片段 %q", got, frag)
				}
			}
		})
	}
}

// --- 地址组黑盒测试(需求:测试机 IP 少,仿真引擎做 ipset 无状态语义黑盒验证) ---

// TestEvaluate_SourceGroup_BoundaryIP: 组成员 CIDR 边界 IP(网络地址/广播地址)命中。
// 地址组 [192.168.80.128/28] 覆盖 128-143,首尾必须命中,相邻外部地址不命中。
func TestEvaluate_SourceGroup_BoundaryIP(t *testing.T) {
	sets := []*myfwv1.AddressSet{set("seg", "192.168.80.128/28")}
	rules := []*myfwv1.CompiledRule{
		rule("i-seg", "business-input", myfwv1.Action_ACTION_ACCEPT, func(r *myfwv1.CompiledRule) {
			r.SourceGroup = "seg"
			r.PortRange = "8080"
		}),
	}
	chains := []*myfwv1.CustomChainDef{chain("business-input", "MYFW-INPUT", "filter")}

	// 组内边界与中间 IP 全部命中
	for _, ip := range []string{"192.168.80.128", "192.168.80.143", "192.168.80.135"} {
		got, err := Evaluate(tcpFlow("INPUT", ip, "10.0.0.1", 30000, 8080), rules, chains, sets)
		if err != nil {
			t.Fatalf("evaluate %s: %v", ip, err)
		}
		assertVerdict(t, got, VerdictAccept)
	}
	// 组外相邻 IP 不命中 -> PASS
	for _, ip := range []string{"192.168.80.127", "192.168.80.144"} {
		got, err := Evaluate(tcpFlow("INPUT", ip, "10.0.0.1", 30000, 8080), rules, chains, sets)
		if err != nil {
			t.Fatalf("evaluate %s: %v", ip, err)
		}
		assertVerdict(t, got, VerdictPass)
	}
}

// TestEvaluate_SourceGroup_MultiCIDR_Partial: 多 CIDR 成员(跨段展开场景),部分命中。
// 成员 = 范围 130-131(/31) + 180(/32),验证跨成员边界地址判定。
func TestEvaluate_SourceGroup_MultiCIDR_Partial(t *testing.T) {
	sets := []*myfwv1.AddressSet{set("seg", "192.168.80.130/31", "192.168.80.180/32")}
	rules := []*myfwv1.CompiledRule{
		rule("i-seg", "business-input", myfwv1.Action_ACTION_ACCEPT, func(r *myfwv1.CompiledRule) {
			r.SourceGroup = "seg"
			r.PortRange = "8080"
		}),
	}
	chains := []*myfwv1.CustomChainDef{chain("business-input", "MYFW-INPUT", "filter")}

	for _, ip := range []string{"192.168.80.130", "192.168.80.131", "192.168.80.180"} {
		got, err := Evaluate(tcpFlow("INPUT", ip, "10.0.0.1", 30000, 8080), rules, chains, sets)
		if err != nil {
			t.Fatalf("evaluate %s: %v", ip, err)
		}
		assertVerdict(t, got, VerdictAccept)
	}
	// 成员间隙(132-179)与成员外均不命中
	for _, ip := range []string{"192.168.80.132", "192.168.80.179", "192.168.80.181"} {
		got, err := Evaluate(tcpFlow("INPUT", ip, "10.0.0.1", 30000, 8080), rules, chains, sets)
		if err != nil {
			t.Fatalf("evaluate %s: %v", ip, err)
		}
		assertVerdict(t, got, VerdictPass)
	}
}

// TestEvaluate_SourceAndDestGroup: 源组 + 目的组同时约束,任一不命中则整条不命中。
func TestEvaluate_SourceAndDestGroup(t *testing.T) {
	sets := []*myfwv1.AddressSet{
		set("internal", "10.0.0.0/8"),
		set("web-servers", "172.16.0.0/16"),
	}
	rules := []*myfwv1.CompiledRule{
		rule("i-both", "business-input", myfwv1.Action_ACTION_ACCEPT, func(r *myfwv1.CompiledRule) {
			r.SourceGroup = "internal"
			r.DestinationGroup = "web-servers"
			r.PortRange = "8080"
		}),
	}
	chains := []*myfwv1.CustomChainDef{chain("business-input", "MYFW-INPUT", "filter")}

	// 源在组 + 目的在组 -> 命中
	got, err := Evaluate(tcpFlow("INPUT", "10.1.2.3", "172.16.9.9", 30000, 8080), rules, chains, sets)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	assertVerdict(t, got, VerdictAccept)
	// 源在组 + 目的不在组 -> 不命中
	got, err = Evaluate(tcpFlow("INPUT", "10.1.2.3", "8.8.8.8", 30000, 8080), rules, chains, sets)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	assertVerdict(t, got, VerdictPass)
	// 源不在组 -> 不命中
	got, err = Evaluate(tcpFlow("INPUT", "8.8.8.8", "172.16.9.9", 30000, 8080), rules, chains, sets)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	assertVerdict(t, got, VerdictPass)
}

// TestEvaluate_GroupMixedWithCIDR: 地址组 + 单 CIDR 混合约束(源组 AND 目的单 CIDR)。
func TestEvaluate_GroupMixedWithCIDR(t *testing.T) {
	sets := []*myfwv1.AddressSet{set("internal", "10.0.0.0/8")}
	rules := []*myfwv1.CompiledRule{
		rule("i-mixed", "business-input", myfwv1.Action_ACTION_ACCEPT, func(r *myfwv1.CompiledRule) {
			r.SourceGroup = "internal"
			r.Destination = "172.16.0.0/16"
			r.PortRange = "8080"
		}),
	}
	chains := []*myfwv1.CustomChainDef{chain("business-input", "MYFW-INPUT", "filter")}

	got, err := Evaluate(tcpFlow("INPUT", "10.1.2.3", "172.16.9.9", 30000, 8080), rules, chains, sets)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	assertVerdict(t, got, VerdictAccept)
	// 源在组但目的不在单 CIDR -> 不命中
	got, err = Evaluate(tcpFlow("INPUT", "10.1.2.3", "8.8.8.8", 30000, 8080), rules, chains, sets)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	assertVerdict(t, got, VerdictPass)
}

// TestEvaluate_RangeExpandedGroup: 与范围语法闭环——成员即 rangeToCIDRs(130-180)展开
// 的 7 条 CIDR,仿真验证展开集合边界命中正确(130/180 命中,129/181 不命中)。
func TestEvaluate_RangeExpandedGroup(t *testing.T) {
	sets := []*myfwv1.AddressSet{set("seg",
		"192.168.80.130/31", "192.168.80.132/30", "192.168.80.136/29",
		"192.168.80.144/28", "192.168.80.160/28", "192.168.80.176/30",
		"192.168.80.180/32",
	)}
	rules := []*myfwv1.CompiledRule{
		rule("i-seg", "business-input", myfwv1.Action_ACTION_ACCEPT, func(r *myfwv1.CompiledRule) {
			r.SourceGroup = "seg"
			r.PortRange = "8080"
		}),
	}
	chains := []*myfwv1.CustomChainDef{chain("business-input", "MYFW-INPUT", "filter")}

	for _, ip := range []string{"192.168.80.130", "192.168.80.155", "192.168.80.180"} {
		got, err := Evaluate(tcpFlow("INPUT", ip, "10.0.0.1", 30000, 8080), rules, chains, sets)
		if err != nil {
			t.Fatalf("evaluate %s: %v", ip, err)
		}
		assertVerdict(t, got, VerdictAccept)
	}
	for _, ip := range []string{"192.168.80.129", "192.168.80.181"} {
		got, err := Evaluate(tcpFlow("INPUT", ip, "10.0.0.1", 30000, 8080), rules, chains, sets)
		if err != nil {
			t.Fatalf("evaluate %s: %v", ip, err)
		}
		assertVerdict(t, got, VerdictPass)
	}
}
