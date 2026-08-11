package stream

import (
	"testing"

	myfwv1 "iptables-tool/api/myfw/v1"
	"iptables-tool/internal/model"
)

// mkCR 构造期望规则(简化:链+动作+协议+端口+源)
func mkCR(chain string, action myfwv1.Action, protocol myfwv1.Protocol, port, src string) *myfwv1.CompiledRule {
	return &myfwv1.CompiledRule{Chain: chain, Action: action, Protocol: protocol, PortRange: port, Source: src}
}

// mkActual 构造实际上报规则行(-A CHAIN ...)
func mkActual(ruleLine string) model.IptablesRule {
	return model.IptablesRule{RuleLine: ruleLine, IsMYFW: true}
}

// TestClassifyDriftExternalTamper 验证存在陌生规则时判定为 external_tamper(最明确篡改信号)。
func TestClassifyDriftExternalTamper(t *testing.T) {
	expected := []*myfwv1.CompiledRule{
		mkCR("FWD", myfwv1.Action_ACTION_ACCEPT, myfwv1.Protocol_PROTOCOL_TCP, "22", ""),
		mkCR("FWD", myfwv1.Action_ACTION_ACCEPT, myfwv1.Protocol_PROTOCOL_TCP, "80", ""),
	}
	actual := []model.IptablesRule{
		mkActual("-A MYFW-FWD -p tcp --dport 22 -j ACCEPT"),
		mkActual("-A MYFW-FWD -p tcp --dport 80 -j ACCEPT"),
		mkActual("-A MYFW-FWD -p tcp --dport 443 -j ACCEPT"), // 陌生规则
	}
	c := classifyDrift(expected, actual)
	if c.Source != DriftSourceExternalTamper {
		t.Fatalf("多出陌生规则应判 external_tamper, got %q (extra=%d)", c.Source, c.Extra)
	}
	if c.Extra != 1 || c.Missing != 0 {
		t.Fatalf("extra=1/missing=0, got extra=%d missing=%d", c.Extra, c.Missing)
	}
}

// TestClassifyDriftRestartLoss 验证大面积缺失(≥80%)判定为 restart_loss(疑似重启丢失)。
func TestClassifyDriftRestartLoss(t *testing.T) {
	expected := []*myfwv1.CompiledRule{
		mkCR("FWD", myfwv1.Action_ACTION_ACCEPT, myfwv1.Protocol_PROTOCOL_TCP, "22", ""),
		mkCR("FWD", myfwv1.Action_ACTION_ACCEPT, myfwv1.Protocol_PROTOCOL_TCP, "23", ""),
		mkCR("FWD", myfwv1.Action_ACTION_ACCEPT, myfwv1.Protocol_PROTOCOL_TCP, "24", ""),
		mkCR("FWD", myfwv1.Action_ACTION_ACCEPT, myfwv1.Protocol_PROTOCOL_TCP, "25", ""),
		mkCR("FWD", myfwv1.Action_ACTION_ACCEPT, myfwv1.Protocol_PROTOCOL_TCP, "26", ""),
	}
	actual := []model.IptablesRule{
		mkActual("-A MYFW-FWD -p tcp --dport 22 -j ACCEPT"), // 仅剩 1/5
	}
	c := classifyDrift(expected, actual)
	if c.Source != DriftSourceRestartLoss {
		t.Fatalf("缺失 4/5(>=80%%)应判 restart_loss, got %q", c.Source)
	}
}

// TestClassifyDriftRestartLossEmpty 验证 actual 全空也判 restart_loss。
func TestClassifyDriftRestartLossEmpty(t *testing.T) {
	expected := []*myfwv1.CompiledRule{
		mkCR("FWD", myfwv1.Action_ACTION_ACCEPT, myfwv1.Protocol_PROTOCOL_TCP, "22", ""),
		mkCR("FWD", myfwv1.Action_ACTION_ACCEPT, myfwv1.Protocol_PROTOCOL_TCP, "80", ""),
	}
	c := classifyDrift(expected, nil)
	if c.Source != DriftSourceRestartLoss {
		t.Fatalf("actual 空应判 restart_loss, got %q", c.Source)
	}
}

// TestClassifyDriftRuleRemoved 验证个别规则缺失(少量)判定为 rule_removed(疑似篡改删除)。
func TestClassifyDriftRuleRemoved(t *testing.T) {
	expected := []*myfwv1.CompiledRule{
		mkCR("FWD", myfwv1.Action_ACTION_ACCEPT, myfwv1.Protocol_PROTOCOL_TCP, "22", ""),
		mkCR("FWD", myfwv1.Action_ACTION_ACCEPT, myfwv1.Protocol_PROTOCOL_TCP, "23", ""),
		mkCR("FWD", myfwv1.Action_ACTION_ACCEPT, myfwv1.Protocol_PROTOCOL_TCP, "24", ""),
		mkCR("FWD", myfwv1.Action_ACTION_ACCEPT, myfwv1.Protocol_PROTOCOL_TCP, "25", ""),
		mkCR("FWD", myfwv1.Action_ACTION_ACCEPT, myfwv1.Protocol_PROTOCOL_TCP, "26", ""),
	}
	actual := []model.IptablesRule{
		mkActual("-A MYFW-FWD -p tcp --dport 22 -j ACCEPT"),
		mkActual("-A MYFW-FWD -p tcp --dport 23 -j ACCEPT"),
		mkActual("-A MYFW-FWD -p tcp --dport 24 -j ACCEPT"),
		mkActual("-A MYFW-FWD -p tcp --dport 25 -j ACCEPT"), // 缺 26
	}
	c := classifyDrift(expected, actual)
	if c.Source != DriftSourceRuleRemoved {
		t.Fatalf("缺失 1/5(少量)应判 rule_removed, got %q", c.Source)
	}
}

// TestClassifyDriftJumpRuleSkipped 验证链跳转规则(-j MYFW-*)不参与对比(避免误算 extra),
// 且打标规则 --set-mark 0xf 与期望态 Mark=15 十六进制对齐。
func TestClassifyDriftJumpRuleSkipped(t *testing.T) {
	expected := []*myfwv1.CompiledRule{
		{Chain: "MARKMANGLE", Action: myfwv1.Action_ACTION_MARK, Protocol: myfwv1.Protocol_PROTOCOL_TCP, PortRange: "22", Mark: 15},
	}
	actual := []model.IptablesRule{
		mkActual("-A MYFW-FORWARD -j MYFW-MARKACL-FWD"),                  // 跳转规则,应跳过
		mkActual("-A MYFW-MARKMANGLE -p tcp -m tcp --dport 22 -j MARK --set-xmark 0xf/0xffffffff"), // 打标,0xf=15 对齐
	}
	c := classifyDrift(expected, actual)
	if c.Source != DriftSourceUnspecified {
		t.Fatalf("跳转规则跳过+打标对齐应 unspecified, got %q (extra=%d missing=%d)", c.Source, c.Extra, c.Missing)
	}
	if c.Extra != 0 || c.Missing != 0 {
		t.Fatalf("对齐后 extra=0/missing=0, got extra=%d missing=%d", c.Extra, c.Missing)
	}
}

// TestClassifyDriftChainFilter 验证 actual 只对比 expected 涉及链,
// 其他链的基础设施规则(conntrack 等)不被误算 extra。
func TestClassifyDriftChainFilter(t *testing.T) {
	expected := []*myfwv1.CompiledRule{
		mkCR("MARKACL-FWD", myfwv1.Action_ACTION_ACCEPT, myfwv1.Protocol_PROTOCOL_UNSPECIFIED, "", "192.168.80.174"),
	}
	actual := []model.IptablesRule{
		mkActual("-A MYFW-INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"), // 其他链,过滤
		mkActual("-A MYFW-MARKACL-FWD -s 192.168.80.174/32 -m mark --mark 0xf -j ACCEPT"), // 对齐
		mkActual("-A MYFW-MARKACL-FWD -s 10.255.255.255/32 -j ACCEPT"),                   // 陌生
	}
	c := classifyDrift(expected, actual)
	if c.Source != DriftSourceExternalTamper {
		t.Fatalf("陌生规则应判 external_tamper, got %q", c.Source)
	}
	if c.Extra != 1 {
		t.Fatalf("conntrack 应过滤,extra 应为 1(仅陌生), got %d", c.Extra)
	}
	if c.Missing != 0 {
		t.Fatalf("放行规则应与 expected 对齐,missing 应 0, got %d", c.Missing)
	}
}

// TestClassifyDriftIPMaskAlign 验证 iptables -S 单 IP 输出 /32 后缀与期望态无后缀对齐,
// 不因掩码写法差异误判(回归:此前 1.2.3.4 vs 1.2.3.4/32 被误算 missing+extra)。
func TestClassifyDriftIPMaskAlign(t *testing.T) {
	expected := []*myfwv1.CompiledRule{
		mkCR("MARKACL-FWD", myfwv1.Action_ACTION_ACCEPT, myfwv1.Protocol_PROTOCOL_UNSPECIFIED, "", "192.168.80.174"),
	}
	actual := []model.IptablesRule{
		mkActual("-A MYFW-MARKACL-FWD -s 192.168.80.174/32 -m mark --mark 0xf -j ACCEPT"),
	}
	c := classifyDrift(expected, actual)
	if c.Source != DriftSourceUnspecified {
		t.Fatalf("单 IP /32 与无后缀应判定一致(unspecified), got %q (missing=%d extra=%d)", c.Source, c.Missing, c.Extra)
	}
	if c.Missing != 0 || c.Extra != 0 {
		t.Fatalf("规范化后应无 missing/extra, got missing=%d extra=%d", c.Missing, c.Extra)
	}
}

// TestClassifyDriftUnspecified 验证 expected 空/无法判定时回落 unspecified。
func TestClassifyDriftUnspecified(t *testing.T) {
	// expected 为空(节点无启用的编译规则,无从对比)
	c := classifyDrift(nil, []model.IptablesRule{
		mkActual("-A MYFW-FWD -p tcp --dport 22 -j ACCEPT"),
	})
	if c.Source != DriftSourceUnspecified {
		t.Fatalf("expected 空应判 unspecified, got %q", c.Source)
	}
	// 完全一致(仅顺序/元数据差异,EnsureJumps 自愈场景):无多出无缺失也回落 unspecified
	expected := []*myfwv1.CompiledRule{
		mkCR("FWD", myfwv1.Action_ACTION_ACCEPT, myfwv1.Protocol_PROTOCOL_TCP, "22", ""),
	}
	actual := []model.IptablesRule{
		mkActual("-A MYFW-FWD -p tcp --dport 22 -j ACCEPT"),
	}
	c = classifyDrift(expected, actual)
	if c.Source != DriftSourceUnspecified {
		t.Fatalf("无多出无缺失应判 unspecified, got %q", c.Source)
	}
}
