package rulespec

import "testing"

func TestValidate_AcceptValid(t *testing.T) {
	cases := []struct {
		name string
		spec Spec
	}{
		{"TCP+端口", Spec{Action: "ACCEPT", Protocol: "TCP", PortRange: "22"}},
		{"UDP+端口", Spec{Action: "ACCEPT", Protocol: "UDP", PortRange: "53"}},
		{"无协议无端口", Spec{Action: "ACCEPT", Protocol: "ANY"}},
		{"DNAT+nat_to", Spec{Action: "DNAT", NatTo: "10.0.0.1:80"}},
		{"SNAT+nat_to", Spec{Action: "SNAT", NatTo: "192.168.1.1"}},
		{"MARK白名单+TCP+端口+方向", Spec{Action: "MARK", Mark: 15, Protocol: "TCP", PortRange: "8080", Source: "10.0.0.0/24", Direction: "FORWARD"}},
		{"MARK白名单INPUT+TCP+端口", Spec{Action: "MARK", Mark: 255, Protocol: "TCP", PortRange: "62022", SourceGroup: "whitelist", Direction: "INPUT"}},
		{"match_mark=15", Spec{Action: "ACCEPT", MatchMark: 15, Protocol: "TCP", PortRange: "80"}},
		{"match_mark=255", Spec{Action: "ACCEPT", MatchMark: 255}},
		{"ICMP无端口", Spec{Action: "ACCEPT", Protocol: "ICMP"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := c.spec.Validate(); err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestValidate_RejectInvalid(t *testing.T) {
	cases := []struct {
		name string
		spec Spec
	}{
		{"ANY+端口", Spec{Action: "ACCEPT", Protocol: "ANY", PortRange: "22"}},
		{"空协议+端口", Spec{Action: "ACCEPT", Protocol: "", PortRange: "22"}},
		{"ICMP+端口", Spec{Action: "ACCEPT", Protocol: "ICMP", PortRange: "7"}},
		{"DNAT无nat_to", Spec{Action: "DNAT"}},
		{"SNAT无nat_to", Spec{Action: "SNAT"}},
		{"MARK错误mark值", Spec{Action: "MARK", Mark: 100}},
		{"match_mark错误值", Spec{Action: "ACCEPT", MatchMark: 99}},
		{"MARK无源(单纯打标已废弃)", Spec{Action: "MARK", Mark: 15}},
		{"MARK有端口无源", Spec{Action: "MARK", Mark: 15, Protocol: "TCP", PortRange: "62022"}},
		{"MARK白名单+源+无端口", Spec{Action: "MARK", Mark: 15, Source: "10.0.0.0/24"}},
		{"MARK白名单+地址组+无端口", Spec{Action: "MARK", Mark: 15, SourceGroup: "whitelist"}},
		{"MARK白名单方向错误", Spec{Action: "MARK", Mark: 15, Protocol: "TCP", PortRange: "8080", Source: "10.0.0.0/24", Direction: "OUTBOUND"}},
		{"ACCEPT带方向(非MARK不支持)", Spec{Action: "ACCEPT", Direction: "INBOUND"}},
		{"DROP带方向(非MARK不支持)", Spec{Action: "DROP", Direction: "FORWARD"}},
		{"DNAT带方向(非MARK不支持)", Spec{Action: "DNAT", NatTo: "10.0.0.5:8080", Direction: "INPUT"}},
		{"未知协议", Spec{Action: "ACCEPT", Protocol: "SCTP"}},
		{"未知动作", Spec{Action: "LOG"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := c.spec.Validate(); err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

// TestIsMarkWhitelist 验证 MARK 白名单判定:仅 MARK + 源(地址/组) + 端口 为 true。
// 作为编译器/路由多处共用的单一真相源,与 Validate 的 MARK 校验保持一致。
func TestIsMarkWhitelist(t *testing.T) {
	cases := []struct {
		name                     string
		action, source, group, port string
		want                     bool
	}{
		{"MARK+源+端口", "MARK", "10.0.0.0/24", "", "8080", true},
		{"MARK+组+端口", "MARK", "", "whitelist", "8080", true},
		{"MARK+源无端口", "MARK", "10.0.0.0/24", "", "", false},
		{"MARK+组无端口", "MARK", "", "whitelist", "", false},
		{"MARK无源有端口", "MARK", "", "", "8080", false},
		{"MARK全空", "MARK", "", "", "", false},
		{"非MARK带源端口", "ACCEPT", "10.0.0.0/24", "", "8080", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := IsMarkWhitelist(c.action, c.source, c.group, c.port); got != c.want {
				t.Errorf("IsMarkWhitelist(%q,%q,%q,%q) = %v, want %v", c.action, c.source, c.group, c.port, got, c.want)
			}
		})
	}
}