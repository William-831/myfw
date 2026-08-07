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
		{"MARK+mark值", Spec{Action: "MARK", Mark: 15}},
		{"DNAT+nat_to", Spec{Action: "DNAT", NatTo: "10.0.0.1:80"}},
		{"SNAT+nat_to", Spec{Action: "SNAT", NatTo: "192.168.1.1"}},
		{"MARK白名单+TCP+端口+方向", Spec{Action: "MARK", Mark: 15, Protocol: "TCP", PortRange: "8080", Source: "10.0.0.0/24", Direction: "FORWARD"}},
		{"MARK白名单INPUT+TCP+端口", Spec{Action: "MARK", Mark: 255, Protocol: "TCP", PortRange: "62022", SourceGroup: "whitelist", Direction: "INPUT"}},
		{"match_mark=15", Spec{Action: "ACCEPT", MatchMark: 15, Protocol: "TCP", PortRange: "80"}},
		{"match_mark=255", Spec{Action: "ACCEPT", MatchMark: 255}},
		{"ICMP无端口", Spec{Action: "ACCEPT", Protocol: "ICMP"}},
		{"MARK无源无白名单（仅打标，非白名单拦截）", Spec{Action: "MARK", Mark: 15, Protocol: "TCP", PortRange: "62022"}},
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
		{"MARK白名单+源+无端口", Spec{Action: "MARK", Mark: 15, Source: "10.0.0.0/24"}},
		{"MARK白名单+地址组+无端口", Spec{Action: "MARK", Mark: 15, SourceGroup: "whitelist"}},
		{"MARK白名单方向错误", Spec{Action: "MARK", Mark: 15, Protocol: "TCP", PortRange: "8080", Source: "10.0.0.0/24", Direction: "OUTBOUND"}},
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