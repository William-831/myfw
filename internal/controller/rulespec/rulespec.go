// Package rulespec 提供规则字段的单一校验权威。
// 校验约束与 iptables/nftables 实际能力对齐，确保"校验通过 = 一定能执行"。
// API 入口/编译器/Agent driver 三层复用同一份 Validate，杜绝"校验放行但执行拒绝"。
package rulespec

import "fmt"

// Spec 是规则字段子集，涵盖所有需要校验的字段。
// 与 policy.Fields 字段一致，但作为独立包避免循环依赖。
type Spec struct {
	Action      string
	Direction   string
	Mark        uint32
	MatchMark   uint32
	NatTo       string
	Protocol    string
	PortRange   string
	Source      string
	SourceGroup string
}

var validProtocols = map[string]bool{
	"": true, "ANY": true, "TCP": true, "UDP": true, "ICMP": true,
}

var validActions = map[string]bool{
	"ACCEPT": true, "DROP": true, "REJECT": true, "MARK": true, "DNAT": true, "SNAT": true,
}

// Validate 校验规则字段合法性与一致性。
// 约束与 iptables/nftables 实际能力对齐，确保规则可执行。
func (s Spec) Validate() error {
	// 协议合法性
	if !validProtocols[s.Protocol] {
		return fmt.Errorf("不支持的协议 %q", s.Protocol)
	}
	// 动作合法性
	if !validActions[s.Action] {
		return fmt.Errorf("不支持的动作 %q", s.Action)
	}

	// 端口必须有具体协议:iptables --dport 必须配合 -p tcp/udp。
	// ANY/ICMP/空协议均不能配端口。
	if s.PortRange != "" && s.Protocol != "TCP" && s.Protocol != "UDP" {
		return fmt.Errorf("端口需指定具体协议(TCP/UDP)")
	}

	// ICMP 不能有端口
	if s.Protocol == "ICMP" && s.PortRange != "" {
		return fmt.Errorf("ICMP 协议不能指定端口")
	}

	// DNAT/SNAT 需要 nat_to
	if (s.Action == "DNAT" || s.Action == "SNAT") && s.NatTo == "" {
		return fmt.Errorf("%s 需指定 nat_to", s.Action)
	}

	// mark 值限定为 dev(15)/ops(255) 两种权限标记
	if s.Action == "MARK" && s.Mark != 15 && s.Mark != 255 {
		return fmt.Errorf("mark 必须是 15(dev) 或 255(ops)")
	}
	if s.MatchMark != 0 && s.MatchMark != 15 && s.MatchMark != 255 {
		return fmt.Errorf("match_mark 必须是 0/15/255")
	}

	// MARK 白名单拦截:有源地址/地址组时必须指定端口。
	// 打标按端口识别业务流量,编译器自动生成 mangle 打标 + filter 白名单放行 + 兜底 DROP。
	if s.Action == "MARK" && (s.Source != "" || s.SourceGroup != "") && s.PortRange == "" {
		return fmt.Errorf("MARK 白名单拦截需指定端口(port_range)")
	}

	// MARK 白名单流量方向:FORWARD(容器转发)/INPUT(主机入站),空默认 FORWARD
	if s.Action == "MARK" && (s.Source != "" || s.SourceGroup != "") && s.PortRange != "" && s.Direction != "" {
		if s.Direction != "FORWARD" && s.Direction != "INPUT" {
			return fmt.Errorf("MARK 白名单方向须为 FORWARD 或 INPUT")
		}
	}

	return nil
}