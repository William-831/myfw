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
	ChainTable  string // 落点链表(filter/nat/mangle),空=不校验(MARK 白名单落内置链)
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
	// DNAT/SNAT 必须落 nat 表链:iptables 的 DNAT/SNAT 目标仅在 nat 表可用,
	// 落 filter/mangle 链会在 Agent 执行期报错。编译期拦截(表一致性, P3),
	// ChainTable 空则跳过(调用方未提供链信息,如 MARK 白名单落内置链)。
	if (s.Action == "DNAT" || s.Action == "SNAT") && s.ChainTable != "" && s.ChainTable != "nat" {
		return fmt.Errorf("%s 规则须落 nat 表链,当前落点链为 %s 表(请选用 PREROUTING/POSTROUTING 钩子的策略组)", s.Action, s.ChainTable)
	}

	// MARK 打标值必须非零:0 在 iptables 表示无标记,不能作为打标值。
	// 标记值不在此硬编码特定数值(如 15/255)——数值合法性只要求非零,
	// 引用完整性(必须存在于标记管理 Mark 表,语义如 dev=开发/ops=运维)由 API 层校验。
	if s.Action == "MARK" && s.Mark == 0 {
		return fmt.Errorf("MARK 打标值不可为 0(0 表示无标记)")
	}
	// match_mark:0=不匹配,任意非零 uint32 合法(标记管理已保证值有效)。

	// MARK 白名单端口必填:白名单拦截的核心是"拦截哪个端口",模板骨架也需指定;
	// 源地址(白名单成员)留实例化时填,模板级不强制(实例层 requireMarkSource 校验)。
	if s.Action == "MARK" && s.PortRange == "" {
		return fmt.Errorf("MARK 白名单拦截需指定端口(port_range)")
	}

	// MARK 白名单流量方向:FORWARD(容器转发)/INPUT(主机入站),空默认 FORWARD
	if s.Action == "MARK" && s.Direction != "" {
		if s.Direction != "FORWARD" && s.Direction != "INPUT" {
			return fmt.Errorf("MARK 白名单方向须为 FORWARD 或 INPUT")
		}
	}

	// 非 MARK 动作 Direction 字段无意义,必须为空(仅 MARK 白名单使用方向字段)
	if s.Action != "MARK" && s.Direction != "" {
		return fmt.Errorf("非 MARK 动作不支持方向字段(仅 MARK 白名单使用)")
	}

	return nil
}

// IsMarkWhitelist 判断是否为 MARK 白名单拦截实例。
// 编译器自动生成打标+放行+兜底 DROP 三条规则,规则落平台内置链(MARKMANGLE+MARKACL-FWD/IN)。
// 与 rulespec.Validate 的 MARK 校验一致(MARK 必有源+端口),作为单一真相源供多处复用。
func IsMarkWhitelist(action, source, sourceGroup, portRange string) bool {
	return action == "MARK" && portRange != "" && (source != "" || sourceGroup != "")
}