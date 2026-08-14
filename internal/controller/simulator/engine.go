// Package simulator 提供规则匹配引擎(计划二:流量仿真预演)。
//
// 语义对齐真实 driver(iptables.go Apply + systemJumps):所有 MYFW 规则落在用户
// 自定义子链 MYFW-<chain> 中,父链 MYFW-INPUT/FORWARD/OUTPUT 仅含 conntrack 放行
// 与子链 jump。仿真遍历:按方向进入 -> 先 mangle 打标预遍(INPUT/FORWARD:mangle
// PREROUTING 先于 filter 决策,仅应用 MARK,支撑 MARK 白名单主场景)-> 按链定义顺序
// 进入各 filter 子链 -> 子链内按 priority(升序,次按 id)线性匹配 -> ACCEPT/DROP/
// REJECT 即终止,RETURN 语义隐含(子链遍历完回父链继续)。首版无状态匹配;NAT 仅
// 提示不建模,mangle 仅建模打标。
package simulator

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	myfwv1 "iptables-tool/api/myfw/v1"
)

// Flow 五元组流量(首版无状态:不携带连接状态/接口,MARK 初值由规则链推导)。
type Flow struct {
	Direction string `json:"direction"` // INPUT | FORWARD | OUTPUT(filter 表钩子)
	SourceIP  string `json:"source_ip"`
	DestIP    string `json:"dest_ip"`
	Protocol  string `json:"protocol"` // tcp | udp | icmp | 空(任意)
	SrcPort   int    `json:"src_port"` // 0 = 任意
	DstPort   int    `json:"dst_port"` // 0 = 任意
	Mark      uint32 `json:"mark"`     // 初始打标(通常 0)
}

// Verdict 仿真最终判定。
type Verdict string

const (
	VerdictAccept Verdict = "ACCEPT"
	VerdictDrop   Verdict = "DROP"
	VerdictReject Verdict = "REJECT"
	// VerdictPass 表示遍历结束无规则命中,交由系统链默认策略(通常放行)。
	VerdictPass Verdict = "PASS"
)

// Step 遍历路径上的单步(一条规则的匹配结果)。
type Step struct {
	Chain   string `json:"chain"`    // 所在子链 MYFW-<chain>
	RuleID  string `json:"rule_id"`  // 规则 id
	Action  string `json:"action"`   // 规则动作(ACCEPT/DROP/REJECT/MARK/DNAT/SNAT)
	Mark    uint32 `json:"mark"`     // 命中 MARK 规则时的打标值
	Matched bool   `json:"matched"`  // 该步是否命中
	Command string `json:"command"`  // 该规则对应 iptables 命令预览(对齐 driver compileRule)
	Note    string `json:"note"`     // 提示(如 NAT 不支持)
}

// Result 仿真结果。
type Result struct {
	Verdict    Verdict `json:"verdict"`
	Steps      []Step  `json:"steps"`
	Note       string  `json:"note"`
	Conclusion string  `json:"conclusion"` // 自然语言结论:按入参五元组 + 最终判定拼接
}

// 首版支持的方向 -> 父链映射(filter 表)。
var filterParents = map[string]string{
	"INPUT":   "MYFW-INPUT",
	"FORWARD": "MYFW-FORWARD",
	"OUTPUT":  "MYFW-OUTPUT",
}

// evalMode 单链评估模式:filter 主遍历可终止;mangle 打标预遍仅应用 MARK。
type evalMode int

const (
	modeFilter     evalMode = iota // filter 表:ACCEPT/DROP/REJECT 终止
	modeMarkPrepass                // mangle 预遍:仅 MARK 生效,其余提示忽略
)

// Evaluate 对规则集 + 流量做无状态 filter 表匹配仿真,返回命中路径与最终判定。
// rules/chains/sets 对应 compiler.CompileForNode 的编译产物(期望态)。
//
// 遍历语义对齐真实 driver(Apply + systemJumps):mangle PREROUTING 打标先于
// filter INPUT/FORWARD 决策(MARK 白名单主场景:打标在 MARKMANGLE,白名单/兜底在
// MARKACL-*),因此 INPUT/FORWARD 先评估挂 MYFW-MANGLE 的 mangle 链(仅 MARK 生效),
// 再按链定义顺序评估 filter 子链。OUTPUT 无对应 mangle 链,直接走 filter。
func Evaluate(flow Flow, rules []*myfwv1.CompiledRule, chains []*myfwv1.CustomChainDef, sets []*myfwv1.AddressSet) (*Result, error) {
	parent, ok := filterParents[flow.Direction]
	if !ok {
		return nil, fmt.Errorf("simulator: 不支持方向 %q(首版仅支持 filter 表 INPUT/FORWARD/OUTPUT)", flow.Direction)
	}

	// 1. 规则入桶 + 链内排序(priority 升序,次按 id,与 driver.Apply 一致)。
	byChain := make(map[string][]*myfwv1.CompiledRule)
	for _, r := range rules {
		if r.Chain == "" {
			continue // 无归属链的规则不会真实下发,跳过
		}
		byChain[r.Chain] = append(byChain[r.Chain], r)
	}
	for _, list := range byChain {
		sort.SliceStable(list, func(i, j int) bool {
			if list[i].Priority != list[j].Priority {
				return list[i].Priority < list[j].Priority
			}
			return list[i].Id < list[j].Id
		})
	}

	// 2. 地址组索引(ipset 无状态成员集合)。
	setMembers := make(map[string][]string, len(sets))
	for _, s := range sets {
		setMembers[s.Name] = s.Members
	}

	res := &Result{}

	// 3. mangle 打标预遍(INPUT/FORWARD):mangle PREROUTING 先于 filter 决策。
	if flow.Direction == "INPUT" || flow.Direction == "FORWARD" {
		for _, cc := range chains {
			if cc.Table == "mangle" && cc.Parent == "MYFW-MANGLE" {
				if evalChainRules(&flow, res, cc.Name, cc.Table, byChain[cc.Name], setMembers, modeMarkPrepass) {
					res.Conclusion = buildConclusion(flow, res)
					return res, nil
				}
			}
		}
	}

	// 4. filter 主遍历:链定义顺序(compiler 已按 priority 升序输出)。
	for _, cc := range chains {
		if cc.Table == "filter" && cc.Parent == parent {
			if evalChainRules(&flow, res, cc.Name, cc.Table, byChain[cc.Name], setMembers, modeFilter) {
				res.Conclusion = buildConclusion(flow, res)
				return res, nil
			}
		}
	}

	res.Verdict = VerdictPass
	res.Note = "无规则命中(PASS):交由系统链默认策略(通常放行)。无状态仿真未建模 conntrack ESTABLISHED,RELATED 放行与系统链默认 DROP 场景。"
	res.Conclusion = buildConclusion(flow, res)
	return res, nil
}

// evalChainRules 评估单链内全部规则,返回是否已终止(命中最终判定)。
// modeMarkPrepass 下 ACCEPT/DROP/REJECT 不终止(仅提示,打标规则仍可命中)。
func evalChainRules(flow *Flow, res *Result, cname, table string, rules []*myfwv1.CompiledRule, sets map[string][]string, mode evalMode) bool {
	for _, r := range rules {
		matched := matchRule(flow, r, sets)
		// Action 取简洁名(去 ACTION_ 枚举前缀):结论/前端 class 均按 ACCEPT/DROP/MARK 比较。
		step := Step{Chain: "MYFW-" + cname, RuleID: r.Id, Action: strings.TrimPrefix(r.Action.String(), "ACTION_"), Matched: matched, Mark: flow.Mark, Command: formatCommand(r, table)}
		if !matched {
			res.Steps = append(res.Steps, step)
			continue
		}
		res.Steps = append(res.Steps, step)
		switch r.Action {
		case myfwv1.Action_ACTION_MARK:
			// 打标不终止,继续遍历(后续 match_mark 规则可命中)。
			flow.Mark = r.Mark
			res.Steps[len(res.Steps)-1].Mark = r.Mark
		case myfwv1.Action_ACTION_ACCEPT:
			if mode == modeMarkPrepass {
				res.Steps[len(res.Steps)-1].Note = "mangle 预遍仅建模打标,ACCEPT 语义不模拟,继续"
				continue
			}
			res.Verdict = VerdictAccept
			return true
		case myfwv1.Action_ACTION_DROP:
			if mode == modeMarkPrepass {
				res.Steps[len(res.Steps)-1].Note = "mangle 预遍仅建模打标,DROP 语义不模拟,继续"
				continue
			}
			res.Verdict = VerdictDrop
			return true
		case myfwv1.Action_ACTION_REJECT:
			if mode == modeMarkPrepass {
				res.Steps[len(res.Steps)-1].Note = "mangle 预遍仅建模打标,REJECT 语义不模拟,继续"
				continue
			}
			res.Verdict = VerdictReject
			return true
		case myfwv1.Action_ACTION_DNAT, myfwv1.Action_ACTION_SNAT:
			// NAT 表语义(源/目的改写)不建模,仅提示并继续。
			res.Steps[len(res.Steps)-1].Note = "NAT 动作不支持仿真(仅展示,已按未命中继续遍历)"
		default:
			res.Steps[len(res.Steps)-1].Note = fmt.Sprintf("未知动作 %s,已按未命中继续遍历", r.Action.String())
		}
	}
	return false
}

// matchRule 判断规则是否命中该流量(全条件 AND)。
func matchRule(flow *Flow, r *myfwv1.CompiledRule, sets map[string][]string) bool {
	if r.Source != "" && !ipInCIDR(flow.SourceIP, r.Source) {
		return false
	}
	if r.Destination != "" && !ipInCIDR(flow.DestIP, r.Destination) {
		return false
	}
	if r.SourceGroup != "" && !ipInAnyCIDR(flow.SourceIP, sets[r.SourceGroup]) {
		return false
	}
	if r.DestinationGroup != "" && !ipInAnyCIDR(flow.DestIP, sets[r.DestinationGroup]) {
		return false
	}
	if !protoMatch(flow.Protocol, r.Protocol) {
		return false
	}
	if r.PortRange != "" && !portInRange(flow.DstPort, r.PortRange) {
		return false
	}
	if r.MatchMark != 0 && flow.Mark != r.MatchMark {
		return false
	}
	return true
}

// protoMatch 协议匹配:ANY/UNSPECIFIED 放行任意。
func protoMatch(flowProto string, ruleProto myfwv1.Protocol) bool {
	switch ruleProto {
	case myfwv1.Protocol_PROTOCOL_ANY, myfwv1.Protocol_PROTOCOL_UNSPECIFIED:
		return true
	case myfwv1.Protocol_PROTOCOL_TCP:
		return flowProto == "tcp"
	case myfwv1.Protocol_PROTOCOL_UDP:
		return flowProto == "udp"
	case myfwv1.Protocol_PROTOCOL_ICMP:
		return flowProto == "icmp"
	}
	return false
}

// portInRange 目的端口区间匹配:"22" 单端口 / "1000-2000" 区间。
// 流端口 0(未指定)不命中带端口约束的规则:未知端口与特定端口规则不产生交集。
func portInRange(flowPort int, rangeStr string) bool {
	if flowPort == 0 {
		return false
	}
	if i := strings.IndexByte(rangeStr, '-'); i >= 0 {
		var lo, hi int
		if _, err := fmt.Sscanf(rangeStr[:i], "%d", &lo); err != nil {
			return false
		}
		if _, err := fmt.Sscanf(rangeStr[i+1:], "%d", &hi); err != nil {
			return false
		}
		return flowPort >= lo && flowPort <= hi
	}
	var port int
	if _, err := fmt.Sscanf(rangeStr, "%d", &port); err != nil {
		return false
	}
	return flowPort == port
}

// ipInCIDR 判断 IP 是否在 CIDR/单 IP 内(单 IP 视作 /32 或 /128)。
func ipInCIDR(ipStr, cidr string) bool {
	ip, err := netip.ParseAddr(ipStr)
	if err != nil {
		return false
	}
	if strings.Contains(cidr, "/") {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return false
		}
		return prefix.Contains(ip)
	}
	other, err := netip.ParseAddr(cidr)
	if err != nil {
		return false
	}
	return ip == other
}

// ipInAnyCIDR 判断 IP 是否命中任一成员(地址组 ipset 无状态语义)。
func ipInAnyCIDR(ipStr string, members []string) bool {
	for _, m := range members {
		if ipInCIDR(ipStr, m) {
			return true
		}
	}
	return false
}

// formatCommand 将一条 CompiledRule 拼成可读的 iptables 命令(预览用),
// 字段顺序与目标语法对齐 driver compileRule(iptables.go:628),filter 表省略 -t。
func formatCommand(r *myfwv1.CompiledRule, table string) string {
	var b strings.Builder
	b.WriteString("iptables")
	if table != "" && table != "filter" {
		b.WriteString(" -t " + table)
	}
	b.WriteString(" -A MYFW-" + r.Chain)
	if r.Source != "" {
		b.WriteString(" -s " + r.Source)
	}
	if r.Destination != "" {
		b.WriteString(" -d " + r.Destination)
	}
	switch r.Protocol {
	case myfwv1.Protocol_PROTOCOL_TCP:
		b.WriteString(" -p tcp")
	case myfwv1.Protocol_PROTOCOL_UDP:
		b.WriteString(" -p udp")
	case myfwv1.Protocol_PROTOCOL_ICMP:
		b.WriteString(" -p icmp")
	}
	if r.PortRange != "" {
		b.WriteString(" --dport " + strings.ReplaceAll(r.PortRange, "-", ":"))
	}
	if r.SourceGroup != "" {
		b.WriteString(" -m set --match-set MYFW-" + r.SourceGroup + " src")
	}
	if r.DestinationGroup != "" {
		b.WriteString(" -m set --match-set MYFW-" + r.DestinationGroup + " dst")
	}
	if r.MatchMark != 0 {
		b.WriteString(" -m mark --mark " + strconv.FormatUint(uint64(r.MatchMark), 10))
	}
	switch r.Action {
	case myfwv1.Action_ACTION_ACCEPT:
		b.WriteString(" -j ACCEPT")
	case myfwv1.Action_ACTION_DROP:
		b.WriteString(" -j DROP")
	case myfwv1.Action_ACTION_REJECT:
		b.WriteString(" -j REJECT")
	case myfwv1.Action_ACTION_MARK:
		b.WriteString(" -j MARK --set-mark " + strconv.FormatUint(uint64(r.Mark), 10))
	case myfwv1.Action_ACTION_DNAT:
		b.WriteString(" -j DNAT --to-destination " + r.NatTo)
	case myfwv1.Action_ACTION_SNAT:
		b.WriteString(" -j SNAT --to-source " + r.NatTo)
	}
	if r.Id != "" {
		b.WriteString(" -m comment --comment \"myfw:" + r.Id + "\"")
	}
	return b.String()
}

// 方向中文描述(结论用)。
var directionLabels = map[string]string{
	"INPUT":   "入站 INPUT",
	"FORWARD": "转发 FORWARD",
	"OUTPUT":  "出站 OUTPUT",
}

// buildConclusion 依据入参五元组与最终判定拼接自然语言结论(纯函数)。
// MARK→ACCEPT 等两段式场景会先描述打标,再描述白名单/兜底判定。
func buildConclusion(flow Flow, res *Result) string {
	src := flow.SourceIP
	if src == "" {
		src = "任意源"
	}
	dst := flow.DestIP
	if dst == "" {
		dst = "任意目的"
	}
	proto := strings.ToUpper(flow.Protocol)
	if flow.Protocol == "" {
		proto = "任意协议"
	}
	flowDesc := fmt.Sprintf("源 %s 的 %s 流量(目的 %s", src, proto, dst)
	if flow.DstPort > 0 {
		flowDesc += fmt.Sprintf(":%d", flow.DstPort)
	}
	if lbl, ok := directionLabels[flow.Direction]; ok {
		flowDesc += ",方向 " + lbl
	}
	flowDesc += ")"

	switch res.Verdict {
	case VerdictAccept, VerdictDrop, VerdictReject:
		term := terminatingStep(res)
		if term == nil {
			// 防御:有终止判定但找不到对应步骤(理论上不出现)。
			return flowDesc + " 最终判定 " + string(res.Verdict) + "。"
		}
		// 前置打标描述(如 MARK 白名单:先在 MARKMANGLE 打标,再在白名单链判定)。
		markDesc := ""
		for _, s := range res.Steps {
			if s.Matched && s.Action == "MARK" {
				markDesc = fmt.Sprintf("先在 %s 链被打标 %d(规则 %s),", s.Chain, s.Mark, s.RuleID)
				break
			}
		}
		verb := map[Verdict]string{VerdictAccept: "放行", VerdictDrop: "拦截", VerdictReject: "拒绝"}[res.Verdict]
		return fmt.Sprintf("%s %s在 %s 链命中规则 %s,动作 %s,流量将被%s。", flowDesc, markDesc, term.Chain, term.RuleID, term.Action, verb)
	default: // VerdictPass
		return flowDesc + ",未命中任何终止规则,遍历结束(PASS),交由系统链默认策略处理(通常放行)。无状态仿真未建模 conntrack 放行。"
	}
}

// terminatingStep 返回最终判定对应的命中终止步(ACCEPT/DROP/REJECT)。
// 从后往前找,排除 mangle 预遍中仅提示的 ACCEPT/DROP(其 Note 标记"mangle 预遍")。
func terminatingStep(res *Result) *Step {
	for i := len(res.Steps) - 1; i >= 0; i-- {
		s := &res.Steps[i]
		if !s.Matched {
			continue
		}
		switch s.Action {
		case "ACCEPT", "DROP", "REJECT":
			if strings.Contains(s.Note, "mangle 预遍") {
				continue
			}
			return s
		}
	}
	return nil
}
