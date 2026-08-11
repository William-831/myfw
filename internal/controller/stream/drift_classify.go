package stream

import (
	"strconv"
	"strings"

	myfwv1 "iptables-tool/api/myfw/v1"
	"iptables-tool/internal/model"
)

// 运行时 drift 来源分类(启发式,仅严重度提示,不改变自愈行为)。
// Controller 收到 node.drift 后,用 expected 编译产物 vs Agent 上报的 actual 规则做 diff 分类,
// 区分"节点重启规则丢失(良性)"与"外部篡改(恶性)"。见 Claudemissing/2026-08-11_运行时drift分类设计.md
const (
	DriftSourceExternalTamper = "external_tamper" // 存在陌生规则(多出):最明确篡改信号
	DriftSourceRuleRemoved    = "rule_removed"    // 个别 expected 规则缺失:疑似篡改删除
	DriftSourceRestartLoss    = "restart_loss"    // 大面积缺失:疑似重启/清空(自愈即可)
	DriftSourceUnspecified    = "unspecified"     // 无法分类:诚实回落
)

// restartLossRatio 缺失达到该比例判定为 restart_loss(0.8 = 4/5,整数比较用 ×5 / ×4)
const restartLossRatio = 0.8

// DriftClass 运行时漂移分类结果。
type DriftClass struct {
	Source    string `json:"source"`
	ExpectedN int    `json:"expected_n"`
	ActualN   int    `json:"actual_n"`
	Missing   int    `json:"missing"`
	Extra     int    `json:"extra"`
	Summary   string `json:"summary"`
}

// classifyDrift 纯函数:对比 expected 编译产物与 actual 上报规则(MYFW 命名空间),输出分类。
// 规则 key 规范化桥接结构化 CompiledRule 与 iptables -S 行:
//
//	chain|action|protocol|port|source|destination|mark
//
// 判定: 有陌生规则→external_tamper;大面积缺失(≥80%)→restart_loss;少量缺失→rule_removed;
// expected 空或完全一致→unspecified(诚实回落,不硬猜)。
func classifyDrift(expected []*myfwv1.CompiledRule, actual []model.IptablesRule) DriftClass {
	c := DriftClass{Source: DriftSourceUnspecified, ExpectedN: len(expected)}
	expKeys := make(map[string]struct{}, len(expected))
	for _, r := range expected {
		if r != nil {
			expKeys[compiledRuleKey(r)] = struct{}{}
		}
	}
	// expected 涉及的链集合(MARKMANGLE/MARKACL-FWD/组链名,不带 MYFW- 前缀)。
	// actual 只对比这些链,避免基础设施规则(conntrack/jump)被误算 extra。
	expChains := make(map[string]struct{}, len(expected))
	for _, r := range expected {
		if r != nil && r.Chain != "" {
			expChains[r.Chain] = struct{}{}
		}
	}
	actKeys := make(map[string]struct{}, len(actual))
	for _, r := range actual {
		if !r.IsMYFW {
			continue
		}
		if k, ok := parseActualRuleKey(r.RuleLine); ok {
			if len(expChains) > 0 {
				if ch, _, _ := strings.Cut(k, "|"); true {
					if _, in := expChains[ch]; !in {
						continue
					}
				}
			}
			actKeys[k] = struct{}{}
		}
	}
	// 集合求差:expected 有 actual 无 = missing;actual 有 expected 无 = extra
	c.ActualN = len(actKeys)
	if len(expKeys) == 0 {
		c.Summary = "节点无启用的编译规则,无法对比"
		return c
	}
	for k := range expKeys {
		if _, ok := actKeys[k]; !ok {
			c.Missing++
		}
	}
	for k := range actKeys {
		if _, ok := expKeys[k]; !ok {
			c.Extra++
		}
	}
	switch {
	case c.Extra > 0:
		c.Source = DriftSourceExternalTamper
		c.Summary = "发现外部新增规则(陌生规则 " + strconv.Itoa(c.Extra) + " 条),疑似被篡改"
	case len(actKeys) == 0 || c.Missing*5 >= len(expKeys)*4:
		c.Source = DriftSourceRestartLoss
		c.Summary = "MYFW 规则大面积缺失(" + strconv.Itoa(c.Missing) + "/" + strconv.Itoa(len(expKeys)) + "),疑似节点重启丢失"
	case c.Missing > 0:
		c.Source = DriftSourceRuleRemoved
		c.Summary = "个别规则被移除(" + strconv.Itoa(c.Missing) + "/" + strconv.Itoa(len(expKeys)) + "),疑似篡改删除"
	default:
		c.Source = DriftSourceUnspecified
		c.Summary = "规则集合一致(仅顺序/元数据差异,或已由 EnsureJumps 自愈)"
	}
	return c
}

// compiledRuleKey 结构化编译规则 → 规范化 key。
func compiledRuleKey(cr *myfwv1.CompiledRule) string {
	chain := cr.Chain
	if chain == "" {
		chain = "-"
	}
	return strings.Join([]string{
		chain,
		actionName(cr.Action),
		protocolName(cr.Protocol),
		orDash(cr.PortRange),
		orDash(normIP(cr.Source)),
		orDash(normIP(cr.Destination)),
		strconv.FormatUint(uint64(cr.Mark), 10),
	}, "|")
}

// parseActualRuleKey 从 iptables -S 规则行("-A CHAIN ...")解析同构 key。
// 非 -A 行(如 -N/-P 声明)返回 false 跳过;字段按标志位提取,顺序无关。
func parseActualRuleKey(line string) (string, bool) {
	fields := strings.Fields(line)
	if len(fields) < 3 || fields[0] != "-A" {
		return "", false
	}
	chain := strings.TrimPrefix(fields[1], "MYFW-")
	action, protocol, port, src, dst, mark := "UNKNOWN", "any", "-", "-", "-", "0"
	for i := 2; i < len(fields); i++ {
		switch fields[i] {
		case "-j":
			if i+1 < len(fields) {
				target := fields[i+1]
				// 跳转到自定义链(MYFW-*)是链跳转而非规则体,expected CompiledRule 不含,
				// 跳过避免误算 extra(如 -A MYFW-FORWARD -j MYFW-MARKACL-FWD)。
				if strings.HasPrefix(target, "MYFW-") {
					return "", false
				}
				action = strings.ToUpper(target)
			}
			i++
		case "-p":
			if i+1 < len(fields) {
				protocol = strings.ToLower(fields[i+1])
			}
			i++
		case "--dport", "--sport":
			if i+1 < len(fields) {
				port = fields[i+1]
			}
			i++
		case "-s":
			if i+1 < len(fields) {
				src = normIP(fields[i+1])
			}
			i++
		case "-d":
			if i+1 < len(fields) {
				dst = normIP(fields[i+1])
			}
			i++
		case "--set-mark", "--set-xmark":
			if i+1 < len(fields) {
				// iptables 输出十六进制(0xf),--set-xmark 带 /掩码(0xf/0xffffffff);
				// 期望态 Mark 存十进制(15),取 / 前值转十进制对齐。
				vStr := fields[i+1]
				if idx := strings.Index(vStr, "/"); idx >= 0 {
					vStr = vStr[:idx]
				}
				if v, err := strconv.ParseUint(vStr, 0, 32); err == nil {
					mark = strconv.FormatUint(v, 10)
				} else {
					mark = vStr
				}
			}
			i++
		}
	}
	return strings.Join([]string{chain, action, protocol, port, src, dst, mark}, "|"), true
}

// actionName / protocolName 枚举 → 展示/对比名(与 iptables 行对齐:协议小写,ANY 无 -p)。
func actionName(a myfwv1.Action) string {
	switch a {
	case myfwv1.Action_ACTION_ACCEPT:
		return "ACCEPT"
	case myfwv1.Action_ACTION_DROP:
		return "DROP"
	case myfwv1.Action_ACTION_REJECT:
		return "REJECT"
	case myfwv1.Action_ACTION_MARK:
		return "MARK"
	case myfwv1.Action_ACTION_DNAT:
		return "DNAT"
	case myfwv1.Action_ACTION_SNAT:
		return "SNAT"
	}
	return "UNKNOWN"
}

func protocolName(p myfwv1.Protocol) string {
	switch p {
	case myfwv1.Protocol_PROTOCOL_TCP:
		return "tcp"
	case myfwv1.Protocol_PROTOCOL_UDP:
		return "udp"
	case myfwv1.Protocol_PROTOCOL_ICMP:
		return "icmp"
	}
	return "any" // ANY/UNSPECIFIED:iptables 行无 -p
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// normIP 规范化 IP/CIDR:iptables -S 对单 IP 输出 1.2.3.4/32,
// 而期望态 CompiledRule.Source 存 1.2.3.4,去 /32 后缀对齐(其他掩码如 /24 保留)。
func normIP(s string) string {
	return strings.TrimSuffix(s, "/32")
}
