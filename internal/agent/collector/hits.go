package collector

import (
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
)

// RuleHitEntry 规则命中统计(规则级,一条 MYFW 规则一条)。
// InstanceID 从规则 comment "myfw:i<id>" 反解;Packets/Bytes 取自 iptables 计数器。
type RuleHitEntry struct {
	InstanceID uint
	Packets    int64
	Bytes      int64
}

// commentRe 匹配 iptables -L 输出中的 myfw comment: /* myfw:i42 */ 或 /* myfw:i42-acl */
var commentRe = regexp.MustCompile(`/\*\s*myfw:(i\d+(?:-\w+)?)\s*\*/`)

// parseRuleHits 解析 `iptables -L -v -n -x` 输出,提取 MYFW 规则的命中统计。
// 仅保留 comment 以 "myfw:" 开头的行(系统规则/jump 规则无 comment,跳过)。
// 从 comment 反解实例 ID("i42-acl" -> 42)。纯函数,无副作用。
func parseRuleHits(output string) []RuleHitEntry {
	var out []RuleHitEntry
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// 跳过链声明行与表头行
		if strings.HasPrefix(line, "Chain ") || strings.HasPrefix(line, "pkts") {
			continue
		}
		m := commentRe.FindStringSubmatch(line)
		if m == nil {
			continue // 无 myfw comment,跳过
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		pkts, _ := strconv.ParseInt(fields[0], 10, 64)
		bytes, _ := strconv.ParseInt(fields[1], 10, 64)
		instanceID := parseInstanceID(m[1])
		if instanceID == 0 {
			continue
		}
		out = append(out, RuleHitEntry{InstanceID: instanceID, Packets: pkts, Bytes: bytes})
	}
	return out
}

// parseInstanceID 从 comment Id 反解实例 ID:"i42" -> 42, "i42-acl" -> 42。
func parseInstanceID(s string) uint {
	s = strings.TrimPrefix(s, "i")
	if idx := strings.IndexByte(s, '-'); idx >= 0 {
		s = s[:idx]
	}
	n, _ := strconv.ParseUint(s, 10, 64)
	return uint(n)
}

// CollectRuleHits 采集节点 MYFW 规则命中统计。执行 `iptables -t filter -L -v -n -x`,
// 解析 pkts/bytes + comment,返回规则级 entry 列表(同实例多条规则返回多条)。
// 非 Linux 返回 nil。filter 表首版,nat/mangle 后续。
func (c *Collector) CollectRuleHits() ([]RuleHitEntry, error) {
	if runtime.GOOS != "linux" {
		return nil, nil
	}
	cmd := exec.Command("iptables", "-t", "filter", "-L", "-v", "-n", "-x")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, err
	}
	return parseRuleHits(string(output)), nil
}
