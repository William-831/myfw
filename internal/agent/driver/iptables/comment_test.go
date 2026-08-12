package iptables

import (
	"strings"
	"testing"

	myfwv1 "iptables-tool/api/myfw/v1"
)

// TestCompileRuleAddsComment 验证规则追加 comment 标识(编码规则 Id),
// 供 Agent 采集命中率时反解到实例 ID。comment 统一加在 target 之后,
// 保证 iptables -S 输出位置稳定(hash 稳定)。
func TestCompileRuleAddsComment(t *testing.T) {
	cases := []struct {
		name string
		rule *myfwv1.CompiledRule
		want string // 期望的 comment 片段
	}{
		{
			name: "accept",
			rule: &myfwv1.CompiledRule{Id: "i42", Action: myfwv1.Action_ACTION_ACCEPT},
			want: `-m comment --comment myfw:i42`,
		},
		{
			name: "mark_whitelist_acl",
			rule: &myfwv1.CompiledRule{Id: "i42-acl", Action: myfwv1.Action_ACTION_ACCEPT, MatchMark: 15},
			want: `-m comment --comment myfw:i42-acl`,
		},
		{
			name: "drop",
			rule: &myfwv1.CompiledRule{Id: "i42-drop", Action: myfwv1.Action_ACTION_DROP},
			want: `-m comment --comment myfw:i42-drop`,
		},
		{
			name: "mark",
			rule: &myfwv1.CompiledRule{Id: "i9", Action: myfwv1.Action_ACTION_MARK, Mark: 42, Protocol: myfwv1.Protocol_PROTOCOL_TCP, PortRange: "443"},
			want: `-m comment --comment myfw:i9`,
		},
		{
			name: "dnat",
			rule: &myfwv1.CompiledRule{Id: "i7", Action: myfwv1.Action_ACTION_DNAT, NatTo: "10.0.0.5:8080", Protocol: myfwv1.Protocol_PROTOCOL_TCP, PortRange: "80"},
			want: `-m comment --comment myfw:i7`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args, err := compileRule(tc.rule, "MYFW-acl-in")
			if err != nil {
				t.Fatalf("compileRule: %v", err)
			}
			joined := strings.Join(args, " ")
			if !strings.Contains(joined, tc.want) {
				t.Fatalf("expected comment %q in rule, got: %s", tc.want, joined)
			}
			// comment 必须在 target(-j ...)之后,保证 -S 输出位置稳定
			jIdx := strings.Index(joined, "-j ")
			cIdx := strings.Index(joined, "-m comment")
			if jIdx == -1 {
				t.Fatalf("rule missing target -j: %s", joined)
			}
			if cIdx < jIdx {
				t.Fatalf("comment should come after target, got: %s", joined)
			}
		})
	}
}
