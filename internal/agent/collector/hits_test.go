package collector

import (
	"reflect"
	"testing"
)

// TestParseRuleHits 验证 `iptables -L -v -n -x` 输出解析:
// 仅保留 comment 以 "myfw:" 开头的行,从 comment 反解实例 ID("i42-acl" -> 42)。
func TestParseRuleHits(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  []RuleHitEntry
	}{
		{
			name:  "standard_accept",
			input: "      42     3360 ACCEPT     all  --  *      *       10.0.0.0/24          0.0.0.0/0            /* myfw:i42 */\n",
			want:  []RuleHitEntry{{InstanceID: 42, Packets: 42, Bytes: 3360}},
		},
		{
			name:  "acl_suffix_instance_id",
			input: "      10      800 ACCEPT     all  --  *      *       0.0.0.0/0            0.0.0.0/0            /* myfw:i42-acl */\n",
			want:  []RuleHitEntry{{InstanceID: 42, Packets: 10, Bytes: 800}},
		},
		{
			name:  "drop_zero_packets",
			input: "       0        0 DROP       all  --  *      *       192.168.0.0/16       0.0.0.0/0            /* myfw:i42-drop */\n",
			want:  []RuleHitEntry{{InstanceID: 42, Packets: 0, Bytes: 0}},
		},
		{
			name:  "no_comment_skipped",
			input: "       5      100 RETURN     all  --  *      *       0.0.0.0/0            0.0.0.0/0\n",
			want:  nil,
		},
		{
			name:  "non_myfw_comment_skipped",
			input: "     999    99999 ACCEPT     all  --  *      *       0.0.0.0/0            0.0.0.0/0            /* custom:other */\n",
			want:  nil,
		},
		{
			name:  "chain_header_skipped",
			input: "Chain MYFW-acl-in (1 references)\n    pkts      bytes target     prot opt in     out     source               destination\n",
			want:  nil,
		},
		{
			name:  "empty_input",
			input: "",
			want:  nil,
		},
		{
			name: "multi_chain_mixed",
			input: `Chain INPUT (policy ACCEPT 100 packets, 8000 bytes)
    pkts      bytes target     prot opt in     out     source               destination
      50     4000 ACCEPT     all  --  *      *       0.0.0.0/0            0.0.0.0/0
Chain MYFW-acl-in (1 references)
    pkts      bytes target     prot opt in     out     source               destination
      42     3360 ACCEPT     all  --  *      *       10.0.0.0/24          0.0.0.0/0            /* myfw:i42 */
      10      800 ACCEPT     all  --  *      *       0.0.0.0/0            0.0.0.0/0            /* myfw:i42-acl */
`,
			want: []RuleHitEntry{
				{InstanceID: 42, Packets: 42, Bytes: 3360},
				{InstanceID: 42, Packets: 10, Bytes: 800},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseRuleHits(tc.input)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("want %+v, got %+v", tc.want, got)
			}
		})
	}
}
