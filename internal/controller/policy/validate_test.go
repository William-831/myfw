package policy

import (
	"strings"
	"testing"
)

// TestValidateFields_MarkWhitelist 覆盖 MARK 白名单拦截:填源地址组+端口即合法,
// 编译器自动生成打标+白名单放行+兜底 DROP。需端口,方向须 FORWARD/INPUT。
func TestValidateFields_MarkWhitelist(t *testing.T) {
	cases := []struct {
		name    string
		f       Fields
		wantErr string // 空表示期望通过
	}{
		{
			name:    "源地址组+端口+方向FORWARD",
			f:       Fields{Action: "MARK", Mark: 15, Protocol: "TCP", SourceGroup: "whitelist", PortRange: "8080", Direction: "FORWARD"},
			wantErr: "",
		},
		{
			name:    "源地址组+端口+方向INPUT",
			f:       Fields{Action: "MARK", Mark: 15, Protocol: "TCP", SourceGroup: "whitelist", PortRange: "8080", Direction: "INPUT"},
			wantErr: "",
		},
		{
			name:    "白名单无端口",
			f:       Fields{Action: "MARK", Mark: 15, SourceGroup: "whitelist"},
			wantErr: "port_range",
		},
		{
			name:    "白名单方向非法",
			f:       Fields{Action: "MARK", Mark: 15, Protocol: "TCP", SourceGroup: "whitelist", PortRange: "8080", Direction: "OUTPUT"},
			wantErr: "FORWARD",
		},
		{
			name:    "纯打标(无白名单)",
			f:       Fields{Action: "MARK", Mark: 255, Protocol: "TCP", PortRange: "8080"},
			wantErr: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateFields(tc.f)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("期望通过,got: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("期望错误含 %q,got: %v", tc.wantErr, err)
			}
		})
	}
}

func TestValidateFields_MarkValue(t *testing.T) {
	if err := ValidateFields(Fields{Action: "MARK", Mark: 16}); err == nil {
		t.Fatal("mark=16 应被拒绝(仅允许 15/255)")
	}
	if err := ValidateFields(Fields{Action: "MARK", Mark: 15, Protocol: "TCP", PortRange: "8080"}); err != nil {
		t.Fatalf("mark=15 纯打标应通过,got: %v", err)
	}
	if err := ValidateFields(Fields{Action: "ACCEPT", MatchMark: 99}); err == nil {
		t.Fatal("match_mark=99 应被拒绝(仅允许 0/15/255)")
	}
}

func TestValidateFields_PortRangeRequiresProtocol(t *testing.T) {
	if err := ValidateFields(Fields{Action: "ACCEPT", PortRange: "8080"}); err == nil {
		t.Fatal("port_range 无 protocol 应被拒绝")
	}
	if err := ValidateFields(Fields{Action: "ACCEPT", Protocol: "TCP", PortRange: "8080"}); err != nil {
		t.Fatalf("port_range+protocol 应通过,got: %v", err)
	}
}

func TestValidateFields_NatRequiresNatTo(t *testing.T) {
	if err := ValidateFields(Fields{Action: "DNAT"}); err == nil {
		t.Fatal("DNAT 无 nat_to 应被拒绝")
	}
	if err := ValidateFields(Fields{Action: "SNAT", NatTo: "203.0.113.1"}); err != nil {
		t.Fatalf("SNAT+nat_to 应通过,got: %v", err)
	}
}
