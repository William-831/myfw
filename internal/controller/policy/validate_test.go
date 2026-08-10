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
			name:    "纯打标已废弃(无源)",
			f:       Fields{Action: "MARK", Mark: 255, Protocol: "TCP", PortRange: "8080"},
			wantErr: "源地址或源地址组",
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
	// mark 非零即可(不再硬编码 15/255,引用标记管理由 API 层校验),但必须非零:0 表示无标记
	if err := ValidateFields(Fields{Action: "MARK", Mark: 0, Protocol: "TCP", PortRange: "8080", Source: "10.0.0.0/24"}); err == nil {
		t.Fatal("mark=0(无标记)应被拒绝,MARK 打标值不可为 0")
	}
	// 任意非零值合法(非 15/255 的自定义标记也可用)
	if err := ValidateFields(Fields{Action: "MARK", Mark: 16, Protocol: "TCP", PortRange: "8080", Source: "10.0.0.0/24"}); err != nil {
		t.Fatalf("mark=16(非 15/255)应通过,got: %v", err)
	}
	if err := ValidateFields(Fields{Action: "MARK", Mark: 15, Protocol: "TCP", PortRange: "8080"}); err == nil {
		t.Fatal("mark=15 无源(纯打标)应被拒绝,MARK 需指定源")
	}
	// match_mark:0=不限,任意非零合法
	if err := ValidateFields(Fields{Action: "ACCEPT", MatchMark: 99}); err != nil {
		t.Fatalf("match_mark=99 应通过(任意非零),got: %v", err)
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
