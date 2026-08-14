package server

import (
	"encoding/json"
	"reflect"
	"testing"
)

// TestNormalizeMembers_IPRange: IP 范围语法(IP1-IP2)在规范化时展开为每个具体 IP。
func TestNormalizeMembers_IPRange(t *testing.T) {
	got := normalizeMembers([]string{"192.168.80.248-192.168.80.250"})
	want := []string{"192.168.80.248/32", "192.168.80.249/32", "192.168.80.250/32"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v\nwant %v", got, want)
	}
}

// TestNormalizeMembers_MixedRangeAndSingle: 范围与裸 IP 混合,范围展开为每个 IP + 裸 IP 补 /32。
func TestNormalizeMembers_MixedRangeAndSingle(t *testing.T) {
	got := normalizeMembers([]string{"192.168.80.248-192.168.80.249", "10.0.0.1", "  "})
	want := []string{"192.168.80.248/32", "192.168.80.249/32", "10.0.0.1/32"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v\nwant %v", got, want)
	}
}

// TestNormalizeMembers_LegacyCIDRAndIP: 原逻辑不破坏 -- CIDR 直通,裸 IP 补 /32。
func TestNormalizeMembers_LegacyCIDRAndIP(t *testing.T) {
	got := normalizeMembers([]string{"10.0.0.0/24", "10.0.0.1"})
	want := []string{"10.0.0.0/24", "10.0.0.1/32"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v\nwant %v", got, want)
	}
}

// TestValidateAddressGroupInput_IPRange: 范围语法校验 -- 合法/反转/跨族/非法IP/缺端。
func TestValidateAddressGroupInput_IPRange(t *testing.T) {
	cases := []struct {
		name    string
		members []string
		wantErr bool
	}{
		{"合法范围", []string{"192.168.80.130-192.168.80.180"}, false},
		{"合法范围_单IP两端", []string{"10.0.0.1-10.0.0.1"}, false},
		{"范围与CIDR混合", []string{"10.0.0.0/24", "192.168.1.10-192.168.1.20"}, false},
		{"反转_start大于end", []string{"192.168.80.180-192.168.80.130"}, true},
		{"跨族_v4到v6", []string{"10.0.0.1-::1"}, true},
		{"非法IP", []string{"192.168.80.300-192.168.80.180"}, true},
		{"缺end", []string{"192.168.80.130-"}, true},
		{"缺start", []string{"-192.168.80.130"}, true},
		{"多段_非法", []string{"1.2.3.4-5.6.7.8-9.10.11.12"}, true},
		{"范围过大_1280IP", []string{"10.0.0.0-10.0.4.255"}, true},
		{"范围等于上限_1024IP", []string{"10.0.0.0-10.0.3.255"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := addressGroupInput{Name: "g1", Kind: "custom", Members: tc.members}
			err := validateAddressGroupInput(in)
			if tc.wantErr && err == nil {
				t.Fatalf("期望校验失败, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("期望校验通过, got %v", err)
			}
		})
	}
}

// TestCreateAddressGroup_IPRange 端到端:POST 含范围语法的 members,返回展开后的每个 IP。
func TestCreateAddressGroup_IPRange(t *testing.T) {
	_, h := newTestGDB(t)
	body := `{"name":"ops","kind":"custom","members":["192.168.80.248-192.168.80.250"]}`
	w := postJSON(t, h, "POST", "/api/v1/address-groups", body)
	if w.Code != 201 {
		t.Fatalf("status: got %d, want 201, body=%s", w.Code, w.Body.String())
	}
	var res struct {
		Members []string `json:"members"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	want := []string{"192.168.80.248/32", "192.168.80.249/32", "192.168.80.250/32"}
	if !reflect.DeepEqual(res.Members, want) {
		t.Fatalf("members: got %v\nwant %v", res.Members, want)
	}
}

// TestCreateAddressGroup_InvalidRange: 非法范围 -> 400。
func TestCreateAddressGroup_InvalidRange(t *testing.T) {
	_, h := newTestGDB(t)
	body := `{"name":"bad","kind":"custom","members":["192.168.80.180-192.168.80.130"]}`
	w := postJSON(t, h, "POST", "/api/v1/address-groups", body)
	if w.Code != 400 {
		t.Fatalf("status: got %d, want 400, body=%s", w.Code, w.Body.String())
	}
}
