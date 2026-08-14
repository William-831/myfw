package server

import (
	"net/netip"
	"reflect"
	"testing"
)

// TestRangeToIPs 覆盖 IP 范围展开为每个具体 IP(/32/128)的列表。
// 设计:范围是"批量为少量连续 IP 建档"的便捷语法,展开为每个 IP 而非 CIDR 压缩,
// 让用户直观看到范围内每个 IP 都被加入。
func TestRangeToIPs(t *testing.T) {
	cases := []struct {
		name  string
		start string
		end   string
		want  []string
	}{
		{
			name:  "单IP范围",
			start: "192.168.80.130", end: "192.168.80.130",
			want: []string{"192.168.80.130/32"},
		},
		{
			name:  "连续3个IP_248-250",
			start: "192.168.80.248", end: "192.168.80.250",
			want: []string{"192.168.80.248/32", "192.168.80.249/32", "192.168.80.250/32"},
		},
		{
			name:  "起始为零地址",
			start: "0.0.0.0", end: "0.0.0.2",
			want: []string{"0.0.0.0/32", "0.0.0.1/32", "0.0.0.2/32"},
		},
		{
			name:  "v6范围_::1-::3",
			start: "::1", end: "::3",
			want: []string{"::1/128", "::2/128", "::3/128"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := netip.MustParseAddr(tc.start)
			e := netip.MustParseAddr(tc.end)
			got := rangeToIPs(s, e)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("rangeToIPs(%s-%s):\n got %v\nwant %v", tc.start, tc.end, got, tc.want)
			}
			// 闭环校验:展开集合须完整覆盖 [start,end] 且不含范围外地址。
			verifyRangeCoverage(t, s, e, got)
		})
	}
}

// TestRangeToIPs_StartAfterEnd: start > end 返回 nil(非法范围,不展开)。
func TestRangeToIPs_StartAfterEnd(t *testing.T) {
	s := netip.MustParseAddr("10.0.0.10")
	e := netip.MustParseAddr("10.0.0.5")
	if got := rangeToIPs(s, e); got != nil {
		t.Fatalf("start>end 应返回 nil, got %v", got)
	}
}

// TestRangeToIPs_SizeLimit: 范围 IP 数上限保护——等于上限合法,超过返回 nil。
func TestRangeToIPs_SizeLimit(t *testing.T) {
	// 恰好 1024 个 IP(10.0.0.0-10.0.3.255)= 上限,合法
	start := netip.MustParseAddr("10.0.0.0")
	end := netip.MustParseAddr("10.0.3.255")
	if got := rangeToIPs(start, end); len(got) != ipRangeMaxIPs {
		t.Fatalf("1024 IP 范围应展开 %d 条, got %d", ipRangeMaxIPs, len(got))
	}
	// 1280 个 IP 超过上限 -> nil
	start = netip.MustParseAddr("10.0.0.0")
	end = netip.MustParseAddr("10.0.4.255")
	if got := rangeToIPs(start, end); got != nil {
		t.Fatalf("1280 IP 超上限应返回 nil, got %d 条", len(got))
	}
}

// verifyRangeCoverage 闭环校验:展开结果须完整覆盖 [start,end] 且不含范围外地址。
// 对范围内每个边界 IP(首尾 + 各条目边界)断言命中,对 start-1 / end+1 断言不命中。
func verifyRangeCoverage(t *testing.T, start, end netip.Addr, cidrs []string) {
	t.Helper()
	// 起止 IP 须命中
	if !hitAny(start, cidrs) {
		t.Errorf("start %s 应命中展开集合 %v", start, cidrs)
	}
	if !hitAny(end, cidrs) {
		t.Errorf("end %s 应命中展开集合 %v", end, cidrs)
	}
	// start 的前一个地址不应命中(若存在)
	if prev, ok := prevAddr(start); ok && hitAny(prev, cidrs) {
		t.Errorf("start 前一个地址 %s 不应命中, got %v", prev, cidrs)
	}
	// end 的后一个地址不应命中(若存在)
	if next, ok := nextAddr(end); ok && hitAny(next, cidrs) {
		t.Errorf("end 后一个地址 %s 不应命中, got %v", next, cidrs)
	}
}

func hitAny(ip netip.Addr, cidrs []string) bool {
	for _, c := range cidrs {
		pfx, err := netip.ParsePrefix(c)
		if err != nil {
			continue
		}
		if pfx.Contains(ip) {
			return true
		}
	}
	return false
}

// prevAddr/nextAddr 用 big.Int 做地址加减(测试辅助,不依赖被测实现)。
func prevAddr(a netip.Addr) (netip.Addr, bool) {
	b := a.AsSlice()
	for i := len(b) - 1; i >= 0; i-- {
		if b[i] > 0 {
			b[i]--
			if ip, ok := netip.AddrFromSlice(b); ok {
				return ip, true
			}
		}
		b[i] = 0xFF
	}
	return netip.Addr{}, false // 全 0 无前驱
}

func nextAddr(a netip.Addr) (netip.Addr, bool) {
	b := a.AsSlice()
	for i := len(b) - 1; i >= 0; i-- {
		if b[i] < 0xFF {
			b[i]++
			if ip, ok := netip.AddrFromSlice(b); ok {
				return ip, true
			}
		}
		b[i] = 0
	}
	return netip.Addr{}, false // 全 FF 无后继
}
