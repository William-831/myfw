package server

import (
	"math/big"
	"net/netip"
)

// ipRangeMaxIPs 单个 IP 范围展开的最大 IP 数。范围是便捷输入,超出上限提示改用 CIDR,
// 避免大段范围展开成海量 /32 条目(如 /8 段将产生 1600 万条)拖垮存储与 ipset。
const ipRangeMaxIPs = 1024

// rangeToIPs 将 IP 范围 [start, end] 展开为每个具体 IP 的 /32(IPv4)/128(IPv6)列表。
// start/end 须同族;start > end、跨族或范围超 ipRangeMaxIPs 返回 nil。
//
// 设计:范围是"批量为少量连续 IP 建档"的便捷语法,展开为每个 IP 而非 CIDR 压缩——
// 用户可直观看到范围内每个 IP 都被加入,避免 CIDR 合并(如 248/31)下中间 IP
// 不单独呈现造成的"没加进去"误解。ipset hash:net 存储 /32 完全支持。
func rangeToIPs(start, end netip.Addr) []string {
	start = start.Unmap()
	end = end.Unmap()
	if start.Is4() != end.Is4() {
		return nil
	}
	s := addrBig(start)
	e := addrBig(end)
	if s.Cmp(e) > 0 {
		return nil
	}
	count := ipRangeSize(start, end)
	if count > ipRangeMaxIPs {
		return nil
	}
	is4 := start.Is4()
	out := make([]string, 0, int(count))
	one := big.NewInt(1)
	for s.Cmp(e) <= 0 {
		ip := addrFromBig(s, is4).String()
		if is4 {
			out = append(out, ip+"/32")
		} else {
			out = append(out, ip+"/128")
		}
		s.Add(s, one)
	}
	return out
}

// ipRangeSize 返回 [start, end] 的 IP 数(start > end 或跨族返回 0)。
func ipRangeSize(start, end netip.Addr) int64 {
	start = start.Unmap()
	end = end.Unmap()
	if start.Is4() != end.Is4() {
		return 0
	}
	s := addrBig(start)
	e := addrBig(end)
	if s.Cmp(e) > 0 {
		return 0
	}
	c := new(big.Int).Sub(new(big.Int).Set(e), s)
	c.Add(c, big.NewInt(1))
	if !c.IsInt64() {
		return 1 << 40 // 远大于 ipRangeMaxIPs,触发上限
	}
	return c.Int64()
}

// addrBig 把 netip.Addr 转 big.Int(大端字节序)。
func addrBig(a netip.Addr) *big.Int {
	return new(big.Int).SetBytes(a.AsSlice())
}

// addrFromBig 把 big.Int 还原为 netip.Addr,按 v4/v6 取 4/16 字节大端(高位补零)。
func addrFromBig(v *big.Int, is4 bool) netip.Addr {
	n := 16
	if is4 {
		n = 4
	}
	b := v.Bytes()
	if len(b) < n {
		padded := make([]byte, n)
		copy(padded[n-len(b):], b)
		b = padded
	}
	ip, _ := netip.AddrFromSlice(b)
	return ip
}
