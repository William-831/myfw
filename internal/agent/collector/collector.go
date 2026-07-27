package collector

import (
	"context"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	myfwv1 "iptables-tool/api/myfw/v1"
)

type Stats struct {
	CPUUsagePercent float64
	MemUsageBytes   int64
	MemTotalBytes   int64
	NetStats        []*NetStat
	ConnCount       int
	RuleHits        map[string]int64
}

type NetStat struct {
	Interface string
	RxBytes   int64
	TxBytes   int64
	RxPackets int64
	TxPackets int64
}

type Collector struct {
	Interval time.Duration
	Log      Logger
}

type Logger interface {
	Info(msg string, args ...any)
	Error(msg string, args ...any)
}

func New(interval time.Duration, log Logger) *Collector {
	return &Collector{
		Interval: interval,
		Log:      log,
	}
}

func (c *Collector) Start(ctx context.Context, reportCh chan<- *myfwv1.StateReport) {
	ticker := time.NewTicker(c.Interval)
	defer ticker.Stop()
	c.collectAndReport(reportCh)
	for {
		select {
		case <-ticker.C:
			c.collectAndReport(reportCh)
		case <-ctx.Done():
			return
		}
	}
}

func (c *Collector) collectAndReport(ch chan<- *myfwv1.StateReport) {
	stats, err := c.Collect()
	if err != nil {
		c.Log.Error("collect stats failed", "error", err)
		return
	}
	select {
	case ch <- c.toProto(stats):
	default:
		c.Log.Error("stats channel full, dropping")
	}
}

func (c *Collector) Collect() (*Stats, error) {
	stats := &Stats{
		RuleHits: map[string]int64{},
	}
	if runtime.GOOS != "linux" {
		return stats, nil
	}
	if err := c.collectCPU(stats); err != nil {
		c.Log.Error("collect CPU failed", "error", err)
	}
	if err := c.collectMemory(stats); err != nil {
		c.Log.Error("collect memory failed", "error", err)
	}
	if err := c.collectNetwork(stats); err != nil {
		c.Log.Error("collect network failed", "error", err)
	}
	if err := c.collectConnections(stats); err != nil {
		c.Log.Error("collect connections failed", "error", err)
	}
	return stats, nil
}

func (c *Collector) collectCPU(stats *Stats) error {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return err
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "cpu ") {
			fields := strings.Fields(line)
			if len(fields) < 5 {
				continue
			}
			total := int64(0)
			for i := 1; i < len(fields); i++ {
				v, _ := strconv.ParseInt(fields[i], 10, 64)
				total += v
			}
			idle, _ := strconv.ParseInt(fields[4], 10, 64)
			if total > 0 {
				stats.CPUUsagePercent = 100.0 - (float64(idle) / float64(total) * 100.0)
			}
			break
		}
	}
	return nil
}

func (c *Collector) collectMemory(stats *Stats) error {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return err
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				v, _ := strconv.ParseInt(fields[1], 10, 64)
				stats.MemTotalBytes = v * 1024
			}
		}
		if strings.HasPrefix(line, "MemAvailable:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				v, _ := strconv.ParseInt(fields[1], 10, 64)
				stats.MemUsageBytes = stats.MemTotalBytes - v*1024
			}
		}
	}
	return nil
}

func (c *Collector) collectNetwork(stats *Stats) error {
	dir, err := os.Open("/proc/net/dev")
	if err != nil {
		return err
	}
	defer dir.Close()
	data, err := io.ReadAll(dir)
	if err != nil {
		return err
	}
	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		if i < 2 {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 17 {
			continue
		}
		iface := strings.TrimSuffix(parts[0], ":")
		if iface == "lo" {
			continue
		}
		rxBytes, _ := strconv.ParseInt(parts[1], 10, 64)
		rxPackets, _ := strconv.ParseInt(parts[2], 10, 64)
		txBytes, _ := strconv.ParseInt(parts[9], 10, 64)
		txPackets, _ := strconv.ParseInt(parts[10], 10, 64)
		stats.NetStats = append(stats.NetStats, &NetStat{
			Interface: iface,
			RxBytes:   rxBytes,
			TxBytes:   txBytes,
			RxPackets: rxPackets,
			TxPackets: txPackets,
		})
	}
	return nil
}

func (c *Collector) collectConnections(stats *Stats) error {
	dir, err := os.Open("/proc/net/tcp")
	if err != nil {
		return err
	}
	defer dir.Close()
	data, err := io.ReadAll(dir)
	if err != nil {
		return err
	}
	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		if i == 0 {
			continue
		}
		if strings.TrimSpace(line) != "" {
			stats.ConnCount++
		}
	}
	dir6, err := os.Open("/proc/net/tcp6")
	if err != nil {
		return nil
	}
	defer dir6.Close()
	data6, err := io.ReadAll(dir6)
	if err != nil {
		return err
	}
	lines6 := strings.Split(string(data6), "\n")
	for i, line := range lines6 {
		if i == 0 {
			continue
		}
		if strings.TrimSpace(line) != "" {
			stats.ConnCount++
		}
	}
	return nil
}

func (c *Collector) toProto(s *Stats) *myfwv1.StateReport {
	ifaces := make([]*myfwv1.InterfaceStat, len(s.NetStats))
	for i, ns := range s.NetStats {
		ifaces[i] = &myfwv1.InterfaceStat{
			Name:      ns.Interface,
			RxBytes:   uint64(ns.RxBytes),
			TxBytes:   uint64(ns.TxBytes),
			RxPackets: uint64(ns.RxPackets),
			TxPackets: uint64(ns.TxPackets),
		}
	}
	return &myfwv1.StateReport{
		TsUnix:       time.Now().Unix(),
		Interfaces:   ifaces,
		ConntrackCount: uint64(s.ConnCount),
	}
}

func (c *Collector) SetRuleHits(hits map[string]int64) {
	c.Log.Info("rule hits updated", "count", len(hits))
}

// CollectIptablesRulesForHTTP 为 HTTP API 收集 iptables 规则
func (c *Collector) CollectIptablesRulesForHTTP() (map[string]map[string][]string, error) {
	if runtime.GOOS != "linux" {
		return nil, nil
	}

	result := make(map[string]map[string][]string)
	tables := []string{"filter", "nat", "mangle", "raw"}

	for _, table := range tables {
		cmd := exec.Command("iptables", "-t", table, "-S")
		output, err := cmd.CombinedOutput()
		if err != nil {
			continue
		}

		lines := strings.Split(string(output), "\n")
		currentChain := ""
		var rules []string

		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}

			if strings.HasPrefix(line, "-N ") || strings.HasPrefix(line, "-P ") {
				if currentChain != "" && len(rules) > 0 {
					if result[table] == nil {
						result[table] = make(map[string][]string)
					}
					result[table][currentChain] = rules
				}
				parts := strings.SplitN(line, " ", 2)
				if len(parts) == 2 {
					currentChain = parts[1]
					rules = nil
				}
			} else if strings.HasPrefix(line, "-A ") {
				rules = append(rules, line)
			}
		}

		if currentChain != "" && len(rules) > 0 {
			if result[table] == nil {
				result[table] = make(map[string][]string)
			}
			result[table][currentChain] = rules
		}
	}

	return result, nil
}