package audit

import (
	"context"
	"encoding/json"
	"testing"

	gormlogger "gorm.io/gorm/logger"

	"iptables-tool/internal/db"
	"iptables-tool/internal/model"
)

// TestDashboardDriftClassified 验证仪表盘 drift 分类统计:
// node.drift.classified 审计按 detail.source 聚合为 external_tamper/rule_removed/restart_loss/unspecified,
// 与运行时 node.drift 总数(drift_count)区分,反映严重度。
func TestDashboardDriftClassified(t *testing.T) {
	gdb, err := db.Open(db.Config{
		Driver:       db.DriverSQLite,
		DSN:          "file::memory:?cache=shared",
		MaxOpenConns: 1,
		MaxIdleConns: 1,
		LogLevel:     gormlogger.Silent,
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.Migrate(gdb); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	s := New(gdb)
	mk := func(source string) {
		d, _ := json.Marshal(map[string]any{"source": source})
		if err := s.Write(context.Background(), model.AuditLog{
			Actor: "system", Action: "node.drift.classified", NodeID: "n1", Detail: string(d),
		}); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	mk("external_tamper")
	mk("external_tamper")
	mk("restart_loss")
	mk("rule_removed")
	mk("unknown_source") // 无法识别应归 unspecified

	stats, err := s.Dashboard(context.Background(), 7)
	if err != nil {
		t.Fatalf("dashboard: %v", err)
	}
	if got := stats.Summary["drift_external_tamper"]; got != 2 {
		t.Fatalf("drift_external_tamper 应为 2, got %d", got)
	}
	if got := stats.Summary["drift_restart_loss"]; got != 1 {
		t.Fatalf("drift_restart_loss 应为 1, got %d", got)
	}
	if got := stats.Summary["drift_rule_removed"]; got != 1 {
		t.Fatalf("drift_rule_removed 应为 1, got %d", got)
	}
	if got := stats.Summary["drift_unspecified"]; got != 1 {
		t.Fatalf("drift_unspecified 应为 1(unknown_source 归此类), got %d", got)
	}
}
