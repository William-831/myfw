package stream

import (
	"context"
	"log/slog"
	"testing"

	gormlogger "gorm.io/gorm/logger"

	myfwv1 "iptables-tool/api/myfw/v1"
	"iptables-tool/internal/db"
)

// newTestService 构建带内存 SQLite 的 stream.Service（SendDecommission 下发逻辑不依赖 DB，
// 仅为保持 New 的契约完整）。
func newTestService(t *testing.T) *Service {
	t.Helper()
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
	return New(gdb, slog.Default(), nil)
}

// TestSendDecommissionOnline 在线节点：消息下发到 Agent 流，reason 正确传递。
func TestSendDecommissionOnline(t *testing.T) {
	svc := newTestService(t)
	ch := make(chan *myfwv1.ControllerToAgent, 1)
	svc.Reg.Register("n_online", ch)

	if err := svc.SendDecommission(context.Background(), "n_online", "node deleted"); err != nil {
		t.Fatalf("SendDecommission: %v", err)
	}
	msg := <-ch
	if got := msg.GetDecommission().GetReason(); got != "node deleted" {
		t.Fatalf("reason mismatch: got %q", got)
	}
}

// TestSendDecommissionOffline 离线节点：返回错误（DELETE 路由忽略，Agent 端自毁兜底）。
func TestSendDecommissionOffline(t *testing.T) {
	svc := newTestService(t)
	if err := svc.SendDecommission(context.Background(), "n_offline", "node deleted"); err == nil {
		t.Fatal("离线节点应返回 not connected 错误")
	}
}
