package stream

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	gormlogger "gorm.io/gorm/logger"

	myfwv1 "iptables-tool/api/myfw/v1"
	"iptables-tool/internal/controller/audit"
	"iptables-tool/internal/db"
	"iptables-tool/internal/model"
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

// TestSyncTriggersOnSyncCallback 验证 Agent 请求 sync(drift 恢复)时,Controller
// 调用 OnSync 回调触发重新下发。修复 drift 死循环:原 Sync case 只记日志不 Apply。
func TestSyncTriggersOnSyncCallback(t *testing.T) {
	svc := newTestService(t)
	var called atomic.Bool
	var gotNode string
	svc.OnSync = func(nodeID string) {
		gotNode = nodeID
		called.Store(true)
	}
	msg := &myfwv1.AgentToController{
		Payload: &myfwv1.AgentToController_Sync{
			Sync: &myfwv1.SyncRequest{Reason: "drift detected: expected X, got Y"},
		},
	}
	svc.handleUpstream(context.Background(), "n_drift", msg)
	if !called.Load() {
		t.Fatal("OnSync 回调应被调用(drift 恢复触发重新下发)")
	}
	if gotNode != "n_drift" {
		t.Fatalf("OnSync nodeID = %q, want n_drift", gotNode)
	}
}

// TestAuditDriftClassified 验证收到 drift 时:①同步写基础 node.drift 审计;
// ②异步分类(CompileExpected + DB 实际规则)补写 node.drift.classified,source 正确。
func TestAuditDriftClassified(t *testing.T) {
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
	svc := New(gdb, slog.Default(), audit.New(gdb))
	svc.CompileExpected = func(ctx context.Context, nodeID string) ([]*myfwv1.CompiledRule, error) {
		return []*myfwv1.CompiledRule{
			mkCR("FWD", myfwv1.Action_ACTION_ACCEPT, myfwv1.Protocol_PROTOCOL_TCP, "22", ""),
		}, nil
	}
	// 预置 actual:22 匹配 + 443 陌生规则
	gdb.Create(&model.IptablesRule{NodeID: "n_cls", TableType: "filter", Chain: "MYFW-FWD", RuleLine: "-A MYFW-FWD -p tcp --dport 22 -j ACCEPT", IsMYFW: true, Priority: 0})
	gdb.Create(&model.IptablesRule{NodeID: "n_cls", TableType: "filter", Chain: "MYFW-FWD", RuleLine: "-A MYFW-FWD -p tcp --dport 443 -j ACCEPT", IsMYFW: true, Priority: 1})

	msg := &myfwv1.AgentToController{
		Payload: &myfwv1.AgentToController_Drift{
			Drift: &myfwv1.DriftReport{NodeId: "n_cls", ExpectedHash: "e", ActualHash: "a", Detail: "external modification", TsUnix: 1},
		},
	}
	svc.handleUpstream(context.Background(), "n_cls", msg)

	// 等异步分类审计写入(轮询最多 3s)
	var log model.AuditLog
	deadline := time.Now().Add(3 * time.Second)
	for {
		if err := gdb.Where("action = ? AND node_id = ?", "node.drift.classified", "n_cls").Order("id DESC").First(&log).Error; err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("异步分类审计未在 3s 内写入")
		}
		time.Sleep(50 * time.Millisecond)
	}
	var d struct {
		Source string `json:"source"`
	}
	if err := json.Unmarshal([]byte(log.Detail), &d); err != nil {
		t.Fatalf("unmarshal detail: %v", err)
	}
	if d.Source != DriftSourceExternalTamper {
		t.Fatalf("分类应为 external_tamper(陌生规则 443), got %q detail=%s", d.Source, log.Detail)
	}
	// 基础 node.drift 审计同步写入
	var cnt int64
	gdb.Model(&model.AuditLog{}).Where("action = ? AND node_id = ?", "node.drift", "n_cls").Count(&cnt)
	if cnt == 0 {
		t.Fatal("基础 node.drift 审计应同步写入")
	}
}
