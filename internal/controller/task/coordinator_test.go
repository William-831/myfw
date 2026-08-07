package task

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"iptables-tool/internal/controller/compiler"
	"iptables-tool/internal/controller/stream"
	"iptables-tool/internal/db"
	"iptables-tool/internal/model"
)

// newTestCoordinator 构造一个内存 SQLite + 真实 stream/compiler 的 Coordinator,
// 用于验证 Confirm/Rollback/autoRollback 对 pending_delete 实例的副作用。
// stream.Reg 已初始化,Send 到未连接节点会失败但属 best-effort,不影响 DB 操作。
func newTestCoordinator(t *testing.T) (*Coordinator, *gorm.DB) {
	t.Helper()
	gdb, err := db.Open(db.Config{
		Driver:       db.DriverSQLite,
		DSN:          "file::memory:",
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
	streamSvc := stream.New(gdb, slog.Default(), nil)
	comp := compiler.New(gdb)
	co := NewCoordinator(gdb, streamSvc, comp, nil, slog.Default())
	return co, gdb
}

// makeConfirmWaitTask 插入一个 confirm_wait 状态的 task,返回 taskID。
func makeConfirmWaitTask(t *testing.T, gdb *gorm.DB, nodeID string) string {
	t.Helper()
	taskID := "t_test_" + nodeID
	deadline := time.Now().Add(5 * time.Minute)
	if err := gdb.Create(&model.Task{
		ID: taskID, NodeID: nodeID, Status: model.TaskConfirmWait,
		Version: time.Now().Unix(), ConfirmDeadline: &deadline,
	}).Error; err != nil {
		t.Fatalf("create task: %v", err)
	}
	return taskID
}

// TestConfirmClearsPendingDelete 验证 Confirm 只清理关联本 task 的 pending_delete 实例,
// 不误伤同节点关联其他 task 的 pending_delete 实例。
func TestConfirmClearsPendingDelete(t *testing.T) {
	co, gdb := newTestCoordinator(t)
	ctx := context.Background()
	taskID := makeConfirmWaitTask(t, gdb, "n1")

	// 实例1:关联本 task,应被 Confirm 清理
	gdb.Create(&model.NodePolicyInstance{
		ID: 1, NodeID: "n1", Name: "to-delete",
		Enabled: false, Applied: false, PendingDelete: true, PendingDeleteTaskID: taskID,
	})
	// 实例2:关联别的 task,应保留
	gdb.Create(&model.NodePolicyInstance{
		ID: 2, NodeID: "n1", Name: "other-task",
		Enabled: false, Applied: false, PendingDelete: true, PendingDeleteTaskID: "t_other",
	})

	if _, err := co.Confirm(ctx, taskID, "reviewer"); err != nil {
		t.Fatalf("confirm: %v", err)
	}

	var inst1 model.NodePolicyInstance
	err1 := gdb.First(&inst1, 1).Error
	if !errors.Is(err1, gorm.ErrRecordNotFound) {
		t.Fatalf("实例1应被删除, got err=%v inst=%+v", err1, inst1)
	}
	var inst2 model.NodePolicyInstance
	if err := gdb.First(&inst2, 2).Error; err != nil {
		t.Fatalf("实例2应保留, err=%v", err)
	}
	if !inst2.PendingDelete || inst2.PendingDeleteTaskID != "t_other" {
		t.Fatalf("实例2状态被误改: %+v", inst2)
	}
}

// TestRollbackRestoresPendingDelete 验证 Rollback 恢复关联本 task 的 pending_delete 实例:
// 规则由 Agent 恢复快照,实例随之恢复启用、清除待删除标记。
func TestRollbackRestoresPendingDelete(t *testing.T) {
	co, gdb := newTestCoordinator(t)
	ctx := context.Background()
	taskID := makeConfirmWaitTask(t, gdb, "n2")

	gdb.Create(&model.NodePolicyInstance{
		ID: 1, NodeID: "n2", Name: "to-restore",
		Enabled: false, Applied: false, PendingDelete: true, PendingDeleteTaskID: taskID,
	})

	if _, err := co.Rollback(ctx, taskID, "reviewer"); err != nil {
		t.Fatalf("rollback: %v", err)
	}

	var inst model.NodePolicyInstance
	if err := gdb.First(&inst, 1).Error; err != nil {
		t.Fatalf("实例应保留(恢复而非删除): %v", err)
	}
	if !inst.Enabled || !inst.Applied || inst.PendingDelete || inst.PendingDeleteTaskID != "" {
		t.Fatalf("实例未恢复: enabled=%v applied=%v pending_delete=%v task_id=%q",
			inst.Enabled, inst.Applied, inst.PendingDelete, inst.PendingDeleteTaskID)
	}
}

// TestAutoRollbackRestoresPendingDelete 验证超时自动回滚同样恢复 pending_delete 实例。
func TestAutoRollbackRestoresPendingDelete(t *testing.T) {
	co, gdb := newTestCoordinator(t)
	taskID := makeConfirmWaitTask(t, gdb, "n3")

	gdb.Create(&model.NodePolicyInstance{
		ID: 1, NodeID: "n3", Name: "auto-restore",
		Enabled: false, Applied: false, PendingDelete: true, PendingDeleteTaskID: taskID,
	})

	co.autoRollback(taskID)

	var inst model.NodePolicyInstance
	if err := gdb.First(&inst, 1).Error; err != nil {
		t.Fatalf("实例应保留: %v", err)
	}
	if !inst.Enabled || !inst.Applied || inst.PendingDelete {
		t.Fatalf("实例未恢复: enabled=%v applied=%v pending_delete=%v",
			inst.Enabled, inst.Applied, inst.PendingDelete)
	}
	var tk model.Task
	if err := gdb.First(&tk, "id = ?", taskID).Error; err != nil {
		t.Fatalf("task 查询失败: %v", err)
	}
	if tk.Status != model.TaskRolledBack {
		t.Fatalf("task 状态应为 rolled_back, got %s", tk.Status)
	}
}
