package server

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"iptables-tool/api/myfw/v1"
	"iptables-tool/internal/controller/stream"
	"iptables-tool/internal/model"
)

// TestDispatchConflictWhenNodeBusy 验证节点有 dispatching/applying 任务(执行中)时,
// 新 dispatch 返回 409(而非 500),提示任务执行中——保护期动作合并接管:执行中任务
// 不可作废,新动作被明确拒绝,避免 Agent 快照串台(2026-08-12)。
func TestDispatchConflictWhenNodeBusy(t *testing.T) {
	gdb := newRevisionTestDB(t)
	streamSvc := stream.New(gdb, slog.Default(), nil)
	h := BuildWebHandlerWithStream(gdb, time.Minute, streamSvc)
	// 注册假节点连接(dispatch 预检通过)
	send := make(chan *myfwv1.ControllerToAgent, 16)
	streamSvc.Reg.Register("n1", send)
	// 节点有 dispatching 任务(执行中,不可接管)
	if err := gdb.Create(&model.Task{
		ID: "t_busy", NodeID: "n1", Status: model.TaskDispatching, Version: time.Now().Unix(),
	}).Error; err != nil {
		t.Fatalf("create busy task: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/nodes/n1/dispatch", strings.NewReader(`{"auto_approve":true}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusConflict {
		t.Fatalf("节点执行中 dispatch 应 409, got %d body=%s", w.Code, w.Body.String())
	}
	// 在途任务应保持原状态(未被误作废/误下发)
	var busy model.Task
	if err := gdb.First(&busy, "id = ?", "t_busy").Error; err != nil {
		t.Fatalf("查 busy task: %v", err)
	}
	if busy.Status != model.TaskDispatching {
		t.Fatalf("执行中任务应保持 dispatching, got %s", busy.Status)
	}
}

// TestDispatchSupersedesOldConfirmWait 集成:节点有 confirm_wait 任务时,新 dispatch
// 自动接管——旧任务置 superseded,新任务进入保护期(节点已注册连接,dispatch 可成功)。
// 测试环境无真实 Agent 回包,新任务停留在 applying(等待结果),验证接管已生效。
func TestDispatchSupersedesOldConfirmWait(t *testing.T) {
	gdb := newRevisionTestDB(t)
	streamSvc := stream.New(gdb, slog.Default(), nil)
	h := BuildWebHandlerWithStream(gdb, time.Minute, streamSvc)
	send := make(chan *myfwv1.ControllerToAgent, 16)
	streamSvc.Reg.Register("n1", send)

	oldID := "t_old_wait"
	deadline := time.Now().Add(5 * time.Minute)
	if err := gdb.Create(&model.Task{
		ID: oldID, NodeID: "n1", Status: model.TaskConfirmWait, Version: time.Now().Unix(),
		ConfirmDeadline: &deadline,
	}).Error; err != nil {
		t.Fatalf("create old task: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/nodes/n1/dispatch", strings.NewReader(`{"auto_approve":true}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("dispatch 应 200, got %d body=%s", w.Code, w.Body.String())
	}
	var old model.Task
	if err := gdb.First(&old, "id = ?", oldID).Error; err != nil {
		t.Fatalf("查旧 task: %v", err)
	}
	if old.Status != model.TaskSuperseded {
		t.Fatalf("旧 confirm_wait 任务应被接管为 superseded, got %s", old.Status)
	}
	// 新任务已创建并尝试下发(节点注册连接,Send 成功 -> applying)
	var created []model.Task
	gdb.Where("node_id = ? AND id != ?", "n1", oldID).Find(&created)
	if len(created) != 1 {
		t.Fatalf("应创建 1 个新 task, got %d", len(created))
	}
	if created[0].Status != model.TaskApplying {
		t.Fatalf("新 task 应进入 applying(等 Agent 回包), got %s", created[0].Status)
	}
}
