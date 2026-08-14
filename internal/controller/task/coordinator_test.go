package task

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
	"google.golang.org/protobuf/encoding/protojson"

	myfwv1 "iptables-tool/api/myfw/v1"
	"iptables-tool/internal/controller/audit"
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

// TestCleanOrphanPendingDelete 验证启动孤儿清理:实例 pending_delete=true 但关联任务
// 已处于终态(非 confirm_wait)时按任务终态兜底——rolled_back 恢复实例 / confirmed 补删 /
// 任务缺失仅清标记;confirm_wait(保护期内)不动。
func TestCleanOrphanPendingDelete(t *testing.T) {
	co, gdb := newTestCoordinator(t)
	ctx := context.Background()

	// 场景1:任务 rolled_back(移除被回滚,规则已恢复) -> 实例恢复启用并清标记
	gdb.Create(&model.Task{ID: "t_rolled", NodeID: "n1", Status: model.TaskRolledBack, Version: time.Now().Unix()})
	gdb.Create(&model.NodePolicyInstance{
		ID: 1, NodeID: "n1", Name: "rolled", Enabled: false, Applied: false,
		PendingDelete: true, PendingDeleteTaskID: "t_rolled",
	})

	// 场景2:任务 confirmed(用户已确认移除但 DB 未清) -> 实例补删
	gdb.Create(&model.Task{ID: "t_confirmed", NodeID: "n1", Status: model.TaskConfirmed, Version: time.Now().Unix()})
	gdb.Create(&model.NodePolicyInstance{
		ID: 2, NodeID: "n1", Name: "confirmed", Enabled: false, Applied: false,
		PendingDelete: true, PendingDeleteTaskID: "t_confirmed",
	})

	// 场景3:任务不存在(孤儿) -> 仅清标记,enabled 保持现值
	gdb.Create(&model.NodePolicyInstance{
		ID: 3, NodeID: "n1", Name: "missing-task", Enabled: false, Applied: true,
		PendingDelete: true, PendingDeleteTaskID: "t_gone",
	})

	// 场景4:任务 confirm_wait(保护期内) -> 不动
	taskID := makeConfirmWaitTask(t, gdb, "n1")
	gdb.Create(&model.NodePolicyInstance{
		ID: 4, NodeID: "n1", Name: "in-flight", Enabled: false, Applied: false,
		PendingDelete: true, PendingDeleteTaskID: taskID,
	})

	if err := co.cleanOrphanPendingDelete(ctx); err != nil {
		t.Fatalf("clean orphan: %v", err)
	}

	// 场景1:恢复启用 + 清标记
	var inst1 model.NodePolicyInstance
	if err := gdb.First(&inst1, 1).Error; err != nil {
		t.Fatalf("实例1应保留: %v", err)
	}
	if !inst1.Enabled || !inst1.Applied || inst1.PendingDelete || inst1.PendingDeleteTaskID != "" {
		t.Fatalf("实例1(rolled_back)应恢复启用清标记, got %+v", inst1)
	}

	// 场景2:补删
	if err := gdb.First(&model.NodePolicyInstance{}, 2).Error; !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("实例2(confirmed)应被删除, got err=%v", err)
	}

	// 场景3:清标记,enabled 保持 false
	var inst3 model.NodePolicyInstance
	if err := gdb.First(&inst3, 3).Error; err != nil {
		t.Fatalf("实例3应保留: %v", err)
	}
	if inst3.PendingDelete || inst3.PendingDeleteTaskID != "" || inst3.Enabled {
		t.Fatalf("实例3(任务缺失)应仅清标记且保持 enabled=false, got %+v", inst3)
	}

	// 场景4:不动
	var inst4 model.NodePolicyInstance
	if err := gdb.First(&inst4, 4).Error; err != nil {
		t.Fatalf("实例4应保留: %v", err)
	}
	if !inst4.PendingDelete || inst4.PendingDeleteTaskID != taskID {
		t.Fatalf("实例4(confirm_wait)不应被清理, got %+v", inst4)
	}
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

// --- 保护期动作合并接管(2026-08-12)-------------------------------------------

// TestSupersedeInFlight_ConfirmWaitTask 验证接管 confirm_wait 任务:
// 旧任务置 superseded + message 记录接管者 + 旧任务不再在途(HasInFlight=false)。
func TestSupersedeInFlight_ConfirmWaitTask(t *testing.T) {
	co, gdb := newTestCoordinator(t)
	co.Audit = audit.New(gdb)
	ctx := context.Background()
	oldID := makeConfirmWaitTask(t, gdb, "n1")

	superseded, err := co.SupersedeInFlight(ctx, "n1", "t_new", "admin", "开关切换接管")
	if err != nil {
		t.Fatalf("supersede: %v", err)
	}
	if len(superseded) != 1 || superseded[0].ID != oldID {
		t.Fatalf("want 1 superseded task %s, got %+v", oldID, superseded)
	}
	var tk model.Task
	if err := gdb.First(&tk, "id = ?", oldID).Error; err != nil {
		t.Fatalf("查旧 task: %v", err)
	}
	if tk.Status != model.TaskSuperseded {
		t.Fatalf("旧任务应为 superseded, got %s", tk.Status)
	}
	if !strings.Contains(tk.Message, "t_new") {
		t.Fatalf("message 应记录接管者, got %q", tk.Message)
	}
	if co.HasInFlight("n1") {
		t.Fatal("superseded 为终态,节点不应再在途")
	}
	// 审计串联:应有 task.superseded 记录
	var logs []model.AuditLog
	gdb.Where("task_id = ? AND action = ?", oldID, "task.superseded").Find(&logs)
	if len(logs) == 0 {
		t.Fatal("缺少 task.superseded 审计记录")
	}
}

// TestSupersedeInFlight_ConfirmWaitRemovalRestoresInstance 验证接管的是移除任务时,
// 其关联的 pending_delete 实例恢复启用(新动作重新决定其去留)。
func TestSupersedeInFlight_ConfirmWaitRemovalRestoresInstance(t *testing.T) {
	co, gdb := newTestCoordinator(t)
	ctx := context.Background()
	oldID := makeConfirmWaitTask(t, gdb, "n1")
	gdb.Create(&model.NodePolicyInstance{
		ID: 1, NodeID: "n1", Name: "rm", Enabled: false, Applied: false,
		PendingDelete: true, PendingDeleteTaskID: oldID,
	})

	if _, err := co.SupersedeInFlight(ctx, "n1", "t_new", "admin", "接管"); err != nil {
		t.Fatalf("supersede: %v", err)
	}
	var inst model.NodePolicyInstance
	if err := gdb.First(&inst, 1).Error; err != nil {
		t.Fatalf("实例应保留(恢复): %v", err)
	}
	if !inst.Enabled || inst.PendingDelete || inst.PendingDeleteTaskID != "" {
		t.Fatalf("旧移除实例应恢复启用清标记, got %+v", inst)
	}
}

// TestSupersedeInFlight_PendingApprovalTask 验证接管 pending_approval 任务(未下发,无 Agent 快照)。
func TestSupersedeInFlight_PendingApprovalTask(t *testing.T) {
	co, gdb := newTestCoordinator(t)
	ctx := context.Background()
	oldID := "t_pend_old"
	if err := gdb.Create(&model.Task{
		ID: oldID, NodeID: "n1", Status: model.TaskPendingApproval, Version: time.Now().Unix(),
	}).Error; err != nil {
		t.Fatalf("create task: %v", err)
	}

	if _, err := co.SupersedeInFlight(ctx, "n1", "t_new", "admin", "接管"); err != nil {
		t.Fatalf("supersede: %v", err)
	}
	var tk model.Task
	if err := gdb.First(&tk, "id = ?", oldID).Error; err != nil {
		t.Fatalf("查旧 task: %v", err)
	}
	if tk.Status != model.TaskSuperseded {
		t.Fatalf("pending_approval 旧任务应为 superseded, got %s", tk.Status)
	}
}

// TestSupersedeInFlight_DispatchingRejected 验证节点有 dispatching/applying 任务(执行中)
// 时拒绝接管,新动作应返回错误由调用方转 409。
func TestSupersedeInFlight_DispatchingRejected(t *testing.T) {
	co, gdb := newTestCoordinator(t)
	ctx := context.Background()
	for _, st := range []model.TaskStatus{model.TaskDispatching, model.TaskApplying} {
		gdb.Create(&model.Task{ID: "t_" + string(st), NodeID: "n1", Status: st, Version: time.Now().Unix()})
	}
	if _, err := co.SupersedeInFlight(ctx, "n1", "t_new", "admin", "接管"); err == nil {
		t.Fatal("节点有 dispatching/applying 任务时应拒绝接管")
	}
	// 在途任务应保持原状态(未被误作废)
	var tk model.Task
	gdb.First(&tk, "id = ?", "t_"+string(model.TaskDispatching))
	if tk.Status != model.TaskDispatching {
		t.Fatalf("dispatching 任务不应被改动, got %s", tk.Status)
	}
}

// TestSupersedeInFlight_NoInflightNoop 验证节点无在途任务时为空操作(不报错、不产生任务)。
func TestSupersedeInFlight_NoInflightNoop(t *testing.T) {
	co, gdb := newTestCoordinator(t)
	_ = gdb
	ctx := context.Background()
	superseded, err := co.SupersedeInFlight(ctx, "n_idle", "t_new", "admin", "接管")
	if err != nil {
		t.Fatalf("无在途不应报错: %v", err)
	}
	if len(superseded) != 0 {
		t.Fatalf("无在途应返回空列表, got %+v", superseded)
	}
}

// TestApproveDispatch_SupersedesConfirmWait 集成:节点已有 confirm_wait 任务时,
// 新任务 AutoApprove dispatch(approveAndDispatch)前置接管旧任务——旧任务 superseded,
// 新任务因测试环境节点未连接而 failed(失败可审计重试,旧任务已让路)。
func TestApproveDispatch_SupersedesConfirmWait(t *testing.T) {
	co, gdb := newTestCoordinator(t)
	co.Audit = audit.New(gdb)
	ctx := context.Background()
	oldID := makeConfirmWaitTask(t, gdb, "n1")

	// 新移除任务(与旧任务同节点)AutoApprove:dispatch 前应接管旧 confirm_wait
	gdb.Create(&model.NodePolicyInstance{ID: 1, NodeID: "n1", Name: "inst", Enabled: true, Applied: true})
	tsk, err := co.SubmitRemoval(ctx, 1, SubmitOpts{Author: "admin", AutoApprove: true})
	if err == nil {
		t.Fatal("测试环境节点未连接,dispatch 应失败(预期,验证旧任务已接管)")
	}
	if tsk == nil {
		t.Fatal("失败也应返回 task")
	}
	var old model.Task
	if err := gdb.First(&old, "id = ?", oldID).Error; err != nil {
		t.Fatalf("查旧 task: %v", err)
	}
	if old.Status != model.TaskSuperseded {
		t.Fatalf("旧 confirm_wait 任务应在新 dispatch 前被接管为 superseded, got %s", old.Status)
	}
}

// TestApproveDispatch_RecompilesRestoredInstance 验证 P1(2026-08-13 走查发现):
// 接管恢复的实例必须进入新任务的下发规则集。旧 confirm_wait 移除任务被接管时,
// restorePendingDelete 把实例 X 恢复为 enabled=true;若新 dispatch 的规则集基于接管前
// 状态编译(不含 X),DB 显示 X 已下发但节点实际无规则——确定性状态不一致。
// 修复:approveAndDispatch 在 SupersedeInFlight 后重新编译。
func TestApproveDispatch_RecompilesRestoredInstance(t *testing.T) {
	co, gdb := newTestCoordinator(t)
	ctx := context.Background()
	// 节点 + 启用组链(编译合法实例必需)
	if err := gdb.Create(&model.Node{ID: "n1", Status: model.NodeStatusActive, Hostname: "n1"}).Error; err != nil {
		t.Fatalf("create node: %v", err)
	}
	ch := model.CustomChain{Name: "acl-fwd", Parent: "MYFW-FORWARD", Table: "filter", Priority: 1, Enabled: true}
	if err := gdb.Create(&ch).Error; err != nil {
		t.Fatalf("create chain: %v", err)
	}
	gid := ch.ID
	// 旧 confirm_wait 移除任务 t_A,关联实例 X(pending_delete,节点上规则已被 -D)
	oldID := makeConfirmWaitTask(t, gdb, "n1")
	if err := gdb.Create(&model.NodePolicyInstance{
		ID: 1, NodeID: "n1", Name: "rm-x", GroupID: gid,
		Source: "10.1.0.0/24", Protocol: "TCP", PortRange: "80", Action: "DROP",
		Enabled: false, Applied: false, PendingDelete: true, PendingDeleteTaskID: oldID,
	}).Error; err != nil {
		t.Fatalf("create pending-delete instance: %v", err)
	}
	// Y:节点其他已启用实例(保证节点有可下发内容)
	if err := gdb.Create(&model.NodePolicyInstance{
		ID: 2, NodeID: "n1", Name: "keep-y", GroupID: gid,
		Source: "10.2.0.0/24", Protocol: "TCP", PortRange: "443", Action: "ACCEPT",
		Enabled: true, Applied: true,
	}).Error; err != nil {
		t.Fatalf("create enabled instance: %v", err)
	}
	// 注册节点连接,捕获下发消息
	send := make(chan *myfwv1.ControllerToAgent, 16)
	co.Stream.Reg.Register("n1", send)

	// 新 dispatch 接管旧移除任务
	if _, err := co.Submit(ctx, 0, []string{"n1"}, SubmitOpts{Author: "admin", AutoApprove: true}); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	// 从 send 通道收集 Apply 消息(SupersedeInFlight 先发旧任务 Confirm,再发新任务 Apply)
	var apply *myfwv1.ApplyTask
	end := time.Now().Add(2 * time.Second)
	for time.Now().Before(end) {
		select {
		case m := <-send:
			if a := m.GetApply(); a != nil {
				apply = a
			}
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}
	if apply == nil {
		t.Fatal("未收到新任务 Apply 消息")
	}
	hasX, hasY := false, false
	for _, r := range apply.RuleSet.Rules {
		if r.Action == myfwv1.Action_ACTION_DROP && r.Source == "10.1.0.0/24" {
			hasX = true
		}
		if r.Action == myfwv1.Action_ACTION_ACCEPT && r.Source == "10.2.0.0/24" {
			hasY = true
		}
	}
	if !hasY {
		t.Fatalf("已启用实例 Y 应在新任务规则集")
	}
	if !hasX {
		t.Fatalf("P1:接管恢复的实例 X 必须进入新任务下发规则集(当前编译基于接管前状态,节点将缺 X 规则)")
	}
}

// TestAutoRollback_LeavesSupersededUntouched 回归防护:任务已被接管(superseded)后,
// 定时器兜底 autoRollback 不得覆盖终态(防止旧任务回滚冲掉新动作结果)。CAS 条件更新
// 重构后仍须保持:autoRollback 只允许从 confirm_wait 转移。
func TestAutoRollback_LeavesSupersededUntouched(t *testing.T) {
	co, gdb := newTestCoordinator(t)
	ctx := context.Background()
	oldID := makeConfirmWaitTask(t, gdb, "n1")
	// 先接管
	if _, err := co.SupersedeInFlight(ctx, "n1", "t_new", "admin", "接管"); err != nil {
		t.Fatalf("supersede: %v", err)
	}
	co.autoRollback(oldID)
	var tk model.Task
	if err := gdb.First(&tk, "id = ?", oldID).Error; err != nil {
		t.Fatalf("查旧 task: %v", err)
	}
	if tk.Status != model.TaskSuperseded {
		t.Fatalf("autoRollback 不得覆盖已 superseded 任务, got %s", tk.Status)
	}
}


// apply 成功后直接 confirmed:不进入 confirm_wait、不 armRollbackTimer,
// 审计 scene 标记为 self_heal。这是修复 drift 自愈死循环的核心:
// 自愈任务不再走 5 分钟保护期,避免"自愈→超时回滚→再漂移"循环。
func TestHandleResultAutoConfirmSkipsConfirmWait(t *testing.T) {
	co, gdb := newTestCoordinator(t)
	co.Audit = audit.New(gdb)
	ctx := context.Background()

	taskID := "t_auto_confirm"
	if err := gdb.Create(&model.Task{
		ID: taskID, NodeID: "n1", Status: model.TaskApplying,
		AutoConfirm: true, Version: time.Now().Unix(),
	}).Error; err != nil {
		t.Fatalf("create task: %v", err)
	}

	co.handleResult(ctx, &myfwv1.TaskResult{TaskId: taskID, Ok: true, ResultHash: "sha256:ok"})

	var tk model.Task
	if err := gdb.First(&tk, "id = ?", taskID).Error; err != nil {
		t.Fatalf("task 查询失败: %v", err)
	}
	if tk.Status != model.TaskConfirmed {
		t.Fatalf("AutoConfirm 任务 apply 成功后应直接 confirmed, got %s", tk.Status)
	}
	if tk.ResultHash != "sha256:ok" {
		t.Fatalf("result_hash 未记录: %q", tk.ResultHash)
	}

	// 审计应含 scene=self_heal 的 applying_ok 记录
	var logs []model.AuditLog
	if err := gdb.Where("task_id = ?", taskID).Find(&logs).Error; err != nil {
		t.Fatalf("查审计失败: %v", err)
	}
	foundSelfHeal := false
	for _, l := range logs {
		if l.Action == "task.applying_ok" && l.Scene == model.AuditSceneSelfHeal {
			foundSelfHeal = true
		}
		if l.Scene != model.AuditSceneSelfHeal {
			t.Fatalf("AutoConfirm 任务审计 scene 应全为 self_heal, got %q (action=%s)", l.Scene, l.Action)
		}
	}
	if !foundSelfHeal {
		t.Fatal("缺少 scene=self_heal 的 task.applying_ok 审计记录")
	}
}

// TestHandleResultNormalStillUsesConfirmWait 验证普通任务(AutoConfirm=false)apply
// 成功后仍进 confirm_wait 保护期——确认改动只影响自愈任务,不破坏人工保护期语义。
func TestHandleResultNormalStillUsesConfirmWait(t *testing.T) {
	co, gdb := newTestCoordinator(t)
	co.Audit = audit.New(gdb)
	ctx := context.Background()

	taskID := "t_normal"
	if err := gdb.Create(&model.Task{
		ID: taskID, NodeID: "n1", Status: model.TaskApplying,
		AutoConfirm: false, Version: time.Now().Unix(),
	}).Error; err != nil {
		t.Fatalf("create task: %v", err)
	}

	co.handleResult(ctx, &myfwv1.TaskResult{TaskId: taskID, Ok: true, ResultHash: "sha256:ok"})

	var tk model.Task
	if err := gdb.First(&tk, "id = ?", taskID).Error; err != nil {
		t.Fatalf("task 查询失败: %v", err)
	}
	if tk.Status != model.TaskConfirmWait {
		t.Fatalf("普通任务 apply 成功后应进 confirm_wait, got %s", tk.Status)
	}
}

// TestHasInFlight 验证 HasInFlight 只在节点有未终态任务时返回 true,
// 用于 OnSync 去重(自愈下发不叠加)。
func TestHasInFlight(t *testing.T) {
	co, gdb := newTestCoordinator(t)
	ctx := context.Background()

	if co.HasInFlight("n_x") {
		t.Fatal("无任务节点不应视为在途")
	}
	makeConfirmWaitTask(t, gdb, "n_inflight")
	if !co.HasInFlight("n_inflight") {
		t.Fatal("confirm_wait 任务应视为在途")
	}
	// pending_approval 也应在途(漏洞 I 修复:自愈不与待审批人工任务叠加下发)
	if err := gdb.Create(&model.Task{
		ID: "t_pend", NodeID: "n_pend", Status: model.TaskPendingApproval,
		Version: time.Now().Unix(),
	}).Error; err != nil {
		t.Fatalf("create pending task: %v", err)
	}
	if !co.HasInFlight("n_pend") {
		t.Fatal("pending_approval 任务应视为在途")
	}
	_ = ctx
}

// TestHandleResultFailurePreservesDisabledInstances 验证 apply 失败时只回退本次涉及的
// enabled 实例 applied,不清零同节点 enabled=false 的稳定/待删实例(漏洞 J 修复)。
// 修复前:失败分支按 node_id 全量 Update applied=false,误伤别的 task 的待删实例。
func TestHandleResultFailurePreservesDisabledInstances(t *testing.T) {
	co, gdb := newTestCoordinator(t)
	ctx := context.Background()
	taskID := "t_fail"
	if err := gdb.Create(&model.Task{
		ID: taskID, NodeID: "n1", Status: model.TaskApplying, Version: time.Now().Unix(),
	}).Error; err != nil {
		t.Fatalf("create task: %v", err)
	}
	// 实例1:enabled=true,本次 task 编译涉及,失败应回退 applied=false
	gdb.Create(&model.NodePolicyInstance{ID: 1, NodeID: "n1", Name: "active", Enabled: true, Applied: true})
	// 实例2:enabled=false,applied=true,属另一 task 的待删实例,失败不应动它
	gdb.Create(&model.NodePolicyInstance{
		ID: 2, NodeID: "n1", Name: "pending-del",
		Enabled: false, Applied: true, PendingDelete: true, PendingDeleteTaskID: "t_other",
	})

	co.handleResult(ctx, &myfwv1.TaskResult{TaskId: taskID, Ok: false, Message: "apply error"})

	var inst1 model.NodePolicyInstance
	if err := gdb.First(&inst1, 1).Error; err != nil {
		t.Fatalf("查实例1: %v", err)
	}
	if inst1.Applied {
		t.Fatalf("实例1(本次涉及)失败后 applied 应回退 false")
	}
	var inst2 model.NodePolicyInstance
	if err := gdb.First(&inst2, 2).Error; err != nil {
		t.Fatalf("查实例2: %v", err)
	}
	if !inst2.Applied {
		t.Fatalf("实例2(待删)applied 被误清零,应保持 true")
	}
}

// TestHandleResultSuccessPreservesPendingDelete 验证 apply 成功时(漏洞 S 修复):
//   - enabled 实例 applied 置 true(本次下发生效);
//   - pending_delete 实例保持 applied=true(在它自己的移除保护期内,等 Confirm 清理或 Rollback 恢复);
//   - 手动禁用(非待删)实例 applied 置 false(节点上已被 desired-state 移除)。
func TestHandleResultSuccessPreservesPendingDelete(t *testing.T) {
	co, gdb := newTestCoordinator(t)
	ctx := context.Background()
	taskID := "t_success"
	if err := gdb.Create(&model.Task{
		ID: taskID, NodeID: "n1", Status: model.TaskApplying, Version: time.Now().Unix(),
	}).Error; err != nil {
		t.Fatalf("create task: %v", err)
	}
	// 实例1:enabled=true,本次下发,成功 -> applied=true
	gdb.Create(&model.NodePolicyInstance{ID: 1, NodeID: "n1", Name: "active", Enabled: true, Applied: false})
	// 实例2:enabled=false,applied=true,pending_delete=true,另一 task 移除保护期 -> 保持 applied=true
	gdb.Create(&model.NodePolicyInstance{
		ID: 2, NodeID: "n1", Name: "pending-del",
		Enabled: false, Applied: true, PendingDelete: true, PendingDeleteTaskID: "t_other",
	})
	// 实例3:enabled=false,applied=true,手动禁用待移除 -> applied 置 false
	gdb.Create(&model.NodePolicyInstance{ID: 3, NodeID: "n1", Name: "disabled", Enabled: false, Applied: true})

	co.handleResult(ctx, &myfwv1.TaskResult{TaskId: taskID, Ok: true, ResultHash: "h"})

	var inst1 model.NodePolicyInstance
	gdb.First(&inst1, 1)
	if !inst1.Applied {
		t.Fatalf("实例1(enabled)成功下发后 applied 应为 true")
	}
	var inst2 model.NodePolicyInstance
	gdb.First(&inst2, 2)
	if !inst2.Applied {
		t.Fatalf("实例2(pending_delete)applied 被误清零,应保持 true 直到本 task 终态")
	}
	var inst3 model.NodePolicyInstance
	gdb.First(&inst3, 3)
	if inst3.Applied {
		t.Fatalf("实例3(手动禁用)applied 应为 false")
	}
}

// TestRefreshNodePreview 验证 dispatch 审批时刷新预览(漏洞 F' 修复):
// 用节点最新实例状态重算 policy_name/change_type,且排除 pending_delete 实例
// (它们的移除由各自保护期 task 展示,不混入别的 dispatch 预览)。
func TestRefreshNodePreview(t *testing.T) {
	co, gdb := newTestCoordinator(t)
	ctx := context.Background()

	tk := &model.Task{ID: "t_prev", NodeID: "n1"}
	// 待下发:enabled=true,applied=false -> 应出现在预览
	gdb.Create(&model.NodePolicyInstance{ID: 1, NodeID: "n1", Name: "pend", Enabled: true, Applied: false})
	// 手动禁用待移除:enabled=false,applied=true -> 应显示 [禁用]
	gdb.Create(&model.NodePolicyInstance{ID: 2, NodeID: "n1", Name: "dis", Enabled: false, Applied: true})
	// pending_delete:enabled=false,applied=true,另一移除保护期 -> 应排除
	gdb.Create(&model.NodePolicyInstance{
		ID: 3, NodeID: "n1", Name: "pd",
		Enabled: false, Applied: true, PendingDelete: true, PendingDeleteTaskID: "t_other",
	})

	co.refreshNodePreview(ctx, tk)

	if !strings.Contains(tk.PolicyName, "pend") {
		t.Fatalf("policy_name 应含待下发实例名, got %q", tk.PolicyName)
	}
	if !strings.Contains(tk.PolicyName, "[禁用]dis") {
		t.Fatalf("policy_name 应含禁用实例名, got %q", tk.PolicyName)
	}
	if strings.Contains(tk.PolicyName, "pd") {
		t.Fatalf("policy_name 不应含 pending_delete 实例, got %q", tk.PolicyName)
	}
	if tk.ChangeType != "mixed" {
		t.Fatalf("change_type 应为 mixed, got %q", tk.ChangeType)
	}
}

// TestSubmitRemovalAtomicMarkAndTaskID 验证移除实例时 task 创建与实例 pending_delete 标记 +
// task_id 关联在同一事务完成(AutoApprove=false 路径不发 dispatch),杜绝崩溃致 pending_delete 无 task_id(漏洞 G 修复)。
func TestSubmitRemovalAtomicMarkAndTaskID(t *testing.T) {
	co, gdb := newTestCoordinator(t)
	ctx := context.Background()
	gdb.Create(&model.NodePolicyInstance{ID: 10, NodeID: "n1", Name: "rm", Enabled: true, Applied: true})

	tsk, err := co.SubmitRemoval(ctx, 10, SubmitOpts{Author: "tester", AutoApprove: false})
	if err != nil {
		t.Fatalf("SubmitRemoval: %v", err)
	}
	if tsk == nil || tsk.ID == "" {
		t.Fatal("task 未创建")
	}

	var inst model.NodePolicyInstance
	if err := gdb.First(&inst, 10).Error; err != nil {
		t.Fatalf("查实例: %v", err)
	}
	if !inst.PendingDelete {
		t.Fatal("实例应标记 pending_delete")
	}
	if inst.Enabled {
		t.Fatal("实例应置 enabled=false")
	}
	if inst.PendingDeleteTaskID != tsk.ID {
		t.Fatalf("实例 task_id 未关联: got %q want %q", inst.PendingDeleteTaskID, tsk.ID)
	}
	var tk model.Task
	if err := gdb.First(&tk, "id = ?", tsk.ID).Error; err != nil {
		t.Fatalf("查 task: %v", err)
	}
	if tk.Status != model.TaskPendingApproval {
		t.Fatalf("task 应为 pending_approval, got %s", tk.Status)
	}
}

// TestSubmitRemovalAutoApproveFailureRestores 验证 AutoApprove 移除在 dispatch 失败(节点未连接)时
// 恢复实例原状(enabled/pending_delete/task_id 复位),task 留 failed,不留半残态(漏洞 G 修复)。
func TestSubmitRemovalAutoApproveFailureRestores(t *testing.T) {
	co, gdb := newTestCoordinator(t)
	ctx := context.Background()
	gdb.Create(&model.NodePolicyInstance{ID: 11, NodeID: "n_disconnected", Name: "rm2", Enabled: true, Applied: true})

	tsk, err := co.SubmitRemoval(ctx, 11, SubmitOpts{Author: "tester", AutoApprove: true})
	if err == nil {
		t.Fatal("节点未连接 dispatch 应失败")
	}
	if tsk == nil {
		t.Fatal("失败也应返回 task")
	}

	var inst model.NodePolicyInstance
	if err := gdb.First(&inst, 11).Error; err != nil {
		t.Fatalf("查实例: %v", err)
	}
	if !inst.Enabled || inst.PendingDelete || inst.PendingDeleteTaskID != "" {
		t.Fatalf("实例应恢复原状: enabled=%v pending_delete=%v task_id=%q",
			inst.Enabled, inst.PendingDelete, inst.PendingDeleteTaskID)
	}
	var tk model.Task
	if err := gdb.First(&tk, "id = ?", tsk.ID).Error; err != nil {
		t.Fatalf("查 task: %v", err)
	}
	if tk.Status != model.TaskFailed {
		t.Fatalf("task 应为 failed, got %s", tk.Status)
	}
}

// TestSubmitRemoval_PreviewFilled 验证移除任务的保护期预览被完整填充:
// policy_name=实例名、change_type=disable、diff_after 含 -D 移除命令。
// 修复前:SubmitRemoval 创建任务只写死 policy_name="节点策略移除",change_type/diff_after 为空;
// approveAndDispatch 的 refreshNodePreview 走通用分支查 disabling(排除 pending_delete)
// 查不到本实例,change_type 被 fillNodeDispatchPreviewFromCache 的 default 分支覆盖为 "dispatch"
// —— 保护期面板显示"节点策略移除 + 下发待确认 + 无命令",与实际"移除"语义不符。
func TestSubmitRemoval_PreviewFilled(t *testing.T) {
	co, gdb := newTestCoordinator(t)
	ctx := context.Background()
	// MARK 白名单实例(源+端口+MARK)不需归属组链即可编译,便于断言 -D 命令生成
	gdb.Create(&model.NodePolicyInstance{
		ID: 12, NodeID: "n1", Name: "myrule",
		Source: "192.168.80.174", Destination: "192.168.80.248",
		Protocol: "TCP", PortRange: "222", Action: "MARK", Mark: 222,
		Priority: 10, Enabled: true, Applied: true,
	})

	tsk, err := co.SubmitRemoval(ctx, 12, SubmitOpts{Author: "tester", AutoApprove: true})
	if err == nil {
		t.Fatal("测试环境节点未连接 dispatch 应失败(预期,preview 已在 Send 前写入)")
	}
	if tsk == nil {
		t.Fatal("失败也应返回 task")
	}
	var tk model.Task
	if err := gdb.First(&tk, "id = ?", tsk.ID).Error; err != nil {
		t.Fatalf("查 task: %v", err)
	}
	if !strings.Contains(tk.PolicyName, "myrule") {
		t.Fatalf("policy_name 应含实例名(而非写死'节点策略移除'), got %q", tk.PolicyName)
	}
	if tk.ChangeType != "disable" {
		t.Fatalf("移除任务 change_type 应为 disable(不被误覆盖为 dispatch), got %q", tk.ChangeType)
	}
	if !strings.Contains(tk.DiffAfter, "-D") {
		t.Fatalf("diff_after 应含 -D 移除命令, got %q", tk.DiffAfter)
	}
}

// --- 规则库版本回滚链路(计划三)-----------------------------------------------

// TestSubmitRuleSet_StoresSnapshot 验证 SubmitRuleSet 创建携带 RuleSetSnapshot
// 的 task:回滚下发不重新编译,直接用历史规则集快照。
func TestSubmitRuleSet_StoresSnapshot(t *testing.T) {
	co, gdb := newTestCoordinator(t)
	ctx := context.Background()
	rs := &myfwv1.RuleSet{
		NodeId: "n1",
		Rules: []*myfwv1.CompiledRule{
			{Id: "i1", Chain: "acl-fwd", Action: myfwv1.Action_ACTION_ACCEPT},
		},
	}
	if _, err := co.SubmitRuleSet(ctx, "n1", rs, SubmitOpts{Author: "admin"}); err != nil {
		t.Fatalf("submit ruleset: %v", err)
	}
	var persisted model.Task
	if err := gdb.First(&persisted, "node_id = ?", "n1").Error; err != nil {
		t.Fatalf("查 task: %v", err)
	}
	if persisted.RuleSetSnapshot == "" {
		t.Fatal("want RuleSetSnapshot persisted")
	}
	var loaded myfwv1.RuleSet
	if err := protojson.Unmarshal([]byte(persisted.RuleSetSnapshot), &loaded); err != nil {
		t.Fatalf("unmarshal snapshot: %v", err)
	}
	if len(loaded.Rules) != 1 || loaded.Rules[0].Id != "i1" {
		t.Fatalf("snapshot rules mismatch: %+v", loaded.Rules)
	}
	if persisted.Status != model.TaskPendingApproval {
		t.Fatalf("want pending_approval, got %s", persisted.Status)
	}
	if persisted.ChangeType != "rollback" {
		t.Fatalf("want change_type=rollback, got %q", persisted.ChangeType)
	}
}

// TestHandleResult_RollbackTaskClearsApplied 验证回滚任务 apply 成功后
// 实例 applied 全置 false(规则已按历史版本收敛,与当前实例定义不一致,提示需重新下发)。
func TestHandleResult_RollbackTaskClearsApplied(t *testing.T) {
	co, gdb := newTestCoordinator(t)
	ctx := context.Background()
	gdb.Create(&model.NodePolicyInstance{ID: 1, NodeID: "n1", Name: "a", Enabled: true, Applied: true})
	gdb.Create(&model.Task{ID: "t_rb", NodeID: "n1", Status: model.TaskApplying,
		Version: time.Now().Unix(), RuleSetSnapshot: `{"rules":[]}`})

	co.handleResult(ctx, &myfwv1.TaskResult{TaskId: "t_rb", Ok: true})

	var inst model.NodePolicyInstance
	if err := gdb.First(&inst, 1).Error; err != nil {
		t.Fatalf("查实例: %v", err)
	}
	if inst.Applied {
		t.Fatal("回滚任务成功后实例 applied 必须清 false(规则已偏离当前定义)")
	}
}

// TestSubmitRuleSet_AutoApproveDispatches 冒烟:AutoApprove 走完整 dispatch 链路
// (节点未连接,dispatch 失败属预期,不应 panic)。
func TestSubmitRuleSet_AutoApproveDispatches(t *testing.T) {
	co, gdb := newTestCoordinator(t)
	rs := &myfwv1.RuleSet{NodeId: "n1", Rules: []*myfwv1.CompiledRule{{Id: "i1"}}}
	_, _ = co.SubmitRuleSet(context.Background(), "n1", rs, SubmitOpts{Author: "admin", AutoApprove: true})
	var task model.Task
	if err := gdb.First(&task, "node_id = ?", "n1").Error; err != nil {
		t.Fatalf("task not found: %v", err)
	}
	if task.Status == model.TaskPendingApproval || task.Status == model.TaskDispatching {
		t.Fatalf("AutoApprove 应已尝试 dispatch, got %s", task.Status)
	}
}
