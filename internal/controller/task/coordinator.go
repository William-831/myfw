// Package task also hosts the Coordinator: the persistent state machine for
// firewall changes (design.md § 11). The M6 Dispatcher was fire-and-forget
// with a synchronous wait; the Coordinator adds:
//
//  1. Persistence: every Apply creates a `tasks` row in PENDING_APPROVAL.
//  2. Approval gate: a task only dispatches once someone calls Approve.
//  3. Confirm-wait protection: after Apply succeeds on the Agent the task
//     moves to CONFIRM_WAIT and a timer is armed. If Confirm doesn't arrive
//     in time the Controller sends RollbackTask.
//  4. Startup recovery: on boot we scan CONFIRM_WAIT rows whose deadline is
//     in the past and roll them back.
//
// The Coordinator's public surface is small: Submit, Approve, Reject,
// Confirm, Get, List. Everything else (dispatch goroutines, timers,
// TaskResult subscribers) is internal.
package task

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
	"google.golang.org/protobuf/encoding/protojson"

	myfwv1 "iptables-tool/api/myfw/v1"
	"iptables-tool/internal/controller/audit"
	"iptables-tool/internal/controller/compiler"
	"iptables-tool/internal/controller/stream"
	"iptables-tool/internal/model"
)

// Coordinator owns the persistent Task state machine.
type Coordinator struct {
	DB     *gorm.DB
	Stream *stream.Service
	Comp   *compiler.Compiler
	Audit  *audit.Sink
	Log    *slog.Logger

	// DefaultConfirmDeadline is applied when a submit request doesn't override
	// it. Auto-rollback fires at this age of the task after apply completes.
	DefaultConfirmDeadline time.Duration

	// ArchiveFn 在普通任务 Apply 成功(节点规则已收敛)后调用,用于归档节点规则库版本
	// (计划三)。由 server 层注入 revision.Service.ArchiveApply;nil 表示不归档(测试)。
	ArchiveFn func(ctx context.Context, nodeID, taskID string) error

	// timers holds in-memory confirm-wait timers, keyed by task_id. Persisted
	// deadlines in `tasks.confirm_deadline` are the source of truth — timers
	// are just an in-memory optimisation so we don't sleep on the DB.
	tmu    sync.Mutex
	timers map[string]*time.Timer

	// results receives every TaskResult so we can move tasks forward when
	// the Agent reports back. Wired at Start().
	results   <-chan *myfwv1.TaskResult
	unsubFn   func()
	stopOnce  sync.Once
	stopCh    chan struct{}
	stoppedCh chan struct{}
}

func NewCoordinator(db *gorm.DB, s *stream.Service, c *compiler.Compiler, a *audit.Sink, log *slog.Logger) *Coordinator {
	if log == nil {
		log = slog.Default()
	}
	return &Coordinator{
		DB:                     db,
		Stream:                 s,
		Comp:                   c,
		Audit:                  a,
		Log:                    log,
		DefaultConfirmDeadline: 5 * time.Minute,
		timers:                 map[string]*time.Timer{},
		stopCh:                 make(chan struct{}),
		stoppedCh:              make(chan struct{}),
	}
}

// Start subscribes to TaskResults and launches the recovery + result loops.
// Non-blocking. Call Stop on shutdown.
func (co *Coordinator) Start(ctx context.Context) {
	results, unsub := co.Stream.SubscribeTaskResults()
	co.results = results
	co.unsubFn = unsub

	// Startup recovery: scan tasks that were mid-flight when we crashed.
	if err := co.recoverOnStart(ctx); err != nil {
		co.Log.Warn("task recovery on start failed", "err", err)
	}

	go co.resultLoop(ctx)
}

// Stop stops the background loops. Safe to call multiple times.
func (co *Coordinator) Stop() {
	co.stopOnce.Do(func() {
		close(co.stopCh)
		if co.unsubFn != nil {
			co.unsubFn()
		}
		<-co.stoppedCh
		// Cancel any live confirm timers.
		co.tmu.Lock()
		for _, t := range co.timers {
			t.Stop()
		}
		co.timers = map[string]*time.Timer{}
		co.tmu.Unlock()
	})
}

// SubmitOpts controls how Submit persists and (optionally) auto-approves.
type SubmitOpts struct {
	Author          string
	AutoApprove     bool          // if true, dispatch immediately without waiting for a reviewer
	AutoConfirm     bool          // 自愈任务:apply 成功后直接 confirmed,跳过 confirm_wait 保护期
	ConfirmDeadline time.Duration // overrides DefaultConfirmDeadline when >0
	Scene           string        // 审计场景,默认 AuditSceneNormal;drift 自愈传 AuditSceneSelfHeal
}

// Submit creates one Task per target node in PENDING_APPROVAL state. It does
// NOT dispatch yet — call Approve or set AutoApprove.
func (co *Coordinator) Submit(ctx context.Context, policyID uint, nodeIDs []string, opts SubmitOpts) ([]*model.Task, error) {
	if len(nodeIDs) == 0 {
		return nil, errors.New("task: no target nodes")
	}
	if opts.ConfirmDeadline <= 0 {
		opts.ConfirmDeadline = co.DefaultConfirmDeadline
	}
	if opts.Scene == "" {
		opts.Scene = model.AuditSceneNormal
	}

	// 查策略名(快照存入 Task,审批展示用,避免 policy 改/删后丢失)。
	// C 档节点级 apply 时 policyID=0,显示"节点策略"。
	var policyName string
	if policyID > 0 {
		var p model.Policy
		if err := co.DB.WithContext(ctx).Select("name").First(&p, policyID).Error; err == nil {
			policyName = p.Name
		}
	} else {
		policyName = "节点策略下发"
		// 节点级 dispatch:policy_name/diff_after/change_type 按每个 task 单独算
		// (区分待下发与待禁用实例),见 fillNodeDispatchPreview。
	}

	// 批量创建 Task(一次性插入,避免循环 N 次 Create)
	now := time.Now().Unix()
	tasks := make([]*model.Task, 0, len(nodeIDs))
	for _, id := range nodeIDs {
		tasks = append(tasks, &model.Task{
			ID:           "t_" + uuid.NewString(),
			NodeID:       id,
			PolicyID:     policyID,
			PolicyName:   policyName,
			Status:       model.TaskPendingApproval,
			Version:      now,
			AutoConfirm:  opts.AutoConfirm,
		})
	}
	if err := co.DB.WithContext(ctx).Create(&tasks).Error; err != nil {
		return nil, err
	}

	// 节点级 dispatch:批量查实例后按节点分组填充,避免逐 task 查询(2N->1 次)
	if policyID == 0 {
		co.fillNodeDispatchPreviewBatch(ctx, tasks)
	}

	detail := map[string]any{
		"policy_id":        policyID,
		"auto_approve":     opts.AutoApprove,
		"auto_confirm":     opts.AutoConfirm,
		"confirm_deadline": opts.ConfirmDeadline.String(),
	}
	// 单用户体系下 admin 视为 root:AutoApprove 即跳过审批(保留保护期),审计留痕以便追溯
	if opts.AutoApprove {
		detail["skip_approval"] = true
		detail["reason"] = "root auto-approve (单用户体系,跳过审批,保留保护期)"
	}
	// 自愈任务(scene=self_heal)标记:与人工操作区分,且不产生保护期(apply 成功即确认)
	if opts.Scene == model.AuditSceneSelfHeal {
		detail["reason"] = "system self-heal (drift 恢复,自动确认,无保护期)"
	}
	co.audit(ctx, opts.Author, "task.submit", opts.Scene, model.AuditResultPending, tasks, detail)

	if opts.AutoApprove {
		var dispatchErr error
		for _, t := range tasks {
			if err := co.approveAndDispatch(ctx, t.ID, opts.Author, opts.ConfirmDeadline); err != nil {
				co.Log.Warn("auto-approve dispatch failed", "task_id", t.ID, "err", err)
				if dispatchErr == nil {
					dispatchErr = fmt.Errorf("task %s: %w", t.ID, err)
				}
			}
		}
		// Re-read so callers see the newer state.
		for i, t := range tasks {
			var fresh model.Task
			if err := co.DB.WithContext(ctx).First(&fresh, "id = ?", t.ID).Error; err == nil {
				tasks[i] = &fresh
			}
		}
		if dispatchErr != nil {
			return tasks, dispatchErr
		}
	}
	return tasks, nil
}

// SubmitRemoval 为移除单条实例创建保护期任务并原子标记实例(漏洞 G 修复)。
// 事务内:创建 task(pending_approval) + 实例置 enabled=false、pending_delete=true、
// pending_delete_task_id=taskID——崩溃时不再出现"待删除但无关联 task"的孤儿标记。
// 事务外:AutoApprove 时 dispatch;dispatch 失败恢复实例原状, task 留 failed(可审计重试)。
func (co *Coordinator) SubmitRemoval(ctx context.Context, instanceID uint, opts SubmitOpts) (*model.Task, error) {
	if opts.ConfirmDeadline <= 0 {
		opts.ConfirmDeadline = co.DefaultConfirmDeadline
	}
	if opts.Scene == "" {
		opts.Scene = model.AuditSceneNormal
	}
	var inst model.NodePolicyInstance
	if err := co.DB.WithContext(ctx).First(&inst, instanceID).Error; err != nil {
		return nil, errNotFoundOr(err)
	}

	taskID := "t_" + uuid.NewString()
	t := &model.Task{
		ID: taskID, NodeID: inst.NodeID, PolicyID: 0,
		PolicyName:  "节点策略移除",
		Status:      model.TaskPendingApproval,
		Version:     time.Now().Unix(),
		AutoConfirm: opts.AutoConfirm,
	}
	if err := co.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(t).Error; err != nil {
			return err
		}
		return tx.Model(&model.NodePolicyInstance{}).Where("id = ?", inst.ID).Updates(map[string]any{
			"enabled": false, "pending_delete": true, "pending_delete_task_id": taskID,
		}).Error
	}); err != nil {
		return nil, err
	}

	co.audit(ctx, opts.Author, "task.submit", opts.Scene, model.AuditResultPending, []*model.Task{t}, map[string]any{
		"policy_id": 0, "auto_approve": opts.AutoApprove, "auto_confirm": opts.AutoConfirm,
		"confirm_deadline": opts.ConfirmDeadline.String(), "change_type": "disable",
	})

	if opts.AutoApprove {
		if err := co.approveAndDispatch(ctx, t.ID, opts.Author, opts.ConfirmDeadline); err != nil {
			// dispatch 失败:恢复实例原状(task 已由 approveAndDispatch 标记 failed)
			co.DB.WithContext(ctx).Model(&model.NodePolicyInstance{}).Where("id = ?", inst.ID).Updates(map[string]any{
				"enabled": true, "pending_delete": false, "pending_delete_task_id": "",
			})
			var fresh model.Task
			if rerr := co.DB.WithContext(ctx).First(&fresh, "id = ?", t.ID).Error; rerr == nil {
				t = &fresh
			}
			return t, err
		}
	}
	return t, nil
}

// SubmitRuleSet 用给定规则集为单节点创建回滚任务(计划三:规则库版本回滚)。
// 规则集 protojson 存 Task.RuleSetSnapshot,dispatch 时直接下发、不重新编译。
// AutoApprove 时立即 dispatch(跳过审批,保留保护期,超时由 Agent 自身快照回退)。
func (co *Coordinator) SubmitRuleSet(ctx context.Context, nodeID string, ruleSet *myfwv1.RuleSet, opts SubmitOpts) (*model.Task, error) {
	if ruleSet == nil {
		return nil, errors.New("task: empty ruleset for rollback")
	}
	if opts.ConfirmDeadline <= 0 {
		opts.ConfirmDeadline = co.DefaultConfirmDeadline
	}
	if opts.Scene == "" {
		opts.Scene = model.AuditSceneNormal
	}
	payload, err := protojson.Marshal(ruleSet)
	if err != nil {
		return nil, fmt.Errorf("task: marshal rollback ruleset: %w", err)
	}
	t := &model.Task{
		ID:              "t_" + uuid.NewString(),
		NodeID:          nodeID,
		PolicyID:        0,
		PolicyName:      "规则库版本回滚",
		ChangeType:      "rollback",
		Status:          model.TaskPendingApproval,
		Version:         time.Now().Unix(),
		RuleSetSnapshot: string(payload),
		AutoConfirm:     opts.AutoConfirm,
	}
	if err := co.DB.WithContext(ctx).Create(t).Error; err != nil {
		return nil, err
	}
	co.audit(ctx, opts.Author, "task.submit", opts.Scene, model.AuditResultPending, []*model.Task{t}, map[string]any{
		"change_type": "rollback", "rules": len(ruleSet.Rules), "auto_approve": opts.AutoApprove,
		"reason": "规则库版本回滚:下发历史规则集,节点规则将偏离当前实例定义(需重新下发收敛)",
	})
	if opts.AutoApprove {
		if err := co.approveAndDispatch(ctx, t.ID, opts.Author, opts.ConfirmDeadline); err != nil {
			co.Log.Warn("rollback auto-approve dispatch failed", "task_id", t.ID, "err", err)
			var fresh model.Task
			if e := co.DB.WithContext(ctx).First(&fresh, "id = ?", t.ID).Error; e == nil {
				t = &fresh
			}
			return t, err
		}
	}
	return t, nil
}

// Approve moves a task from PENDING_APPROVAL to APPROVED and immediately
// dispatches it. ConfirmDeadline (optional, 0 = coordinator default) is the
// window before auto-rollback.
func (co *Coordinator) Approve(ctx context.Context, taskID, reviewer string, confirmDeadline time.Duration) (*model.Task, error) {
	if confirmDeadline <= 0 {
		confirmDeadline = co.DefaultConfirmDeadline
	}
	if err := co.approveAndDispatch(ctx, taskID, reviewer, confirmDeadline); err != nil {
		return nil, err
	}
	return co.getByID(ctx, taskID)
}

// Reject terminates a PENDING_APPROVAL task with FAILED + reviewer note.
func (co *Coordinator) Reject(ctx context.Context, taskID, reviewer, reason string) (*model.Task, error) {
	var updated *model.Task
	err := co.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var t model.Task
		if err := tx.Where("id = ?", taskID).First(&t).Error; err != nil {
			return errNotFoundOr(err)
		}
		if t.Status != model.TaskPendingApproval {
			return fmt.Errorf("task: cannot reject %s (status=%s)", taskID, t.Status)
		}
		t.Status = model.TaskFailed
		t.Reviewer = reviewer
		t.Message = "rejected: " + reason
		if err := tx.Save(&t).Error; err != nil {
			return err
		}
		updated = &t
		return nil
	})
	if err != nil {
		return nil, err
	}
	co.audit(ctx, reviewer, "task.reject", model.AuditSceneNormal, model.AuditResultFailed, []*model.Task{updated}, map[string]any{"reason": reason})
	return updated, nil
}

// Confirm settles a CONFIRM_WAIT task as CONFIRMED and cancels its rollback
// timer. Called by the admin once they've verified the change is safe.
func (co *Coordinator) Confirm(ctx context.Context, taskID, reviewer string) (*model.Task, error) {
	var updated *model.Task
	err := co.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var t model.Task
		if err := tx.Where("id = ?", taskID).First(&t).Error; err != nil {
			return errNotFoundOr(err)
		}
		if t.Status != model.TaskConfirmWait {
			return fmt.Errorf("task: cannot confirm %s (status=%s)", taskID, t.Status)
		}
		t.Status = model.TaskConfirmed
		t.Reviewer = reviewer
		if err := tx.Save(&t).Error; err != nil {
			return err
		}
		// 用户确认移除:清理本次 task 关联的待删除实例(移除进保护期后由 Confirm 落槽数据库删除)
		if err := co.purgePendingDelete(tx, taskID); err != nil {
			return err
		}
		updated = &t
		return nil
	})
	if err != nil {
		return nil, err
	}
	// Tell the Agent to discard its retained snapshot.
	co.sendConfirmToAgent(ctx, updated)
	co.cancelTimer(taskID)
	co.audit(ctx, reviewer, "task.confirm", model.AuditSceneNormal, model.AuditResultSuccess, []*model.Task{updated}, nil)
	return updated, nil
}

// Rollback 手动回滚一个处于保护期(confirm_wait)的任务:发 Rollback 给 Agent
// 恢复变更前快照,置 ROLLED_BACK 并取消倒计时定时器。
func (co *Coordinator) Rollback(ctx context.Context, taskID, reviewer string) (*model.Task, error) {
	var updated *model.Task
	err := co.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var t model.Task
		if err := tx.Where("id = ?", taskID).First(&t).Error; err != nil {
			return errNotFoundOr(err)
		}
		if t.Status != model.TaskConfirmWait {
			return fmt.Errorf("task: cannot rollback %s (status=%s)", taskID, t.Status)
		}
		t.Status = model.TaskRolledBack
		t.Reviewer = reviewer
		t.Message = "manual rollback by " + reviewer
		if err := tx.Save(&t).Error; err != nil {
			return err
		}
		// 误删回滚:恢复本次 task 关联的待删除实例(Agent 恢复快照,节点规则回来)
		co.restorePendingDelete(tx, taskID)
		updated = &t
		return nil
	})
	if err != nil {
		return nil, err
	}
	co.sendRollbackToAgent(ctx, updated)
	co.cancelTimer(taskID)
	co.audit(ctx, reviewer, "task.manual_rollback", model.AuditSceneNormal, model.AuditResultRolledBack, []*model.Task{updated}, nil)
	return updated, nil
}

// Get / List helpers.
func (co *Coordinator) Get(ctx context.Context, taskID string) (*model.Task, error) {
	return co.getByID(ctx, taskID)
}

// HasInFlight 报告节点是否有未终态(在途)任务:pending_approval/dispatching/applying/confirm_wait。
// OnSync 去重用——节点已有任务(含待审批人工任务)时跳过自愈 Submit,避免叠加下发(漏洞 I 修复)。
func (co *Coordinator) HasInFlight(nodeID string) bool {
	var cnt int64
	co.DB.Model(&model.Task{}).
		Where("node_id = ? AND status IN ?", nodeID,
			[]string{string(model.TaskPendingApproval), string(model.TaskDispatching), string(model.TaskApplying), string(model.TaskConfirmWait)}).
		Count(&cnt)
	return cnt > 0
}

func (co *Coordinator) List(ctx context.Context, statusFilter string) ([]model.Task, error) {
	q := co.DB.WithContext(ctx).Order("created_at DESC")
	if statusFilter != "" {
		q = q.Where("status = ?", statusFilter)
	}
	var out []model.Task
	err := q.Find(&out).Error
	return out, err
}

// --- internal ---------------------------------------------------------------

func (co *Coordinator) approveAndDispatch(ctx context.Context, taskID, reviewer string, confirmDeadline time.Duration) error {
	// 1. Move state APPROVED -> DISPATCHING atomically.
	var task model.Task
	err := co.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("id = ?", taskID).First(&task).Error; err != nil {
			return errNotFoundOr(err)
		}
		if task.Status != model.TaskPendingApproval {
			return fmt.Errorf("task: cannot approve %s (status=%s)", taskID, task.Status)
		}
		task.Status = model.TaskDispatching
		task.Reviewer = reviewer
		return tx.Save(&task).Error
	})
	if err != nil {
		return err
	}
	// 自愈任务(AutoConfirm)的审批审计用 self_heal 场景,与人工审批区分
	apprScene := model.AuditSceneNormal
	if task.AutoConfirm {
		apprScene = model.AuditSceneSelfHeal
	}
	co.audit(ctx, reviewer, "task.approve", apprScene, model.AuditResultPending, []*model.Task{&task}, nil)

	// 2. 编译前刷新预览:审批时可能已与 Submit 时刻不同,保证展示与实际下发一致(漏洞 F' 修复)。
	//    回滚任务(RuleSetSnapshot 非空)无基于实例的 diff 预览,跳过。
	if task.PolicyID == 0 && task.RuleSetSnapshot == "" {
		co.refreshNodePreview(ctx, &task)
	}

	// 3. 回滚任务直接用历史规则集快照下发,不重新编译;普通任务按当前 DB 状态编译。
	//    compile errors mark the task FAILED.
	var rules []*myfwv1.CompiledRule
	var sets []*myfwv1.AddressSet
	var customChains []*myfwv1.CustomChainDef
	if task.RuleSetSnapshot != "" {
		var snap myfwv1.RuleSet
		if err := protojson.Unmarshal([]byte(task.RuleSetSnapshot), &snap); err != nil {
			co.markFailed(ctx, task.ID, "rollback ruleset unmarshal: "+err.Error())
			return err
		}
		rules, sets, customChains = snap.Rules, snap.Sets, snap.CustomChains
	} else {
		var err error
		rules, sets, customChains, err = co.Comp.CompileForNode(ctx, task.NodeID)
		if err != nil {
			co.markFailed(ctx, task.ID, "compile: "+err.Error())
			return err
		}
	}
	deadline := time.Now().Add(confirmDeadline)
	msg := &myfwv1.ControllerToAgent{
		Payload: &myfwv1.ControllerToAgent_Apply{
			Apply: &myfwv1.ApplyTask{
				TaskId: task.ID,
				RuleSet: &myfwv1.RuleSet{
					NodeId:       task.NodeID,
					Version:      task.Version,
					Rules:        rules,
					Sets:         sets,
					CustomChains: customChains,
				},
				ConfirmDeadlineUnix: deadline.Unix(),
			},
		},
	}
	if err := co.Stream.Reg.Send(task.NodeID, msg); err != nil {
		co.markFailed(ctx, task.ID, "dispatch: "+err.Error())
		return err
	}

	// 4. Move to APPLYING and stamp confirm_deadline. When the TaskResult
	//    arrives resultLoop will bump us to CONFIRM_WAIT and arm the timer.
	return co.DB.WithContext(ctx).Model(&model.Task{}).
		Where("id = ?", task.ID).
		Updates(map[string]any{
			"status":           model.TaskApplying,
			"confirm_deadline": deadline,
		}).Error
}

// resultLoop consumes TaskResult from the shared subscription and advances
// the state machine.
func (co *Coordinator) resultLoop(ctx context.Context) {
	defer close(co.stoppedCh)
	for {
		select {
		case <-co.stopCh:
			return
		case <-ctx.Done():
			return
		case res, ok := <-co.results:
			if !ok {
				return
			}
			co.handleResult(ctx, res)
		}
	}
}

func (co *Coordinator) handleResult(ctx context.Context, res *myfwv1.TaskResult) {
	var t model.Task
	if err := co.DB.WithContext(ctx).Where("id = ?", res.TaskId).First(&t).Error; err != nil {
		// Not our task (M5 legacy apply, or already-cleaned) — drop it.
		return
	}
	// Only APPLYING transitions on a result. Other states (e.g. CONFIRM_WAIT
	// after a redelivered result) are logged and ignored.
	if t.Status != model.TaskApplying {
		co.Log.Debug("ignored result for task not in APPLYING", "task_id", t.ID, "status", t.Status)
		return
	}
	if !res.Ok {
		t.Status = model.TaskFailed
		t.Message = res.Message
		t.ResultHash = res.ResultHash
		_ = co.DB.WithContext(ctx).Save(&t).Error
		// Agent 应用失败:仅回退本次 task 涉及的 enabled 实例的 applied,
		// 不动同节点 enabled=false 的稳定/待删实例(它们在别的 task 的保护期内,漏洞 J 修复)。
		co.DB.WithContext(ctx).Model(&model.NodePolicyInstance{}).
			Where("node_id = ? AND enabled = ?", t.NodeID, true).Update("applied", false)
		co.audit(ctx, "agent", "task.apply_failed", model.AuditSceneNormal, model.AuditResultFailed, []*model.Task{&t}, map[string]any{"msg": res.Message})
		return
	}
	// 回滚任务(RuleSetSnapshot 非空):规则已按历史版本收敛,与当前实例定义不一致,
	// 实例 applied 全置 false,提示节点规则偏离当前期望(前端黄色未同步),需重新下发收敛。
	if t.RuleSetSnapshot != "" {
		co.DB.WithContext(ctx).Model(&model.NodePolicyInstance{}).
			Where("node_id = ?", t.NodeID).Update("applied", false)
	} else {
		// Agent 确认应用成功:enabled 实例 applied 置 true(本次下发生效);
		// 手动禁用(非待删)实例 applied 置 false(节点上已被 desired-state 移除);
		// pending_delete 实例保持不动(在它自己的移除保护期内,等 Confirm 清理或 Rollback 恢复,
		// 漏洞 S 修复——全量 expr(enabled) 会把待删实例的 applied 误清零)。
		co.DB.WithContext(ctx).Model(&model.NodePolicyInstance{}).
			Where("node_id = ? AND enabled = ?", t.NodeID, true).Update("applied", true)
		co.DB.WithContext(ctx).Model(&model.NodePolicyInstance{}).
			Where("node_id = ? AND enabled = ? AND pending_delete = ?", t.NodeID, false, false).Update("applied", false)
	}
	// 普通任务 Apply 成功(节点规则已收敛):归档规则库版本(计划三)。
	// 回滚任务不自动归档——路由层已在回滚前手动归档当前版本(便于撤销回滚)。
	if t.RuleSetSnapshot == "" && co.ArchiveFn != nil {
		if err := co.ArchiveFn(ctx, t.NodeID, t.ID); err != nil {
			co.Log.Warn("archive node revision", "node_id", t.NodeID, "task_id", t.ID, "err", err)
		}
	}

	// 自愈任务(AutoConfirm):apply 成功即确认,跳过 confirm_wait 保护期。
	// 这是修复 drift 自愈死循环的核心——自愈是系统行为,无人工确认,若走保护期
	// 必然超时回滚,回滚恢复快照≠expected 又触发再漂移,形成死循环。
	if t.AutoConfirm {
		t.Status = model.TaskConfirmed
		t.ResultHash = res.ResultHash
		if err := co.DB.WithContext(ctx).Save(&t).Error; err != nil {
			co.Log.Warn("save auto-confirmed", "task_id", t.ID, "err", err)
			return
		}
		// 通知 Agent 释放快照(与人工 Confirm 语义一致)
		co.sendConfirmToAgent(ctx, &t)
		co.audit(ctx, "system", "task.applying_ok", model.AuditSceneSelfHeal, model.AuditResultSuccess,
			[]*model.Task{&t}, map[string]any{"hash": res.ResultHash, "auto_confirm": true})
		return
	}

	// 人工任务:进入保护期(confirm_wait),启动倒计时定时器,超时未确认则自动回滚。
	// Agent 保留变更前快照,等待用户 Confirm(释放快照) 或 Rollback(恢复快照)。
	t.Status = model.TaskConfirmWait
	t.ResultHash = res.ResultHash
	if err := co.DB.WithContext(ctx).Save(&t).Error; err != nil {
		co.Log.Warn("save confirm_wait", "task_id", t.ID, "err", err)
		return
	}
	co.armRollbackTimer(&t)
	deadline := "-"
	pw := 0
	if t.ConfirmDeadline != nil {
		deadline = t.ConfirmDeadline.Format(time.RFC3339)
		pw = int(time.Until(*t.ConfirmDeadline).Seconds())
		if pw < 0 {
			pw = 0
		}
	}
	co.audit(ctx, "agent", "task.applying_ok", model.AuditSceneNormal, model.AuditResultPending, []*model.Task{&t}, map[string]any{
		"hash":              res.ResultHash,
		"confirm_deadline":  deadline,
		"protection_window": pw,
	})
}

// armRollbackTimer schedules an auto-rollback at t.ConfirmDeadline. If the
// deadline is already in the past the rollback runs immediately.
func (co *Coordinator) armRollbackTimer(t *model.Task) {
	if t.ConfirmDeadline == nil {
		return
	}
	d := time.Until(*t.ConfirmDeadline)
	if d < 0 {
		d = 0
	}
	taskID := t.ID
	timer := time.AfterFunc(d, func() { co.autoRollback(taskID) })
	co.tmu.Lock()
	co.timers[taskID] = timer
	co.tmu.Unlock()
}

func (co *Coordinator) cancelTimer(taskID string) {
	co.tmu.Lock()
	defer co.tmu.Unlock()
	if timer, ok := co.timers[taskID]; ok {
		timer.Stop()
		delete(co.timers, taskID)
	}
}

// autoRollback runs when a confirm-wait timer fires. It sends a Rollback to
// the Agent and marks the task ROLLED_BACK. The Agent's OnRollback handler
// (M5) uses its retained snapshot to restore.
func (co *Coordinator) autoRollback(taskID string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var t model.Task
	if err := co.DB.WithContext(ctx).Where("id = ?", taskID).First(&t).Error; err != nil {
		return
	}
	if t.Status != model.TaskConfirmWait {
		return // already confirmed / rolled back
	}
	co.sendRollbackToAgent(ctx, &t)

	t.Status = model.TaskRolledBack
	t.Message = "auto-rollback: confirm-wait deadline expired"
	_ = co.DB.WithContext(ctx).Save(&t).Error
	// 超时自动回滚同手动回滚:恢复待删除实例(Agent 恢复快照,规则回来)
	co.restorePendingDelete(co.DB.WithContext(ctx), taskID)
	co.audit(ctx, "system", "task.auto_rollback", model.AuditSceneAutoRollback, model.AuditResultRolledBack, []*model.Task{&t}, nil)

	co.tmu.Lock()
	delete(co.timers, taskID)
	co.tmu.Unlock()
}

// recoverOnStart handles Controller restart: any task in a mid-flight state
// gets moved to a terminal state so operators aren't left with hung rows.
func (co *Coordinator) recoverOnStart(ctx context.Context) error {
	now := time.Now()

	// CONFIRM_WAIT with expired deadline -> auto-rollback immediately.
	var expired []model.Task
	if err := co.DB.WithContext(ctx).
		Where("status = ? AND confirm_deadline IS NOT NULL AND confirm_deadline < ?",
			model.TaskConfirmWait, now).
		Find(&expired).Error; err != nil {
		return err
	}
	for i := range expired {
		co.Log.Info("recovery: rolling back expired confirm-wait task", "task_id", expired[i].ID)
		co.autoRollback(expired[i].ID)
	}

	// CONFIRM_WAIT still in-window -> re-arm the timer against its persisted
	// deadline. We don't lose the wall-clock protection across restarts.
	var live []model.Task
	if err := co.DB.WithContext(ctx).
		Where("status = ? AND confirm_deadline IS NOT NULL AND confirm_deadline >= ?",
			model.TaskConfirmWait, now).
		Find(&live).Error; err != nil {
		return err
	}
	for i := range live {
		t := live[i]
		co.armRollbackTimer(&t)
	}

	// APPLYING or DISPATCHING tasks: the Controller was mid-flight when it
	// died; there's no way to know if the Agent applied or not. Move them
	// to FAILED with a clear message so ops can re-submit.
	var stuck []model.Task
	if err := co.DB.WithContext(ctx).
		Where("status IN ?", []string{string(model.TaskDispatching), string(model.TaskApplying)}).
		Find(&stuck).Error; err != nil {
		return err
	}
	for i := range stuck {
		stuck[i].Status = model.TaskFailed
		stuck[i].Message = "controller restarted while task was in flight"
		_ = co.DB.WithContext(ctx).Save(&stuck[i]).Error
		co.audit(ctx, "system", "task.recover_failed", model.AuditSceneRecovery, model.AuditResultFailed, []*model.Task{&stuck[i]}, nil)
	}
	return nil
}

// --- helpers ---------------------------------------------------------------

func (co *Coordinator) sendConfirmToAgent(ctx context.Context, t *model.Task) {
	_ = co.Stream.Reg.Send(t.NodeID, &myfwv1.ControllerToAgent{
		Payload: &myfwv1.ControllerToAgent_Confirm{
			Confirm: &myfwv1.ConfirmTask{TaskId: t.ID},
		},
	})
}

func (co *Coordinator) sendRollbackToAgent(ctx context.Context, t *model.Task) {
	// Best-effort. If the Agent is offline the snapshot on-agent may not be
	// available anymore anyway; a follow-up Sync when it reconnects will
	// bring the node back in line via a fresh Apply.
	_ = co.Stream.Reg.Send(t.NodeID, &myfwv1.ControllerToAgent{
		Payload: &myfwv1.ControllerToAgent_Rollback{
			Rollback: &myfwv1.RollbackTask{TaskId: t.ID},
		},
	})
}

// purgePendingDelete 物理删除与 taskID 关联的待删除实例:Confirm 时调用。
// 用户确认移除,节点规则已不在(apply 时已 -D),数据库记录随之清除。
func (co *Coordinator) purgePendingDelete(tx *gorm.DB, taskID string) error {
	return tx.Where("pending_delete = ? AND pending_delete_task_id = ?", true, taskID).
		Delete(&model.NodePolicyInstance{}).Error
}

// restorePendingDelete 恢复与 taskID 关联的待删除实例:Rollback(手动/自动)时调用。
// Agent 已恢复变更前快照,节点规则回来,实例随之恢复启用并清除待删除标记。
func (co *Coordinator) restorePendingDelete(tx *gorm.DB, taskID string) {
	tx.Model(&model.NodePolicyInstance{}).
		Where("pending_delete = ? AND pending_delete_task_id = ?", true, taskID).
		Updates(map[string]any{
			"enabled":                true,
			"pending_delete":         false,
			"applied":                true,
			"pending_delete_task_id": "",
		})
}

func (co *Coordinator) markFailed(ctx context.Context, taskID, msg string) {
	_ = co.DB.WithContext(ctx).Model(&model.Task{}).
		Where("id = ?", taskID).
		Updates(map[string]any{
			"status":  model.TaskFailed,
			"message": msg,
		}).Error
}

func (co *Coordinator) getByID(ctx context.Context, taskID string) (*model.Task, error) {
	var t model.Task
	if err := co.DB.WithContext(ctx).Where("id = ?", taskID).First(&t).Error; err != nil {
		return nil, errNotFoundOr(err)
	}
	return &t, nil
}

// audit 写审计流水。scene/result 为结构化索引列(便于聚合统计保护期变更仪表盘),
// detail 为 Detail JSON 扩展字段,其中 protection_window(int) 会被提取到独立列。
// tasks 为空时写单条(专家终端等无 task 场景)。
func (co *Coordinator) audit(ctx context.Context, actor, action, scene, result string, tasks []*model.Task, detail map[string]any) {
	if co.Audit == nil {
		return
	}
	writeOne := func(nodeID, taskID string, base map[string]any) {
		d := map[string]any{"scene": scene}
		pw := 0
		for k, v := range base {
			if k == "protection_window" {
				if n, ok := v.(int); ok {
					pw = n
				}
				continue
			}
			d[k] = v
		}
		buf, _ := json.Marshal(d)
		_ = co.Audit.Write(ctx, model.AuditLog{
			Actor:            actor,
			Action:           action,
			Scene:            scene,
			Result:           result,
			NodeID:           nodeID,
			TaskID:           taskID,
			Detail:           string(buf),
			ProtectionWindow: pw,
		})
	}
	if len(tasks) == 0 {
		writeOne("", "", detail)
		return
	}
	for _, t := range tasks {
		d := map[string]any{"status": string(t.Status)}
		if t.PolicyID > 0 {
			d["policy_id"] = t.PolicyID
		}
		if t.PolicyName != "" {
			d["policy_name"] = t.PolicyName
		}
		if t.ChangeType != "" {
			d["change_type"] = t.ChangeType
		}
		for k, v := range detail {
			d[k] = v
		}
		writeOne(t.NodeID, t.ID, d)
	}
}

var ErrNotFound = errors.New("task: not found")

func errNotFoundOr(err error) error {
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return ErrNotFound
	}
	return err
}

// fillNodeDispatchPreview 填充节点级 dispatch 任务的 policy_name/diff_after/change_type:
//   - 待下发实例(enabled=true,applied=false)-> 生成 -A 追加命令
//   - 待禁用实例(enabled=false,applied=true)-> 生成 -D 移除命令,policy_name 标注"[禁用]"
//
// 让保护期面板能区分本次是下发新规则还是禁用旧规则,并显著标注禁用任务。
// fillNodeDispatchPreviewBatch 批量查所有目标节点实例,按 nodeID 分组后填充每个 task 预览。
// 避免逐 task 查询(2N 次 DB),改为 1 次批量查询 + Go 内分组。编译仍按节点单独执行(CPU 密集,不可跨节点合并)。
func (co *Coordinator) fillNodeDispatchPreviewBatch(ctx context.Context, tasks []*model.Task) {
	nodeIDs := make([]string, 0, len(tasks))
	for _, t := range tasks {
		nodeIDs = append(nodeIDs, t.NodeID)
	}
	// 一次查询所有待下发(enabled=true,applied=false)和待禁用(enabled=false,applied=true)实例。
	// 待禁用排除 pending_delete 实例:它们的移除由各自保护期 task 展示,
	// 不混入其他 dispatch 预览(漏洞 S/F' 修复)。
	var instances []model.NodePolicyInstance
	co.DB.WithContext(ctx).
		Where("node_id IN ? AND ((enabled = ? AND applied = ?) OR (enabled = ? AND applied = ? AND pending_delete = ?))",
			nodeIDs, true, false, false, true, false).
		Order("node_id, priority ASC, id ASC").Find(&instances)

	pendingByNode := map[string][]model.NodePolicyInstance{}
	disablingByNode := map[string][]model.NodePolicyInstance{}
	for i := range instances {
		inst := instances[i]
		if inst.Enabled && !inst.Applied {
			pendingByNode[inst.NodeID] = append(pendingByNode[inst.NodeID], inst)
		} else if !inst.Enabled && inst.Applied {
			disablingByNode[inst.NodeID] = append(disablingByNode[inst.NodeID], inst)
		}
	}
	for _, t := range tasks {
		co.fillNodeDispatchPreviewFromCache(ctx, t, pendingByNode[t.NodeID], disablingByNode[t.NodeID])
	}
}

// refreshNodePreview 用节点最新实例状态重算单 task 的 policy_name/change_type/diff_after。
// Submit 时生成的预览可能因审批期间实例被编辑而过时;审批(dispatch)时刷新为下发真值,
// 保证保护期面板展示与实际下发一致(漏洞 F' 修复)。
func (co *Coordinator) refreshNodePreview(ctx context.Context, t *model.Task) {
	var pending, disabling []model.NodePolicyInstance
	co.DB.WithContext(ctx).
		Where("node_id = ? AND enabled = ? AND applied = ?", t.NodeID, true, false).Find(&pending)
	co.DB.WithContext(ctx).
		Where("node_id = ? AND enabled = ? AND applied = ? AND pending_delete = ?",
			t.NodeID, false, true, false).Find(&disabling)
	co.fillNodeDispatchPreviewFromCache(ctx, t, pending, disabling)
}

// fillNodeDispatchPreviewFromCache 用预查的实例切片填充单个 task 预览(不再查 DB)。
func (co *Coordinator) fillNodeDispatchPreviewFromCache(ctx context.Context, t *model.Task, pending, disabling []model.NodePolicyInstance) {
	// policy_name:待下发实例名 + 待禁用实例名(前缀"[禁用]")
	var names []string
	for _, inst := range pending {
		names = append(names, inst.Name)
	}
	for _, inst := range disabling {
		names = append(names, "[禁用]"+inst.Name)
	}
	if len(names) > 0 {
		t.PolicyName = strings.Join(names, ", ")
	}

	// change_type:仅禁用->disable,仅下发->dispatch,两者皆有->mixed
	switch {
	case len(disabling) > 0 && len(pending) > 0:
		t.ChangeType = "mixed"
	case len(disabling) > 0:
		t.ChangeType = "disable"
	default:
		t.ChangeType = "dispatch"
	}

	// diff_after:待下发 -A + 待禁用 -D
	var lines []string
	if len(pending) > 0 {
		rules, c2t, err := co.Comp.CompileInstances(ctx, pending)
		if err == nil {
			lines = append(lines, formatRuleLines(rules, c2t, "A")...)
		}
	}
	if len(disabling) > 0 {
		rules, c2t, err := co.Comp.CompileInstances(ctx, disabling)
		if err == nil {
			lines = append(lines, formatRuleLines(rules, c2t, "D")...)
		}
	}
	if len(lines) > 0 {
		t.DiffAfter = strings.Join(lines, "\n")
	}
	co.DB.Model(&model.Task{}).Where("id = ?", t.ID).Updates(map[string]any{
		"policy_name": t.PolicyName,
		"change_type": t.ChangeType,
		"diff_after":  t.DiffAfter,
	})
}

// formatRuleLines 将 CompiledRule 列表拼为 iptables 命令行,mode="A" 追加/"D" 移除,
// 供 diff_after 预览。chainToTable 提供 chain->table 映射(组链 + MARK 白名单内置链)。
func formatRuleLines(rules []*myfwv1.CompiledRule, chainToTable map[string]string, mode string) []string {
	lines := make([]string, 0, len(rules))
	for _, r := range rules {
		table := chainToTable[r.Chain]
		if table == "" {
			table = "filter"
		}
		line := fmt.Sprintf("iptables -t %s -%s MYFW-%s", table, mode, r.Chain)
		if r.Source != "" {
			line += " -s " + r.Source
		}
		if r.Destination != "" {
			line += " -d " + r.Destination
		}
		if p := protoShort(r.Protocol); p != "" {
			line += " -p " + p
			if r.PortRange != "" {
				line += " --dport " + r.PortRange
			}
		}
		if r.SourceGroup != "" {
			line += " -m set --match-set MYFW-" + r.SourceGroup + " src"
		}
		if r.MatchMark != 0 {
			line += fmt.Sprintf(" -m mark --mark %d", r.MatchMark)
		}
		line += " -j " + actionShort(r.Action)
		if r.Action == myfwv1.Action_ACTION_MARK {
			line += fmt.Sprintf(" --set-mark %d", r.Mark)
		}
		if r.Action == myfwv1.Action_ACTION_DNAT && r.NatTo != "" {
			line += " --to-destination " + r.NatTo
		}
		if r.Action == myfwv1.Action_ACTION_SNAT && r.NatTo != "" {
			line += " --to-source " + r.NatTo
		}
		lines = append(lines, line)
	}
	return lines
}

// protoShort / actionShort 将 proto/enum 转为 iptables 命令用的短名,供 diff_after 预览。
func protoShort(p myfwv1.Protocol) string {
	switch p {
	case myfwv1.Protocol_PROTOCOL_TCP:
		return "tcp"
	case myfwv1.Protocol_PROTOCOL_UDP:
		return "udp"
	case myfwv1.Protocol_PROTOCOL_ICMP:
		return "icmp"
	}
	return ""
}
func actionShort(a myfwv1.Action) string {
	switch a {
	case myfwv1.Action_ACTION_ACCEPT:
		return "ACCEPT"
	case myfwv1.Action_ACTION_DROP:
		return "DROP"
	case myfwv1.Action_ACTION_REJECT:
		return "REJECT"
	case myfwv1.Action_ACTION_MARK:
		return "MARK"
	case myfwv1.Action_ACTION_DNAT:
		return "DNAT"
	case myfwv1.Action_ACTION_SNAT:
		return "SNAT"
	}
	return "ACCEPT"
}
