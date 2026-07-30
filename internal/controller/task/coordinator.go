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
	"sync"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

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
	ConfirmDeadline time.Duration // overrides DefaultConfirmDeadline when >0
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

	// 查策略名(快照存入 Task,审批展示用,避免 policy 改/删后丢失)。
	// C 档节点级 apply 时 policyID=0,显示"节点策略"。
	var policyName string
	if policyID > 0 {
		var p model.Policy
		if err := co.DB.WithContext(ctx).Select("name").First(&p, policyID).Error; err == nil {
			policyName = p.Name
		}
	} else {
		policyName = "节点策略"
	}

	tasks := make([]*model.Task, 0, len(nodeIDs))
	err := co.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		for _, id := range nodeIDs {
			t := &model.Task{
				ID:         "t_" + uuid.NewString(),
				NodeID:     id,
				PolicyID:   policyID,
				PolicyName: policyName,
				Status:     model.TaskPendingApproval,
				Version:    time.Now().Unix(),
			}
			if err := tx.Create(t).Error; err != nil {
				return err
			}
			tasks = append(tasks, t)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	detail := map[string]any{
		"policy_id":        policyID,
		"auto_approve":     opts.AutoApprove,
		"confirm_deadline": opts.ConfirmDeadline.String(),
	}
	// 单用户体系下 admin 视为 root:AutoApprove 即跳过审批(保留保护期),审计留痕以便追溯
	if opts.AutoApprove {
		detail["skip_approval"] = true
		detail["reason"] = "root auto-approve (单用户体系,跳过审批,保留保护期)"
	}
	co.audit(ctx, opts.Author, "task.submit", tasks, detail)

	if opts.AutoApprove {
		for _, t := range tasks {
			if err := co.approveAndDispatch(ctx, t.ID, opts.Author, opts.ConfirmDeadline); err != nil {
				co.Log.Warn("auto-approve dispatch failed", "task_id", t.ID, "err", err)
			}
		}
		// Re-read so callers see the newer state.
		for i, t := range tasks {
			var fresh model.Task
			if err := co.DB.WithContext(ctx).First(&fresh, "id = ?", t.ID).Error; err == nil {
				tasks[i] = &fresh
			}
		}
	}
	return tasks, nil
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
	co.audit(ctx, reviewer, "task.reject", []*model.Task{updated}, map[string]any{"reason": reason})
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
		updated = &t
		return nil
	})
	if err != nil {
		return nil, err
	}
	// Tell the Agent to discard its retained snapshot.
	co.sendConfirmToAgent(ctx, updated)
	co.cancelTimer(taskID)
	co.audit(ctx, reviewer, "task.confirm", []*model.Task{updated}, nil)
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
		updated = &t
		return nil
	})
	if err != nil {
		return nil, err
	}
	co.sendRollbackToAgent(ctx, updated)
	co.cancelTimer(taskID)
	co.audit(ctx, reviewer, "task.manual_rollback", []*model.Task{updated}, nil)
	return updated, nil
}

// Get / List helpers.
func (co *Coordinator) Get(ctx context.Context, taskID string) (*model.Task, error) {
	return co.getByID(ctx, taskID)
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
	co.audit(ctx, reviewer, "task.approve", []*model.Task{&task}, nil)

	// 2. Compile & send. compile errors mark the task FAILED.
	rules, sets, customChains, err := co.Comp.CompileForNode(ctx, task.NodeID)
	if err != nil {
		co.markFailed(ctx, task.ID, "compile: "+err.Error())
		return err
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

	// 3. Move to APPLYING and stamp confirm_deadline. When the TaskResult
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
		co.audit(ctx, "agent", "task.apply_failed", []*model.Task{&t}, map[string]any{"msg": res.Message})
		return
	}
	// apply 成功:进入保护期(confirm_wait),启动倒计时定时器,超时未确认则自动回滚。
	// Agent 保留变更前快照,等待用户 Confirm(释放快照) 或 Rollback(恢复快照)。
	t.Status = model.TaskConfirmWait
	t.ResultHash = res.ResultHash
	if err := co.DB.WithContext(ctx).Save(&t).Error; err != nil {
		co.Log.Warn("save confirm_wait", "task_id", t.ID, "err", err)
		return
	}
	co.armRollbackTimer(&t)
	deadline := "-"
	if t.ConfirmDeadline != nil {
		deadline = t.ConfirmDeadline.Format(time.RFC3339)
	}
	co.audit(ctx, "agent", "task.applying_ok", []*model.Task{&t}, map[string]any{
		"hash":             res.ResultHash,
		"confirm_deadline": deadline,
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
	co.audit(ctx, "system", "task.auto_rollback", []*model.Task{&t}, nil)

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
		co.audit(ctx, "system", "task.recover_failed", []*model.Task{&stuck[i]}, nil)
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

func (co *Coordinator) audit(ctx context.Context, actor, action string, tasks []*model.Task, detail map[string]any) {
	if co.Audit == nil {
		return
	}
	for _, t := range tasks {
		d := map[string]any{"status": t.Status}
		for k, v := range detail {
			d[k] = v
		}
		buf, _ := json.Marshal(d)
		_ = co.Audit.Write(ctx, model.AuditLog{
			Actor:  actor,
			Action: action,
			NodeID: t.NodeID,
			TaskID: t.ID,
			Detail: string(buf),
		})
	}
}

var ErrNotFound = errors.New("task: not found")

func errNotFoundOr(err error) error {
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return ErrNotFound
	}
	return err
}
