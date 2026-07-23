// Package handler bridges Controller-to-Agent messages to a Firewall Driver.
// It is the concrete conn.Handler used at runtime.
package handler

import (
	"context"
	"log/slog"
	"time"

	myfwv1 "iptables-tool/api/myfw/v1"
	"iptables-tool/internal/agent/driver"
)

// Driver is the subset of driver.Driver that Handler needs. Kept small so it
// can be faked by tests without pulling in every method.
type Driver interface {
	Apply(ctx context.Context, rules []*myfwv1.CompiledRule) (string, error)
	Snapshot(ctx context.Context) (payload string, hash string, err error)
	Restore(ctx context.Context, payload string) error
}

// HashNotifier is called when an Apply succeeds, so the Watchdog can update
// its expected hash baseline.
type HashNotifier interface {
	SetExpectedHash(hash string)
}

// Handler dispatches ApplyTask/ConfirmTask/RollbackTask to a Driver. It keeps
// the pre-Apply snapshot in memory so a subsequent Rollback can restore it.
type Handler struct {
	D   Driver
	Log *slog.Logger

	// HashNotifier receives the hash after a successful Apply.
	HashNotifier HashNotifier

	// last snapshot taken before Apply, keyed by TaskId — read when Rollback
	// arrives, cleared on Confirm.
	last map[string]string
}

// New builds a Handler around drv. If drv is nil, Apply tasks are rejected
// with a clear message (useful during dev on macOS where no real driver is
// available).
func New(drv Driver, log *slog.Logger) *Handler {
	return &Handler{D: drv, Log: log, last: map[string]string{}}
}

// SetHashNotifier registers a notifier to receive successful Apply hashes.
func (h *Handler) SetHashNotifier(n HashNotifier) {
	h.HashNotifier = n
}

// OnApply snapshots the current namespace, then applies the new RuleSet.
// The snapshot is retained so a later RollbackTask can restore it.
func (h *Handler) OnApply(ctx context.Context, task *myfwv1.ApplyTask) *myfwv1.TaskResult {
	res := &myfwv1.TaskResult{TaskId: task.TaskId, TsUnix: time.Now().Unix()}

	if h.D == nil {
		res.Message = "no firewall driver on this host"
		return res
	}
	if task.RuleSet == nil {
		res.Message = "empty RuleSet"
		return res
	}

	snap, _, err := h.D.Snapshot(ctx)
	if err != nil {
		res.Message = "snapshot failed: " + err.Error()
		return res
	}
	h.last[task.TaskId] = snap

	hash, err := h.D.Apply(ctx, task.RuleSet.Rules)
	if err != nil {
		// Best-effort self-rollback: try to restore the snapshot we just took
		// so a mid-Apply failure doesn't leave the host in a bad state. If
		// this also fails we surface both errors.
		if rbErr := h.D.Restore(ctx, snap); rbErr != nil {
			h.Log.Error("apply failed AND self-rollback failed",
				"apply_err", err, "rollback_err", rbErr, "task_id", task.TaskId)
			res.Message = "apply failed: " + err.Error() + " (self-rollback also failed: " + rbErr.Error() + ")"
			return res
		}
		res.Message = "apply failed: " + err.Error() + " (self-rolled back)"
		return res
	}

	res.Ok = true
	res.ResultHash = hash

	// Notify Watchdog of the new expected hash.
	if h.HashNotifier != nil {
		h.HashNotifier.SetExpectedHash(hash)
	}

	return res
}

// OnConfirm discards the snapshot we kept for this task — the change is now
// considered stable.
func (h *Handler) OnConfirm(ctx context.Context, task *myfwv1.ConfirmTask) {
	delete(h.last, task.TaskId)
	h.Log.Info("apply confirmed", "task_id", task.TaskId)
}

// OnRollback restores the pre-Apply snapshot for the given task.
func (h *Handler) OnRollback(ctx context.Context, task *myfwv1.RollbackTask) {
	snap, ok := h.last[task.TaskId]
	if !ok {
		h.Log.Warn("rollback requested but no snapshot on hand", "task_id", task.TaskId)
		return
	}
	if err := h.D.Restore(ctx, snap); err != nil {
		h.Log.Error("rollback failed", "task_id", task.TaskId, "err", err)
		return
	}
	delete(h.last, task.TaskId)
	h.Log.Info("rolled back", "task_id", task.TaskId)
}

// static check: Handler satisfies conn.Handler (defined in sibling package).
// We can't import conn here without a cycle, so this remains an implicit
// contract enforced by the compilation of cmd/agent/main.go.
var _ = (*driver.Driver)(nil) // keep the driver package referenced
