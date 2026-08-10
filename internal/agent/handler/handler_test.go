package handler

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	myfwv1 "iptables-tool/api/myfw/v1"
)

// fakeDriver lets tests script Snapshot/Apply/Restore behaviour.
type fakeDriver struct {
	SnapshotOut  string
	SnapshotErr  error
	ApplyHash    string
	ApplyErr     error
	RestoreErr   error
	ApplyRules   *myfwv1.RuleSet
	RestoreCalls []string
}

func (f *fakeDriver) Snapshot(ctx context.Context) (string, string, error) {
	return f.SnapshotOut, "sha256:snap", f.SnapshotErr
}
func (f *fakeDriver) Apply(ctx context.Context, r *myfwv1.RuleSet) (string, error) {
	f.ApplyRules = r
	return f.ApplyHash, f.ApplyErr
}
func (f *fakeDriver) Restore(ctx context.Context, p string) error {
	f.RestoreCalls = append(f.RestoreCalls, p)
	return f.RestoreErr
}

func TestOnApplySuccess(t *testing.T) {
	f := &fakeDriver{SnapshotOut: "SNAP1", ApplyHash: "sha256:new"}
	h := New(f, slog.Default())

	rules := []*myfwv1.CompiledRule{{Id: "r1", Action: myfwv1.Action_ACTION_ACCEPT}}
	res := h.OnApply(context.Background(), &myfwv1.ApplyTask{TaskId: "t1", RuleSet: &myfwv1.RuleSet{Rules: rules}})

	if !res.Ok || res.ResultHash != "sha256:new" {
		t.Fatalf("unexpected: %+v", res)
	}
	if len(f.ApplyRules.GetRules()) != 1 {
		t.Fatalf("driver never saw rules")
	}
	if len(f.RestoreCalls) != 0 {
		t.Fatalf("Restore should NOT be called on success")
	}
	if _, ok := h.last["t1"]; !ok {
		t.Fatal("snapshot not retained for later rollback")
	}
}

func TestOnApplyFailureTriggersSelfRollback(t *testing.T) {
	f := &fakeDriver{SnapshotOut: "SNAP-PRE", ApplyErr: errors.New("boom")}
	h := New(f, slog.Default())

	res := h.OnApply(context.Background(), &myfwv1.ApplyTask{TaskId: "t2",
		RuleSet: &myfwv1.RuleSet{Rules: []*myfwv1.CompiledRule{{Id: "x"}}}})

	if res.Ok {
		t.Fatal("apply that failed shouldn't be Ok")
	}
	if len(f.RestoreCalls) != 1 || f.RestoreCalls[0] != "SNAP-PRE" {
		t.Fatalf("self-rollback didn't restore the pre-apply snapshot: %v", f.RestoreCalls)
	}
}

func TestOnRollbackWithoutSnapshotIsSafe(t *testing.T) {
	f := &fakeDriver{}
	h := New(f, slog.Default())
	// No prior OnApply — the map is empty.
	h.OnRollback(context.Background(), &myfwv1.RollbackTask{TaskId: "nope"})
	if len(f.RestoreCalls) != 0 {
		t.Fatal("Restore called for unknown task id")
	}
}

func TestOnConfirmClearsSnapshot(t *testing.T) {
	f := &fakeDriver{SnapshotOut: "S", ApplyHash: "sha256:x"}
	h := New(f, slog.Default())
	h.OnApply(context.Background(), &myfwv1.ApplyTask{TaskId: "t3", RuleSet: &myfwv1.RuleSet{}})
	if _, ok := h.last["t3"]; !ok {
		t.Fatal("precondition: snapshot should be retained after Apply")
	}
	h.OnConfirm(context.Background(), &myfwv1.ConfirmTask{TaskId: "t3"})
	if _, ok := h.last["t3"]; ok {
		t.Fatal("Confirm should clear the retained snapshot")
	}
}

func TestOnApplyWithNilDriverGracefullyFails(t *testing.T) {
	h := New(nil, slog.Default())
	res := h.OnApply(context.Background(), &myfwv1.ApplyTask{TaskId: "t"})
	if res.Ok {
		t.Fatal("nil driver: Ok should be false")
	}
	if res.Message == "" {
		t.Fatal("nil driver: message should explain the situation")
	}
}

// recordingNotifier 记录 SetExpectedHash 的调用序列,用于验证 watchdog 期望值更新。
type recordingNotifier struct{ hashes []string }

func (r *recordingNotifier) SetExpectedHash(h string) { r.hashes = append(r.hashes, h) }

// TestOnRollbackUpdatesExpectedHash 验证回滚恢复快照后把 watchdog expected 更新为
// 快照 hash:避免恢复后的规则被误判为 drift,杜绝"自愈→回滚→再漂移→再自愈"死循环。
// 红阶段:修复前 OnRollback 不通知 HashNotifier,expected 停留在 apply 后 hash。
func TestOnRollbackUpdatesExpectedHash(t *testing.T) {
	f := &fakeDriver{SnapshotOut: "SNAP", ApplyHash: "sha256:applied"}
	n := &recordingNotifier{}
	h := New(f, slog.Default())
	h.SetHashNotifier(n)

	// apply 后 expected = 期望态 hash
	h.OnApply(context.Background(), &myfwv1.ApplyTask{TaskId: "t4",
		RuleSet: &myfwv1.RuleSet{Rules: []*myfwv1.CompiledRule{{Id: "r"}}}})
	if len(n.hashes) != 1 || n.hashes[0] != "sha256:applied" {
		t.Fatalf("apply 后应通知 expected=applied hash, got %v", n.hashes)
	}

	// 回滚后 expected 应更新为快照 hash(而非停留在 applied hash)
	h.OnRollback(context.Background(), &myfwv1.RollbackTask{TaskId: "t4"})
	if len(f.RestoreCalls) != 1 || f.RestoreCalls[0] != "SNAP" {
		t.Fatalf("rollback 未恢复快照: %v", f.RestoreCalls)
	}
	if len(n.hashes) != 2 || n.hashes[1] != "sha256:snap" {
		t.Fatalf("rollback 后应通知 expected=snapshot hash(sha256:snap), got %v", n.hashes)
	}
}

// TestOnConfirmClearsSnapshotHash 验证 Confirm 同时清除快照与快照 hash 记录。
func TestOnConfirmClearsSnapshotHash(t *testing.T) {
	f := &fakeDriver{SnapshotOut: "S", ApplyHash: "sha256:x"}
	h := New(f, slog.Default())
	h.OnApply(context.Background(), &myfwv1.ApplyTask{TaskId: "t5", RuleSet: &myfwv1.RuleSet{}})
	if _, ok := h.last["t5"]; !ok {
		t.Fatal("precondition: snapshot should be retained after Apply")
	}
	h.OnConfirm(context.Background(), &myfwv1.ConfirmTask{TaskId: "t5"})
	if _, ok := h.last["t5"]; ok {
		t.Fatal("Confirm should clear the retained snapshot")
	}
	if _, ok := h.lastHash["t5"]; ok {
		t.Fatal("Confirm should clear the retained snapshot hash")
	}
}

// TestOnDecommissionInvokesFn 验证注销指令触发自毁回调并传递 reason。
func TestOnDecommissionInvokesFn(t *testing.T) {
	var gotReason string
	called := false
	h := New(nil, slog.Default())
	h.DecommissionFn = func(ctx context.Context, reason string) error {
		called = true
		gotReason = reason
		return nil
	}
	h.OnDecommission(context.Background(), &myfwv1.DecommissionCommand{Reason: "node deleted"})
	if !called {
		t.Fatal("DecommissionFn 未被调用")
	}
	if gotReason != "node deleted" {
		t.Fatalf("reason 传递错误: got %q", gotReason)
	}
}

// TestOnDecommissionNilFnNoPanic 验证未注入回调时不 panic（仅记日志）。
func TestOnDecommissionNilFnNoPanic(t *testing.T) {
	h := New(nil, slog.Default())
	h.OnDecommission(context.Background(), &myfwv1.DecommissionCommand{Reason: "test"})
}
