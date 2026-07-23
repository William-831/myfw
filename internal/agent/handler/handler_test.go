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
	ApplyRules   []*myfwv1.CompiledRule
	RestoreCalls []string
}

func (f *fakeDriver) Snapshot(ctx context.Context) (string, string, error) {
	return f.SnapshotOut, "sha256:snap", f.SnapshotErr
}
func (f *fakeDriver) Apply(ctx context.Context, r []*myfwv1.CompiledRule) (string, error) {
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
	if len(f.ApplyRules) != 1 {
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
