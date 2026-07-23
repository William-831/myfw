package watchdog

import (
	"context"
	"sync"
	"testing"
	"time"

	myfwv1 "iptables-tool/api/myfw/v1"
)

// fakeDriver is a test double that returns a configurable hash.
type fakeDriver struct {
	mu   sync.RWMutex
	hash string
	err  error
}

func (f *fakeDriver) Hash(ctx context.Context) (string, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.hash, f.err
}

func (f *fakeDriver) setHash(hash string) {
	f.mu.Lock()
	f.hash = hash
	f.mu.Unlock()
}

func (f *fakeDriver) setErr(err error) {
	f.mu.Lock()
	f.err = err
}

// fakeReporter captures drift reports and sync requests for testing.
type fakeReporter struct {
	mu         sync.Mutex
	reports    []*myfwv1.DriftReport
	syncReqs   []string
}

func (f *fakeReporter) ReportDrift(drift *myfwv1.DriftReport) {
	f.mu.Lock()
	f.reports = append(f.reports, drift)
	f.mu.Unlock()
}

func (f *fakeReporter) RequestSync(reason string) {
	f.mu.Lock()
	f.syncReqs = append(f.syncReqs, reason)
	f.mu.Unlock()
}

func (f *fakeReporter) getReports() []*myfwv1.DriftReport {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*myfwv1.DriftReport(nil), f.reports...)
}

func (f *fakeReporter) getSyncReqs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.syncReqs...)
}

func TestNoDrift(t *testing.T) {
	d := &fakeDriver{hash: "sha256:abc123"}
	r := &fakeReporter{}
	w := New(d, r, nil, Options{
		Interval: time.Millisecond * 50,
		NodeID:   "test-node",
	})

	w.SetExpectedHash("sha256:abc123")
	w.Start()
	defer w.Stop()

	time.Sleep(time.Millisecond * 200)

	reports := r.getReports()
	if len(reports) != 0 {
		t.Fatalf("expected no drift reports, got %d", len(reports))
	}
}

func TestDriftDetected(t *testing.T) {
	d := &fakeDriver{hash: "sha256:original"}
	r := &fakeReporter{}
	w := New(d, r, nil, Options{
		Interval: time.Millisecond * 50,
		NodeID:   "test-node",
	})

	w.SetExpectedHash("sha256:original")
	w.Start()
	defer w.Stop()

	// Let it check once to establish no drift.
	time.Sleep(time.Millisecond * 70)

	// Now change the hash to simulate external modification.
	d.setHash("sha256:modified")

	// Wait for a few checks.
	time.Sleep(time.Millisecond * 200)

	reports := r.getReports()
	if len(reports) == 0 {
		t.Fatal("expected at least one drift report")
	}

	last := reports[len(reports)-1]
	if last.NodeId != "test-node" {
		t.Errorf("expected node_id=test-node, got %s", last.NodeId)
	}
	if last.ExpectedHash != "sha256:original" {
		t.Errorf("expected expected_hash=sha256:original, got %s", last.ExpectedHash)
	}
	if last.ActualHash != "sha256:modified" {
		t.Errorf("expected actual_hash=sha256:modified, got %s", last.ActualHash)
	}
	if last.Detail == "" {
		t.Error("expected non-empty detail")
	}
}

func TestNoExpectedHash(t *testing.T) {
	d := &fakeDriver{hash: "sha256:anything"}
	r := &fakeReporter{}
	w := New(d, r, nil, Options{
		Interval: time.Millisecond * 50,
		NodeID:   "test-node",
	})

	// Don't set expected hash - watchdog should skip checking.
	w.Start()
	defer w.Stop()

	time.Sleep(time.Millisecond * 200)

	reports := r.getReports()
	if len(reports) != 0 {
		t.Fatalf("expected no drift reports without baseline, got %d", len(reports))
	}
}

func TestHashError(t *testing.T) {
	d := &fakeDriver{err: &driftError{"test error"}}
	r := &fakeReporter{}
	w := New(d, r, nil, Options{
		Interval: time.Millisecond * 50,
		NodeID:   "test-node",
	})

	w.SetExpectedHash("sha256:expected")
	w.Start()
	defer w.Stop()

	time.Sleep(time.Millisecond * 200)

	reports := r.getReports()
	if len(reports) != 0 {
		t.Fatalf("expected no drift reports on hash error, got %d", len(reports))
	}
}

func TestDisabled(t *testing.T) {
	d := &fakeDriver{hash: "sha256:expected"}
	r := &fakeReporter{}
	w := New(d, r, nil, Options{
		Interval: 0, // disabled
		NodeID:   "test-node",
	})

	w.SetExpectedHash("sha256:different")
	w.Start()
	defer w.Stop()

	time.Sleep(time.Millisecond * 100)

	reports := r.getReports()
	if len(reports) != 0 {
		t.Fatalf("expected no drift reports when disabled, got %d", len(reports))
	}
}

func TestNilDriver(t *testing.T) {
	r := &fakeReporter{}
	w := New(nil, r, nil, Options{
		Interval: time.Millisecond * 50,
		NodeID:   "test-node",
	})

	w.SetExpectedHash("sha256:expected")
	w.Start()
	defer w.Stop()

	time.Sleep(time.Millisecond * 100)

	reports := r.getReports()
	if len(reports) != 0 {
		t.Fatalf("expected no drift reports with nil driver, got %d", len(reports))
	}
}

type driftError struct{ msg string }

func (e *driftError) Error() string { return e.msg }
