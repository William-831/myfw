// Package watchdog periodically checks if the live MYFW namespace still matches
// the expected hash from the last successful Apply. When drift is detected,
// it reports to the Controller via the AgentStream. See design.md § 12.
package watchdog

import (
	"context"
	"log/slog"
	"sync"
	"time"

	myfwv1 "iptables-tool/api/myfw/v1"
)

// Driver is the subset of driver.Driver needed for Watchdog.
type Driver interface {
	Hash(ctx context.Context) (string, error)
}

// Reporter sends drift reports and sync requests back to the Controller.
type Reporter interface {
	ReportDrift(drift *myfwv1.DriftReport)
	RequestSync(reason string)
}

// Options configures the Watchdog's behavior.
type Options struct {
	// Interval is how often to check for drift. Zero means disabled.
	Interval time.Duration
	// NodeID is the agent's identity for reports.
	NodeID string
	// AutoRecover, if true, triggers a SyncRequest when drift is detected
	// so the Controller can re-apply the correct rules. When false, only
	// reports drift without recovery.
	AutoRecover bool
}

// Watchdog monitors the MYFW namespace for unexpected changes.
type Watchdog struct {
	D      Driver
	Rep    Reporter
	Log    *slog.Logger
	Opts   Options
	ctx    context.Context
	cancel context.CancelFunc

	// mu protects expectedHash and isRunning.
	mu           sync.RWMutex
	expectedHash string // the hash we expect (set after successful Apply)
	isRunning    bool
}

// New builds a Watchdog. If d is nil, the watchdog is inert (drift checks
// are skipped).
func New(d Driver, rep Reporter, log *slog.Logger, opts Options) *Watchdog {
	ctx, cancel := context.WithCancel(context.Background())
	return &Watchdog{
		D:      d,
		Rep:    rep,
		Log:    log,
		Opts:   opts,
		ctx:    ctx,
		cancel: cancel,
	}
}

// Start begins the periodic drift checking loop. Non-blocking.
func (w *Watchdog) Start() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.isRunning || w.D == nil || w.Opts.Interval <= 0 {
		return
	}
	w.isRunning = true
	go w.loop()
}

// Stop halts the watchdog. Safe to call multiple times.
func (w *Watchdog) Stop() {
	w.cancel()
	w.mu.Lock()
	w.isRunning = false
	w.mu.Unlock()
}

// SetExpectedHash updates the hash we expect to find. Call this after a
// successful Apply to arm the watchdog.
func (w *Watchdog) SetExpectedHash(hash string) {
	w.mu.Lock()
	w.expectedHash = hash
	w.mu.Unlock()
	if w.Log != nil {
		w.Log.Info("watchdog: expected hash updated", "hash", hash)
	}
}

// GetExpectedHash returns the currently expected hash (empty if never set).
func (w *Watchdog) GetExpectedHash() string {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.expectedHash
}

// loop runs until ctx is cancelled, checking for drift at each interval.
func (w *Watchdog) loop() {
	tick := time.NewTicker(w.Opts.Interval)
	defer tick.Stop()

	for {
		select {
		case <-w.ctx.Done():
			return
		case <-tick.C:
			w.checkOnce()
		}
	}
}

// checkOnce computes the current hash and compares it with the expected hash.
// Reports drift if they differ.
func (w *Watchdog) checkOnce() {
	w.mu.RLock()
	expected := w.expectedHash
	w.mu.RUnlock()

	if expected == "" {
		// No baseline yet (first start, or no Apply has succeeded).
		return
	}

	current, err := w.D.Hash(w.ctx)
	if err != nil {
		if w.Log != nil {
			w.Log.Warn("watchdog: hash check failed", "err", err)
		}
		return
	}

	if current == expected {
		return // No drift.
	}

	// Drift detected!
	if w.Log != nil {
		w.Log.Error("watchdog: drift detected",
			"expected", expected,
			"actual", current)
	}

	if w.Rep != nil {
		w.Rep.ReportDrift(&myfwv1.DriftReport{
			NodeId:       w.Opts.NodeID,
			ExpectedHash: expected,
			ActualHash:   current,
			Detail:       "external modification detected in MYFW namespace",
			TsUnix:       time.Now().Unix(),
		})
	}

	if w.Opts.AutoRecover && w.Rep != nil {
		if w.Log != nil {
			w.Log.Info("watchdog: requesting sync to recover from drift")
		}
		w.Rep.RequestSync("drift detected: expected hash " + expected + ", got " + current)
	}
}
