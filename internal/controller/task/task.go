// Package task orchestrates apply dispatch: it computes each target node's
// desired RuleSet from the policy DB, pushes an ApplyTask onto the stream
// registry, and aggregates the returned TaskResults. Persistent task queue
// (design.md § 11) is deferred to M7; this package provides the synchronous
// slice-and-fan-out primitive M6 needs.
package task

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/google/uuid"

	myfwv1 "iptables-tool/api/myfw/v1"
	"iptables-tool/internal/controller/compiler"
	"iptables-tool/internal/controller/stream"
)

// Dispatcher owns references to the stream + compiler; wire it once at server
// startup.
type Dispatcher struct {
	Stream *stream.Service
	Comp   *compiler.Compiler
}

func New(s *stream.Service, c *compiler.Compiler) *Dispatcher {
	return &Dispatcher{Stream: s, Comp: c}
}

// NodeOutcome is one row of an apply's per-node result.
type NodeOutcome struct {
	NodeID     string `json:"node_id"`
	TaskID     string `json:"task_id,omitempty"`
	Ok         bool   `json:"ok"`
	Message    string `json:"message,omitempty"`
	ResultHash string `json:"result_hash,omitempty"`
	Error      string `json:"error,omitempty"` // set when dispatch/wait itself failed, not the agent
}

// ApplyOptions tunes an apply run. Zero values are sensible.
type ApplyOptions struct {
	// ConfirmDeadline is how long the agent is instructed to hold before
	// self-rollback. Not enforced by M6 (auto-rollback lands in M7); still
	// stamped on the wire so agents have a hint.
	ConfirmDeadline time.Duration
	// WaitFor is how long we wait synchronously for each agent's TaskResult
	// after dispatch.
	WaitFor time.Duration
}

func (o *ApplyOptions) normalize() {
	if o.ConfirmDeadline <= 0 {
		o.ConfirmDeadline = 30 * time.Second
	}
	if o.WaitFor <= 0 {
		o.WaitFor = 10 * time.Second
	}
}

// ApplyToNodes compiles each node's ruleset from the policy DB and dispatches
// an ApplyTask in parallel. Blocks until every dispatched task returns a
// result or the per-node WaitFor expires. Order of outcomes matches nodeIDs.
func (d *Dispatcher) ApplyToNodes(ctx context.Context, nodeIDs []string, opts ApplyOptions) ([]NodeOutcome, error) {
	if len(nodeIDs) == 0 {
		return nil, errors.New("task: no target nodes")
	}
	opts.normalize()

	// Subscribe BEFORE any Send so a fast agent can't race us.
	resultsCh, unsub := d.Stream.SubscribeTaskResults()
	defer unsub()

	outcomes := make([]NodeOutcome, len(nodeIDs))
	expected := map[string]int{} // task_id -> outcome index

	// --- Dispatch ---------------------------------------------------------
	for i, id := range nodeIDs {
		outcomes[i].NodeID = id
		rules, err := d.Comp.CompileForNode(ctx, id)
		if err != nil {
			outcomes[i].Error = "compile: " + err.Error()
			continue
		}
		tid := "t_" + uuid.NewString()
		outcomes[i].TaskID = tid
		expected[tid] = i

		msg := &myfwv1.ControllerToAgent{
			Payload: &myfwv1.ControllerToAgent_Apply{
				Apply: &myfwv1.ApplyTask{
					TaskId: tid,
					RuleSet: &myfwv1.RuleSet{
						NodeId:  id,
						Version: time.Now().Unix(),
						Rules:   rules,
					},
					ConfirmDeadlineUnix: time.Now().Add(opts.ConfirmDeadline).Unix(),
				},
			},
		}
		if err := d.Stream.Reg.Send(id, msg); err != nil {
			outcomes[i].Error = "dispatch: " + err.Error()
			delete(expected, tid)
			outcomes[i].TaskID = ""
		}
	}

	// --- Collect ---------------------------------------------------------
	if len(expected) == 0 {
		return outcomes, nil
	}
	deadline := time.After(opts.WaitFor)
	var mu sync.Mutex // guards `expected` during matching
	for len(expected) > 0 {
		select {
		case <-ctx.Done():
			markMissingTimeout(&mu, &expected, outcomes, "cancelled")
			return outcomes, nil
		case <-deadline:
			markMissingTimeout(&mu, &expected, outcomes, "timeout waiting for result")
			return outcomes, nil
		case res, ok := <-resultsCh:
			if !ok {
				markMissingTimeout(&mu, &expected, outcomes, "subscription closed")
				return outcomes, nil
			}
			mu.Lock()
			idx, want := expected[res.TaskId]
			if want {
				outcomes[idx].Ok = res.Ok
				outcomes[idx].Message = res.Message
				outcomes[idx].ResultHash = res.ResultHash
				delete(expected, res.TaskId)
			}
			mu.Unlock()
		}
	}
	return outcomes, nil
}

func markMissingTimeout(mu *sync.Mutex, expected *map[string]int, outcomes []NodeOutcome, msg string) {
	mu.Lock()
	defer mu.Unlock()
	for _, idx := range *expected {
		outcomes[idx].Error = msg
	}
	*expected = map[string]int{}
}
