// Package conn maintains the Agent's long-lived, mTLS-authenticated gRPC
// connection to the Controller. It exposes:
//   - Dial: one-shot builder for the client-side TLS config and *grpc.ClientConn
//   - Loop: a heartbeat goroutine that runs until ctx is cancelled, reconnecting
//     with exponential backoff on failure.
//
// The Loop is deliberately tolerant of a Controller that hasn't implemented
// AgentStream yet (Unimplemented → log and back off), so the Agent can still
// be installed and observed on a host before M5/M7 land the server side.
package conn

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	myfwv1 "iptables-tool/api/myfw/v1"
)

// TLSMaterial identifies the files an authenticated Agent needs to dial the
// Controller. When BootstrapOnly is true, CertFile/KeyFile may be empty and
// the resulting connection is only good for calling Register.
type TLSMaterial struct {
	CAFile        string
	CertFile      string
	KeyFile       string
	ServerName    string // TLS SNI; falls back to the endpoint host
	BootstrapOnly bool
}

// Dial builds a *grpc.ClientConn to endpoint using the provided TLS material.
// The caller is responsible for closing the returned conn.
func Dial(ctx context.Context, endpoint string, m TLSMaterial) (*grpc.ClientConn, error) {
	tlsCfg, err := buildClientTLS(endpoint, m)
	if err != nil {
		return nil, err
	}
	conn, err := grpc.NewClient(endpoint, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	if err != nil {
		return nil, fmt.Errorf("conn: dial %s: %w", endpoint, err)
	}
	return conn, nil
}

func buildClientTLS(endpoint string, m TLSMaterial) (*tls.Config, error) {
	caPEM, err := os.ReadFile(m.CAFile)
	if err != nil {
		return nil, fmt.Errorf("conn: read CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("conn: no valid certificates in %s", m.CAFile)
	}
	cfg := &tls.Config{
		RootCAs:    pool,
		ServerName: chooseServerName(endpoint, m.ServerName),
		MinVersion: tls.VersionTLS12,
	}
	if !m.BootstrapOnly {
		cert, err := tls.LoadX509KeyPair(m.CertFile, m.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("conn: load client keypair: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	return cfg, nil
}

func chooseServerName(endpoint, override string) string {
	if override != "" {
		return override
	}
	// Strip :port to leave the host as SNI.
	host, _, err := net.SplitHostPort(endpoint)
	if err != nil {
		return endpoint
	}
	return host
}

// HeartbeatOptions tunes the retry/backoff behaviour of Loop. Zero values use
// sensible defaults.
type HeartbeatOptions struct {
	Interval        time.Duration
	InitialBackoff  time.Duration
	MaxBackoff      time.Duration
	CapabilityEvery int // resend Capability every N heartbeats (0 = only first)
}

func (o *HeartbeatOptions) normalize() {
	if o.Interval <= 0 {
		o.Interval = 15 * time.Second
	}
	if o.InitialBackoff <= 0 {
		o.InitialBackoff = 2 * time.Second
	}
	if o.MaxBackoff <= 0 {
		o.MaxBackoff = 60 * time.Second
	}
	if o.CapabilityEvery <= 0 {
		o.CapabilityEvery = 60 // roughly every 15 min at 15s interval
	}
}

// Handler translates downstream Controller messages into local action. The
// Agent supplies a driver-backed implementation; tests can supply a fake.
type Handler interface {
	// OnApply processes an ApplyTask and returns the TaskResult to send back.
	OnApply(ctx context.Context, task *myfwv1.ApplyTask) *myfwv1.TaskResult
	// OnConfirm and OnRollback let higher-level code react to those messages;
	// they may be no-ops on M5.
	OnConfirm(ctx context.Context, task *myfwv1.ConfirmTask)
	OnRollback(ctx context.Context, task *myfwv1.RollbackTask)
}

// Reporter is used by Watchdog to send drift reports and sync requests through the stream.
type Reporter struct {
	log    *slog.Logger
	sendCh chan<- *myfwv1.AgentToController
}

// NewReporter creates a Reporter that sends drift reports through the given channel.
func NewReporter(log *slog.Logger, sendCh chan<- *myfwv1.AgentToController) *Reporter {
	return &Reporter{log: log, sendCh: sendCh}
}

// ReportDrift sends a drift report to the Controller.
func (r *Reporter) ReportDrift(drift *myfwv1.DriftReport) {
	select {
	case r.sendCh <- &myfwv1.AgentToController{
		Payload: &myfwv1.AgentToController_Drift{Drift: drift},
	}:
		if r.log != nil {
			r.log.Info("drift report sent", "node_id", drift.NodeId)
		}
	default:
		if r.log != nil {
			r.log.Warn("drift report dropped (send channel full)")
		}
	}
}

// RequestSync sends a SyncRequest to the Controller to trigger a re-apply.
func (r *Reporter) RequestSync(reason string) {
	select {
	case r.sendCh <- &myfwv1.AgentToController{
		Payload: &myfwv1.AgentToController_Sync{
			Sync: &myfwv1.SyncRequest{Reason: reason},
		},
	}:
		if r.log != nil {
			r.log.Info("sync request sent", "reason", reason)
		}
	default:
		if r.log != nil {
			r.log.Warn("sync request dropped (send channel full)")
		}
	}
}

// ReportState sends a state report to the Controller.
func (r *Reporter) ReportState(state *myfwv1.StateReport) {
	select {
	case r.sendCh <- &myfwv1.AgentToController{
		Payload: &myfwv1.AgentToController_State{State: state},
	}:
		if r.log != nil {
			r.log.Debug("state report sent", "interfaces", len(state.Interfaces))
		}
	default:
		if r.log != nil {
			r.log.Warn("state report dropped (send channel full)")
		}
	}
}

// NopHandler is a Handler that logs but does nothing. Useful before drivers
// are wired.
type NopHandler struct{ Log *slog.Logger }

func (h NopHandler) OnApply(ctx context.Context, t *myfwv1.ApplyTask) *myfwv1.TaskResult {
	if h.Log != nil {
		h.Log.Warn("ApplyTask ignored (no handler wired)", "task_id", t.TaskId)
	}
	return &myfwv1.TaskResult{TaskId: t.TaskId, Ok: false, Message: "no handler wired", TsUnix: time.Now().Unix()}
}
func (h NopHandler) OnConfirm(ctx context.Context, t *myfwv1.ConfirmTask)   {}
func (h NopHandler) OnRollback(ctx context.Context, t *myfwv1.RollbackTask) {}

// Loop opens an AgentStream and pushes a Heartbeat every Interval until ctx
// is cancelled. Any RPC error causes a reconnect with exponential backoff.
// Loop returns nil on clean cancellation, or the last connect error on fatal
// setup failure.
// The sendCh parameter is a shared channel for sending messages from other
// goroutines (like Watchdog) through the stream. It must be created before
// calling Loop and persist across reconnections.
func Loop(ctx context.Context, conn *grpc.ClientConn, log *slog.Logger, nodeID string, cap *myfwv1.Capability, h Handler, opts HeartbeatOptions, sendCh chan *myfwv1.AgentToController) error {
	if h == nil {
		h = NopHandler{Log: log}
	}
	opts.normalize()
	client := myfwv1.NewAgentStreamClient(conn)

	backoff := opts.InitialBackoff
	for {
		if ctx.Err() != nil {
			return nil
		}
		err := runStream(ctx, client, log, nodeID, cap, h, opts, sendCh)
		if ctx.Err() != nil {
			return nil
		}
		// Unimplemented is expected until M5 wires the server side — log at
		// debug so we don't spam INFO with the same line.
		if status.Code(err) == codes.Unimplemented {
			log.Debug("AgentStream not implemented on controller yet", "err", err)
		} else {
			log.Warn("stream ended, backing off", "err", err, "backoff", backoff)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}
		backoff *= 2
		if backoff > opts.MaxBackoff {
			backoff = opts.MaxBackoff
		}
	}
}

// runStream opens one AgentStream, pushes heartbeats until it errors or ctx
// cancels, and returns the terminating error. Downstream messages are
// dispatched to h. The sendCh parameter is a shared channel for messages
// from other goroutines (like Watchdog).
func runStream(ctx context.Context, client myfwv1.AgentStreamClient, log *slog.Logger, nodeID string, cap *myfwv1.Capability, h Handler, opts HeartbeatOptions, sendCh chan *myfwv1.AgentToController) error {
	stream, err := client.Connect(ctx)
	if err != nil {
		return err
	}
	log.Info("stream opened", "node_id", nodeID)

	// Serialize sends onto a single goroutine — a gRPC ClientStream is not
	// safe for concurrent SendMsg calls.
	rxErr := make(chan error, 1)

	// RX goroutine: dispatches Controller-to-Agent messages.
	go func() {
		for {
			msg, err := stream.Recv()
			if err != nil {
				rxErr <- err
				return
			}
			switch p := msg.Payload.(type) {
			case *myfwv1.ControllerToAgent_Apply:
				res := h.OnApply(ctx, p.Apply)
				if res != nil {
					select {
					case sendCh <- &myfwv1.AgentToController{Payload: &myfwv1.AgentToController_TaskResult{TaskResult: res}}:
					case <-ctx.Done():
						return
					}
				}
			case *myfwv1.ControllerToAgent_Confirm:
				h.OnConfirm(ctx, p.Confirm)
			case *myfwv1.ControllerToAgent_Rollback:
				h.OnRollback(ctx, p.Rollback)
			case *myfwv1.ControllerToAgent_Sync:
				log.Debug("sync requested", "reason", p.Sync.Reason)
			case *myfwv1.ControllerToAgent_Ack:
				// heartbeat ack — nothing to do beyond keepalive.
			default:
				log.Warn("unknown downstream payload")
			}
		}
	}()

	tick := time.NewTicker(opts.Interval)
	defer tick.Stop()

	sendHB := func(count int) *myfwv1.AgentToController {
		hb := &myfwv1.Heartbeat{
			NodeId: nodeID,
			TsUnix: time.Now().Unix(),
		}
		if count == 0 || (opts.CapabilityEvery > 0 && count%opts.CapabilityEvery == 0) {
			hb.Capability = cap
		}
		return &myfwv1.AgentToController{
			Payload: &myfwv1.AgentToController_Heartbeat{Heartbeat: hb},
		}
	}

	// Fire an immediate heartbeat.
	if err := stream.Send(sendHB(0)); err != nil {
		return err
	}
	count := 1

	for {
		select {
		case <-ctx.Done():
			_ = stream.CloseSend()
			return nil
		case err := <-rxErr:
			if errors.Is(err, context.Canceled) {
				return nil
			}
			return err
		case <-tick.C:
			if err := stream.Send(sendHB(count)); err != nil {
				return err
			}
			count++
		case msg := <-sendCh:
			if err := stream.Send(msg); err != nil {
				return err
			}
		}
	}
}
