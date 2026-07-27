// Package stream implements the server side of the myfw.v1.AgentStream
// bidirectional RPC. It maintains a registry of currently-connected agents
// so other controller modules (task dispatch) can push messages downstream.
//
// M5 scope: connection tracking, heartbeat receive, ApplyTask push, TaskResult
// receive. Full task state machine + persistent queue land in M6/M7.
// See docs/design.md § 11 / § 13.
package stream

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"gorm.io/gorm"

	myfwv1 "iptables-tool/api/myfw/v1"
	"iptables-tool/internal/controller/audit"
	"iptables-tool/internal/model"
	"iptables-tool/internal/pki"
)

// Service implements myfwv1.AgentStreamServer.
type Service struct {
	myfwv1.UnimplementedAgentStreamServer

	DB    *gorm.DB
	Log   *slog.Logger
	Reg   *Registry
	Audit *audit.Sink

	// subscribers receive every TaskResult; each one filters by task id.
	// New in M6 to allow multiple concurrent Apply orchestrators without
	// stealing each other's results.
	subMu sync.Mutex
	subs  []chan *myfwv1.TaskResult
}

// New builds a Service with an empty registry.
func New(db *gorm.DB, log *slog.Logger, audit *audit.Sink) *Service {
	return &Service{
		DB:    db,
		Log:   log,
		Reg:   NewRegistry(),
		Audit: audit,
	}
}

// SubscribeTaskResults returns a receive-only channel that gets a copy of
// every TaskResult observed on any Agent stream. The channel is buffered;
// slow subscribers get dropped rather than blocking upstream. Call the
// returned cancel func to unsubscribe.
func (s *Service) SubscribeTaskResults() (<-chan *myfwv1.TaskResult, func()) {
	ch := make(chan *myfwv1.TaskResult, 64)
	s.subMu.Lock()
	s.subs = append(s.subs, ch)
	s.subMu.Unlock()

	cancel := func() {
		s.subMu.Lock()
		defer s.subMu.Unlock()
		for i, c := range s.subs {
			if c == ch {
				s.subs = append(s.subs[:i], s.subs[i+1:]...)
				close(ch)
				return
			}
		}
	}
	return ch, cancel
}

// broadcastTaskResult fans a TaskResult out to every current subscriber.
// Non-blocking; a full subscriber channel loses the message.
func (s *Service) broadcastTaskResult(res *myfwv1.TaskResult) {
	s.subMu.Lock()
	subs := s.subs
	s.subMu.Unlock()
	for _, ch := range subs {
		select {
		case ch <- res:
		default:
			s.Log.Warn("task result subscriber slow; dropping", "task_id", res.TaskId)
		}
	}
}

// Connect is the server side of the bidi stream. One goroutine per connection.
// It identifies the caller by client certificate, registers it, and then
// forwards downstream messages until the client disconnects or ctx cancels.
func (s *Service) Connect(stream myfwv1.AgentStream_ConnectServer) error {
	ctx := stream.Context()
	nodeID, err := nodeIDFromContext(ctx)
	if err != nil {
		return err
	}

	// Sanity: node must still exist and not be archived. The auth interceptor
	// has already checked this at connection time, but we re-check because
	// a stream can outlive an admin-triggered archival.
	if archived, err := s.isArchived(ctx, nodeID); err != nil {
		return status.Errorf(codes.Internal, "lookup node: %v", err)
	} else if archived {
		return status.Error(codes.PermissionDenied, "node archived")
	}

	send := make(chan *myfwv1.ControllerToAgent, 16)
	handle := s.Reg.Register(nodeID, send)
	defer s.Reg.Deregister(handle)

	s.Log.Info("agent stream connected", "node_id", nodeID)
	defer s.Log.Info("agent stream closed", "node_id", nodeID)

	// Send goroutine: forwards messages queued on `send` to the wire.
	sendErr := make(chan error, 1)
	go func() {
		for {
			select {
			case <-ctx.Done():
				sendErr <- ctx.Err()
				return
			case msg, ok := <-send:
				if !ok {
					sendErr <- nil
					return
				}
				if err := stream.Send(msg); err != nil {
					sendErr <- err
					return
				}
			}
		}
	}()

	// Receive loop: read from the wire until EOF or ctx cancel.
	for {
		msg, err := stream.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return <-sendErr
			}
			return err
		}
		s.handleUpstream(ctx, nodeID, msg)
	}
}

func (s *Service) handleUpstream(ctx context.Context, nodeID string, msg *myfwv1.AgentToController) {
	switch p := msg.Payload.(type) {
	case *myfwv1.AgentToController_Heartbeat:
		s.onHeartbeat(ctx, nodeID, p.Heartbeat)
	case *myfwv1.AgentToController_TaskResult:
		s.Log.Info("task result",
			"node_id", nodeID,
			"task_id", p.TaskResult.TaskId,
			"ok", p.TaskResult.Ok,
			"hash", p.TaskResult.ResultHash,
			"msg", p.TaskResult.Message)
		s.broadcastTaskResult(p.TaskResult)
	case *myfwv1.AgentToController_Drift:
		s.Log.Warn("drift reported", "node_id", nodeID,
			"expected", p.Drift.ExpectedHash, "actual", p.Drift.ActualHash)
		s.auditDrift(ctx, nodeID, p.Drift)
	case *myfwv1.AgentToController_Sync:
		s.Log.Info("sync requested", "node_id", nodeID, "reason", p.Sync.Reason)
	case *myfwv1.AgentToController_State:
		// M10 will wire this; drop with a debug log for now.
		s.Log.Debug("state report", "node_id", nodeID)
	default:
		s.Log.Warn("unknown upstream payload", "node_id", nodeID)
	}
}

// onHeartbeat updates node.LastSeen and, if a Capability is attached,
// replaces the persisted NodeCapability row.
func (s *Service) onHeartbeat(ctx context.Context, nodeID string, hb *myfwv1.Heartbeat) {
	if hb == nil {
		return
	}
	now := time.Now().UTC()
	// 从 gRPC 上下文中提取客户端 IP 并更新
	ip := extractIPFromContext(ctx)
	updates := map[string]any{"last_seen": &now}
	if ip != "" {
		updates["ip"] = ip
	}
	if err := s.DB.WithContext(ctx).
		Model(&model.Node{}).
		Where("id = ?", nodeID).
		Updates(updates).Error; err != nil {
		s.Log.Warn("update last_seen", "node_id", nodeID, "err", err)
	}
}

// extractIPFromContext 从 gRPC 上下文中提取客户端 IP 地址
func extractIPFromContext(ctx context.Context) string {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return ""
	}
	addr, ok := p.Addr.(*net.TCPAddr)
	if !ok {
		host, _, err := net.SplitHostPort(p.Addr.String())
		if err != nil {
			return p.Addr.String()
		}
		return host
	}
	return addr.IP.String()
}

func (s *Service) isArchived(ctx context.Context, nodeID string) (bool, error) {
	var n model.Node
	if err := s.DB.WithContext(ctx).Where("id = ?", nodeID).First(&n).Error; err != nil {
		return false, err
	}
	return n.Status == model.NodeStatusArchived, nil
}

// auditDrift writes a drift event to the audit log.
func (s *Service) auditDrift(ctx context.Context, nodeID string, drift *myfwv1.DriftReport) {
	if s.Audit == nil {
		return
	}
	detail, _ := json.Marshal(map[string]any{
		"expected_hash": drift.ExpectedHash,
		"actual_hash":   drift.ActualHash,
		"detail":        drift.Detail,
	})
	_ = s.Audit.Write(ctx, model.AuditLog{
		Actor:  "agent",
		Action: "node.drift",
		NodeID: nodeID,
		Detail: string(detail),
	})
}

// --- helpers ----------------------------------------------------------------

// nodeIDFromContext extracts the node id from the client certificate the
// stream was established with. mTLS is enforced by the auth interceptor for
// every non-bootstrap method, so we can rely on a certificate being present.
func nodeIDFromContext(ctx context.Context) (string, error) {
	// 首先尝试从 metadata 中获取 node_id（用于无 mTLS 模式）
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if vals := md.Get("x-node-id"); len(vals) > 0 && vals[0] != "" {
			return vals[0], nil
		}
	}

	// 回退到从客户端证书中提取 node_id（mTLS 模式）
	p, ok := peer.FromContext(ctx)
	if !ok {
		return "", status.Error(codes.Unauthenticated, "no peer info")
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return "", status.Error(codes.Unauthenticated, "not a TLS connection")
	}
	if len(tlsInfo.State.VerifiedChains) == 0 || len(tlsInfo.State.VerifiedChains[0]) == 0 {
		return "", status.Error(codes.Unauthenticated, "client certificate required")
	}
	nid, err := pki.NodeIDFromCert(tlsInfo.State.VerifiedChains[0][0])
	if err != nil {
		return "", status.Errorf(codes.Unauthenticated, "extract node id: %v", err)
	}
	return nid, nil
}

// --- registry ---------------------------------------------------------------

// Registry tracks currently-connected agents by node id, giving other modules
// (task dispatch, drift response) a way to push a message downstream.
type Registry struct {
	mu    sync.RWMutex
	seq   uint64
	conns map[string][]conn
}

type conn struct {
	handle uint64
	send   chan<- *myfwv1.ControllerToAgent
}

// Handle identifies a live registration so Deregister can remove exactly the
// right entry when a stream ends (a node may briefly have overlapping
// registrations while reconnecting).
type Handle struct {
	NodeID string
	seq    uint64
}

func NewRegistry() *Registry { return &Registry{conns: map[string][]conn{}} }

// Register adds a connection under nodeID and returns a Handle for later
// deregistration.
func (r *Registry) Register(nodeID string, send chan<- *myfwv1.ControllerToAgent) Handle {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seq++
	r.conns[nodeID] = append(r.conns[nodeID], conn{handle: r.seq, send: send})
	return Handle{NodeID: nodeID, seq: r.seq}
}

// Deregister removes the connection identified by h. It's a no-op if h has
// already been removed.
func (r *Registry) Deregister(h Handle) {
	r.mu.Lock()
	defer r.mu.Unlock()
	list := r.conns[h.NodeID]
	for i, c := range list {
		if c.handle == h.seq {
			r.conns[h.NodeID] = append(list[:i], list[i+1:]...)
			break
		}
	}
	if len(r.conns[h.NodeID]) == 0 {
		delete(r.conns, h.NodeID)
	}
}

// Send delivers msg to the newest registered connection for nodeID. Returns
// an error if the node is not currently connected. Non-blocking: if the
// per-connection send channel is full, the message is dropped and an error
// is returned so the caller can retry / persist.
func (r *Registry) Send(nodeID string, msg *myfwv1.ControllerToAgent) error {
	r.mu.RLock()
	list := r.conns[nodeID]
	if len(list) == 0 {
		r.mu.RUnlock()
		return status.Errorf(codes.FailedPrecondition, "node %s not connected", nodeID)
	}
	// Newest wins (a fresh reconnect supersedes stale ones).
	c := list[len(list)-1]
	r.mu.RUnlock()

	select {
	case c.send <- msg:
		return nil
	default:
		return status.Errorf(codes.ResourceExhausted, "node %s send queue full", nodeID)
	}
}

// Connected reports the ids of all currently-connected nodes.
func (r *Registry) Connected() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.conns))
	for id := range r.conns {
		out = append(out, id)
	}
	return out
}
