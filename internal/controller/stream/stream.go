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
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
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

	// rulesWaiters: 一次性通知通道，RequestRulesAndWait 调用方在此阻塞，
	// Agent 上报 IptablesRules 时被唤醒。
	rulesMu      sync.Mutex
	rulesWaiters map[string]chan struct{}

	// OnSync 在 Agent 请求 sync(drift 恢复)时被调用,触发 Controller 重新下发期望态。
	// 由 server.go 注入(避免 stream 直接依赖 task 包造成循环导入)。nil 时仅记日志。
	// 回调内部应异步执行(Apply 不阻塞 stream 处理)。
	OnSync func(nodeID string)

	// CompileExpected 编译节点期望规则集(drift 分类用),由 server.go 注入
	// (包装 compiler.CompileForNode,避免 stream 直接依赖 compiler 包)。nil 时分类回落 unspecified。
	CompileExpected func(ctx context.Context, nodeID string) ([]*myfwv1.CompiledRule, error)
}

// New builds a Service with an empty registry.
func New(db *gorm.DB, log *slog.Logger, audit *audit.Sink) *Service {
	return &Service{
		DB:           db,
		Log:          log,
		Reg:          NewRegistry(),
		Audit:        audit,
		rulesWaiters: map[string]chan struct{}{},
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
		// 触发重新下发期望态(drift 恢复):回调由 server.go 注入,异步 Apply 不阻塞 stream。
		// 修复 drift 死循环:原仅记日志不 Apply,导致 expected 永不更新、30s 后又 drift。
		if s.OnSync != nil {
			s.OnSync(nodeID)
		}
	case *myfwv1.AgentToController_State:
		// M10 will wire this; drop with a debug log for now.
		s.Log.Debug("state report", "node_id", nodeID)
	case *myfwv1.AgentToController_IptablesRules:
		s.onIptablesRules(ctx, nodeID, p.IptablesRules)
	default:
		s.Log.Warn("unknown upstream payload", "node_id", nodeID)
	}
}

// onHeartbeat updates node.LastSeen. The node IP is intentionally NOT
// refreshed here: it was captured at registration from the Agent's reported
// ip_addresses, and overwriting it with the gRPC peer IP would regress to
// 127.0.0.1 when the Agent connects via loopback.
func (s *Service) onHeartbeat(ctx context.Context, nodeID string, hb *myfwv1.Heartbeat) {
	if hb == nil {
		return
	}
	// 心跳携带 capability 时（首包及每 N 次一次），更新能力快照并据后端可用性切换状态
	if hb.Capability != nil {
		s.applyCapability(ctx, nodeID, hb.Capability)
	}
	now := time.Now().UTC()
	if err := s.DB.WithContext(ctx).
		Model(&model.Node{}).
		Where("id = ?", nodeID).
		Update("last_seen", &now).Error; err != nil {
		s.Log.Warn("update last_seen", "node_id", nodeID, "err", err)
	}
}

// applyCapability 持久化 Agent 上报的能力快照，并根据后端可用性切换节点状态：
//   - 后端不可用且当前 ACTIVE -> 置为 ABNORMAL 并写审计
//   - 后端恢复可用且当前 ABNORMAL -> 置为 ACTIVE 并写审计
//
// PENDING 节点仅更新能力快照，不自动改状态（仍需管理员审批）。
func (s *Service) applyCapability(ctx context.Context, nodeID string, cap *myfwv1.Capability) {
	available, reason := parseBackendAvailable(cap.Extra)
	raw, _ := json.Marshal(cap)
	now := time.Now().UTC()

	var existing model.NodeCapability
	findErr := s.DB.WithContext(ctx).Where("node_id = ?", nodeID).First(&existing).Error
	updates := map[string]any{
		"distro":            cap.Distro,
		"kernel_version":    cap.KernelVersion,
		"iptables_version":  cap.IptablesVersion,
		"selected_backend":  cap.SelectedBackend.String(),
		"nft_supported":     cap.NftSupported,
		"docker_present":    cap.DockerPresent,
		"k8s_present":       cap.KubernetesPresent,
		"backend_available": available,
		"backend_reason":    reason,
		"raw":               string(raw),
		"updated_at":        now,
	}
	if findErr == nil {
		if err := s.DB.WithContext(ctx).Model(&existing).Updates(updates).Error; err != nil {
			s.Log.Warn("update capability", "node_id", nodeID, "err", err)
			return
		}
	} else {
		// 首次上报（如禁用 mTLS 路径未在注册时持久化能力），创建记录
		rec := model.NodeCapability{
			NodeID:           nodeID,
			Distro:           cap.Distro,
			KernelVersion:    cap.KernelVersion,
			IptablesVersion:  cap.IptablesVersion,
			SelectedBackend:  cap.SelectedBackend.String(),
			BackendAvailable: &available,
			BackendReason:    reason,
			NftSupported:     cap.NftSupported,
			DockerPresent:    cap.DockerPresent,
			K8sPresent:       cap.KubernetesPresent,
			Raw:              string(raw),
			UpdatedAt:        now,
		}
		if err := s.DB.WithContext(ctx).Create(&rec).Error; err != nil {
			s.Log.Warn("create capability", "node_id", nodeID, "err", err)
			return
		}
	}

	// 状态切换：仅 ACTIVE <-> ABNORMAL，PENDING 等其他状态不动
	if !available {
		s.transitionForBackend(ctx, nodeID, model.NodeStatusActive, model.NodeStatusAbnormal, "node.abnormal", reason)
	} else {
		s.transitionForBackend(ctx, nodeID, model.NodeStatusAbnormal, model.NodeStatusActive, "node.recovered", "")
	}
}

// transitionForBackend 在节点处于 from 状态时切换到 to 并写审计；非 from 状态则跳过。
func (s *Service) transitionForBackend(ctx context.Context, nodeID string, from, to model.NodeStatus, action, reason string) {
	res := s.DB.WithContext(ctx).
		Model(&model.Node{}).
		Where("id = ? AND status = ?", nodeID, from).
		Update("status", to)
	if res.Error != nil {
		s.Log.Warn("transition node status", "node_id", nodeID, "from", from, "to", to, "err", res.Error)
		return
	}
	if res.RowsAffected == 0 {
		return // 节点不在 from 状态，无需切换
	}
	s.Log.Info("node status transitioned by backend availability", "node_id", nodeID, "from", from, "to", to, "reason", reason)
	if s.Audit != nil {
		detail, _ := json.Marshal(map[string]any{"from": from, "to": to, "reason": reason})
		_ = s.Audit.Write(ctx, model.AuditLog{
			Actor:  "agent",
			Action: action,
			NodeID: nodeID,
			Detail: string(detail),
		})
	}
}

// parseBackendAvailable 从 Capability.extra 解析后端可用性标记。
// 约定："backend_available=true|false" 与 "backend_reason:<文本>"。
// 未携带标记时默认可用（向后兼容旧版 Agent）。
func parseBackendAvailable(extra []string) (bool, string) {
	available := true
	reason := ""
	for _, e := range extra {
		switch {
		case strings.HasPrefix(e, "backend_available="):
			available = strings.TrimPrefix(e, "backend_available=") == "true"
		case strings.HasPrefix(e, "backend_reason:"):
			reason = strings.TrimPrefix(e, "backend_reason:")
		}
	}
	return available, reason
}

// onIptablesRules 持久化 Agent 刚上报的规则，并唤醒等待实时拉取的调用方。
func (s *Service) onIptablesRules(ctx context.Context, nodeID string, msg *myfwv1.IptablesRules) {
	if msg == nil {
		return
	}
	tx := s.DB.WithContext(ctx).Begin()
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()
	if err := tx.Where("node_id = ?", nodeID).Delete(&model.IptablesRule{}).Error; err != nil {
		tx.Rollback()
		s.Log.Warn("delete old iptables rules", "node_id", nodeID, "err", err)
		return
	}
	// 批量收集规则,一次性插入避免逐条 N 次写入
	rules := make([]model.IptablesRule, 0)
	for _, chain := range msg.Chains {
		for i, rule := range chain.Rules {
			rules = append(rules, model.IptablesRule{
				NodeID:    nodeID,
				TableType: chain.Table,
				Chain:     chain.Chain,
				RuleLine:  rule,
				Priority:  i,
				IsMYFW:    isMYFWRules(rule),
			})
		}
	}
	if len(rules) > 0 {
		if err := tx.Create(&rules).Error; err != nil {
			tx.Rollback()
			s.Log.Warn("batch create iptables rules", "node_id", nodeID, "err", err)
			return
		}
	}
	if err := tx.Commit().Error; err != nil {
		s.Log.Warn("commit iptables rules", "node_id", nodeID, "err", err)
		return
	}
	s.Log.Debug("iptables rules persisted", "node_id", nodeID, "chains", len(msg.Chains))

	// 唤醒等待实时拉取的调用方
	s.rulesMu.Lock()
	ch, ok := s.rulesWaiters[nodeID]
	if ok {
		delete(s.rulesWaiters, nodeID)
	}
	s.rulesMu.Unlock()
	if ok {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

// RequestRulesAndWait 下发 SyncRulesRequest 让 Agent 上报当前规则，阻塞等待
// 上报完成或超时。Web API 用它返回节点规则的准实时视图。
func (s *Service) RequestRulesAndWait(ctx context.Context, nodeID string, timeout time.Duration) error {
	ch := make(chan struct{}, 1)
	s.rulesMu.Lock()
	s.rulesWaiters[nodeID] = ch
	s.rulesMu.Unlock()
	defer func() {
		s.rulesMu.Lock()
		delete(s.rulesWaiters, nodeID)
		s.rulesMu.Unlock()
	}()
	if err := s.Reg.Send(nodeID, &myfwv1.ControllerToAgent{
		Payload: &myfwv1.ControllerToAgent_SyncRules{SyncRules: &myfwv1.SyncRulesRequest{Reason: "web query"}},
	}); err != nil {
		return err
	}
	select {
	case <-ch:
		return nil
	case <-time.After(timeout):
		return errors.New("timeout waiting for agent rules")
	case <-ctx.Done():
		return ctx.Err()
	}
}

// SendRuleOperation 下发单条规则操作到 Agent 并等待 TaskResult。
func (s *Service) SendRuleOperation(ctx context.Context, nodeID string, op *myfwv1.RuleOperation, timeout time.Duration) (*myfwv1.TaskResult, error) {
	ch, cancel := s.SubscribeTaskResults()
	defer cancel()
	if err := s.Reg.Send(nodeID, &myfwv1.ControllerToAgent{
		Payload: &myfwv1.ControllerToAgent_RuleOperation{RuleOperation: op},
	}); err != nil {
		return nil, err
	}
	for {
		select {
		case res := <-ch:
			if res.TaskId == op.TaskId {
				return res, nil
			}
		case <-time.After(timeout):
			return nil, errors.New("timeout waiting for rule operation result")
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// execSeq 为专家模式命令生成唯一 task_id 的自增计数器
var execSeq uint64

// SendExecAndWait 下发裸 iptables 命令到 Agent 并等待 TaskResult（专家模式）。
// 命令白名单校验由 Agent 侧 OnExec 保证；本方法仅负责下发与同步等待。
func (s *Service) SendExecAndWait(ctx context.Context, nodeID, command string, timeout time.Duration) (*myfwv1.TaskResult, error) {
	taskID := fmt.Sprintf("exec-%d", atomic.AddUint64(&execSeq, 1))
	ch, cancel := s.SubscribeTaskResults()
	defer cancel()
	if err := s.Reg.Send(nodeID, &myfwv1.ControllerToAgent{
		Payload: &myfwv1.ControllerToAgent_ExecCommand{
			ExecCommand: &myfwv1.ExecCommand{TaskId: taskID, Command: command},
		},
	}); err != nil {
		return nil, err
	}
	for {
		select {
		case res := <-ch:
			if res.TaskId == taskID {
				return res, nil
			}
		case <-time.After(timeout):
			return nil, errors.New("timeout waiting for exec result")
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// SendRenewCert 下发证书续签指令到 Agent。续签由 Agent 异步执行，成功后 Agent
// 重建连接加载新证书；本方法仅负责下发指令，不等待续签结果。
func (s *Service) SendRenewCert(ctx context.Context, nodeID string) error {
	if archived, err := s.isArchived(ctx, nodeID); err != nil {
		return err
	} else if archived {
		return errors.New("node archived")
	}
	return s.Reg.Send(nodeID, &myfwv1.ControllerToAgent{
		Payload: &myfwv1.ControllerToAgent_RenewCert{
			RenewCert: &myfwv1.RenewCertCommand{},
		},
	})
}

// SendDecommission 下发注销指令到 Agent。Agent 收到后自毁（停 systemd + 删本地文件 + 退出）。
// 在线节点立即清理；离线节点返回 not connected 错误，调用方（DELETE 路由）忽略后删 DB，
// Agent 重连被拒时由自毁兜底。reason 用于审计追溯。
func (s *Service) SendDecommission(ctx context.Context, nodeID string, reason string) error {
	return s.Reg.Send(nodeID, &myfwv1.ControllerToAgent{
		Payload: &myfwv1.ControllerToAgent_Decommission{
			Decommission: &myfwv1.DecommissionCommand{Reason: reason},
		},
	})
}

// isMYFWRules 判断规则是否属于 MYFW 命名空间（与 server 包判定保持一致）。
func isMYFWRules(rule string) bool {
	return strings.HasPrefix(rule, "-A MYFW-") || strings.Contains(rule, "-j MYFW-")
}

func (s *Service) isArchived(ctx context.Context, nodeID string) (bool, error) {
	var n model.Node
	if err := s.DB.WithContext(ctx).Where("id = ?", nodeID).First(&n).Error; err != nil {
		return false, err
	}
	return n.Status == model.NodeStatusArchived, nil
}

// auditDrift writes a drift event to the audit log.
// 同步写基础审计(hash)后,异步分类(编译 expected + 拉 actual + diff)补写 node.drift.classified,
// 区分"重启规则丢失(良性)"与"外部篡改(恶性)"。异步不阻塞 stream 收包;分类失败回落 unspecified。
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
	// 异步分类:复用 stream 连接上下文值(节点标识),不被连接关闭取消
	go s.classifyAndAudit(context.WithoutCancel(ctx), nodeID, drift)
}

// classifyAndAudit 异步分类 drift 并补写 node.drift.classified 审计。
// 依赖 CompileExpected(期望编译产物)与 DB 中 Agent 上报的实际 MYFW 规则;
// RequestRulesAndWait 拉取失败不影响分类(用 DB 现有规则兜底)。
func (s *Service) classifyAndAudit(ctx context.Context, nodeID string, drift *myfwv1.DriftReport) {
	if s.Audit == nil {
		return
	}
	cls := DriftClass{Source: DriftSourceUnspecified, Summary: "分类失败(无法获取期望/实际规则)"}
	if s.CompileExpected != nil {
		if expected, err := s.CompileExpected(ctx, nodeID); err == nil {
			_ = s.RequestRulesAndWait(ctx, nodeID, 3*time.Second)
			var actual []model.IptablesRule
			if s.DB != nil {
				s.DB.WithContext(ctx).Where("node_id = ? AND is_myfw = ?", nodeID, true).Find(&actual)
			}
			cls = classifyDrift(expected, actual)
		}
	}
	cdetail, _ := json.Marshal(map[string]any{
		"source":        cls.Source,
		"summary":       cls.Summary,
		"expected_n":    cls.ExpectedN,
		"actual_n":      cls.ActualN,
		"missing":       cls.Missing,
		"extra":         cls.Extra,
		"expected_hash": drift.ExpectedHash,
		"actual_hash":   drift.ActualHash,
	})
	_ = s.Audit.Write(ctx, model.AuditLog{
		Actor:  "system",
		Action: "node.drift.classified",
		NodeID: nodeID,
		Detail: string(cdetail),
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
