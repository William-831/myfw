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
	"crypto/rand"
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
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	myfwv1 "iptables-tool/api/myfw/v1"
	"iptables-tool/internal/security"
)

// TLSMaterial identifies the files an authenticated Agent needs to dial the
// Controller. When BootstrapOnly is true, CertFile/KeyFile may be empty and
// the resulting connection is only good for calling Register.
type TLSMaterial struct {
	Disable       bool   // 禁用 TLS（仅用于内网开发环境）
	CAFile        string
	CertFile      string
	KeyFile       string
	ServerName    string // TLS SNI; falls back to the endpoint host
	BootstrapOnly bool
}

// Dial builds a *grpc.ClientConn to endpoint using the provided TLS material.
// The caller is responsible for closing the returned conn.
func Dial(ctx context.Context, endpoint string, m TLSMaterial) (*grpc.ClientConn, error) {
	var opts []grpc.DialOption

	// 如果禁用 TLS，使用不安全的明文连接
	if m.Disable {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else {
		tlsCfg, err := buildClientTLS(endpoint, m)
		if err != nil {
			return nil, err
		}
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	}

	conn, err := grpc.NewClient(endpoint, opts...)
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
	// OnSyncRules collects the node's current iptables rules when the
	// Controller requests a real-time pull.
	OnSyncRules(ctx context.Context) *myfwv1.IptablesRules
	// OnRuleOperation executes a single rule add/delete/insert/replace.
	OnRuleOperation(ctx context.Context, op *myfwv1.RuleOperation) *myfwv1.TaskResult
	// OnExec 执行专家模式裸 iptables 命令（白名单校验后）。
	OnExec(ctx context.Context, cmd *myfwv1.ExecCommand) *myfwv1.TaskResult
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
func (h NopHandler) OnSyncRules(ctx context.Context) *myfwv1.IptablesRules { return nil }
func (h NopHandler) OnRuleOperation(ctx context.Context, op *myfwv1.RuleOperation) *myfwv1.TaskResult {
	return &myfwv1.TaskResult{TaskId: op.TaskId, Ok: false, Message: "no handler wired", TsUnix: time.Now().Unix()}
}
func (h NopHandler) OnExec(ctx context.Context, cmd *myfwv1.ExecCommand) *myfwv1.TaskResult {
	return &myfwv1.TaskResult{TaskId: cmd.TaskId, Ok: false, Message: "no handler wired", TsUnix: time.Now().Unix()}
}

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

// runStream 打开一个 AgentStream，推送心跳直到出错或 ctx 取消。
// 下游消息分发到 h。sendCh 用于从其他 goroutine（如 Watchdog）发送消息。
func runStream(ctx context.Context, client myfwv1.AgentStreamClient, log *slog.Logger, nodeID string, cap *myfwv1.Capability, h Handler, opts HeartbeatOptions, sendCh chan *myfwv1.AgentToController) error {
	// 生成会话令牌用于防重放
	sessionSecret := make([]byte, 32)
	if _, err := readRandom(sessionSecret); err != nil {
		return fmt.Errorf("generate session secret: %w", err)
	}
	sm := security.NewSessionManager(sessionSecret, 24*time.Hour)
	token, sig, err := sm.IssueToken(nodeID, "", getLocalIP())
	if err != nil {
		log.Warn("failed to issue session token", "err", err)
	}

	// dev 联调：仅发 node_id（会话令牌需 Controller 签发，当前 Agent 自生成无法通过
	// Controller 验证，暂不发，仅靠 mTLS 证书认证。TODO: Controller 注册时签发令牌）
	_ = token
	_ = sig
	ctx = metadata.AppendToOutgoingContext(ctx, "x-node-id", nodeID)

	stream, err := client.Connect(ctx)
	if err != nil {
		return err
	}
	log.Info("stream opened", "node_id", nodeID)

	// 序列化发送到单个 goroutine（gRPC ClientStream 非并发安全）
	rxErr := make(chan error, 1)

	// RX goroutine: 分发 Controller-to-Agent 消息
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
			case *myfwv1.ControllerToAgent_SyncRules:
				log.Debug("sync rules requested", "reason", p.SyncRules.Reason)
				if res := h.OnSyncRules(ctx); res != nil {
					res.NodeId = nodeID
					select {
					case sendCh <- &myfwv1.AgentToController{Payload: &myfwv1.AgentToController_IptablesRules{IptablesRules: res}}:
					case <-ctx.Done():
						return
					}
				}
			case *myfwv1.ControllerToAgent_RuleOperation:
				log.Info("rule operation", "node_id", nodeID, "op", p.RuleOperation.Op, "task_id", p.RuleOperation.TaskId)
				res := h.OnRuleOperation(ctx, p.RuleOperation)
				if res != nil {
					select {
					case sendCh <- &myfwv1.AgentToController{Payload: &myfwv1.AgentToController_TaskResult{TaskResult: res}}:
					case <-ctx.Done():
						return
					}
				}
			case *myfwv1.ControllerToAgent_ExecCommand:
				log.Info("exec command", "node_id", nodeID, "task_id", p.ExecCommand.TaskId)
				res := h.OnExec(ctx, p.ExecCommand)
				if res != nil {
					select {
					case sendCh <- &myfwv1.AgentToController{Payload: &myfwv1.AgentToController_TaskResult{TaskResult: res}}:
					case <-ctx.Done():
						return
					}
				}
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

	// 立即发送心跳
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

// TokenToString 将会话令牌序列化为字符串（导出给 conn 包使用）。
// 实际实现在 security 包中，这里仅做类型适配。

// getLocalIP 获取本机IP地址（用于会话令牌绑定）。
func getLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
			if ipNet.IP.To4() != nil {
				return ipNet.IP.String()
			}
		}
	}
	return ""
}

// readRandom 读取密码学安全的随机字节。
func readRandom(b []byte) (int, error) {
	return rand.Read(b)
}
