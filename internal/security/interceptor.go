package security

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// SecureConfig 安全配置。
type SecureConfig struct {
	// DisableTLS 是否禁用TLS（仅用于开发环境）
	DisableTLS bool
	// SessionTTL 会话有效期
	SessionTTL time.Duration
	// HMACSecret HMAC签名密钥（生产环境必须设置）
	HMACSecret []byte
	// EnableIPPinning 是否启用IP钉扎
	EnableIPPinning bool
	// AntiReplayWindow 防重放窗口（秒），默认300秒
	AntiReplayWindow int64
	// BootstrapMethods 不需要会话验证的方法列表
	BootstrapMethods []string
}

// SecureInterceptor 安全拦截器组合。
type SecureInterceptor struct {
	cfg      SecureConfig
	sessions *SessionManager
	log      *slog.Logger
	mu       sync.RWMutex
	// nodeIPCache 绑定节点ID到首次连接IP（IP钉扎）
	nodeIPCache map[string]string
}

// NewSecureInterceptor 创建安全拦截器。
func NewSecureInterceptor(cfg SecureConfig, log *slog.Logger) *SecureInterceptor {
	if cfg.AntiReplayWindow <= 0 {
		cfg.AntiReplayWindow = 300
	}
	if len(cfg.BootstrapMethods) == 0 {
		cfg.BootstrapMethods = []string{
			"/myfw.v1.Registration/Register",
		}
	}
	return &SecureInterceptor{
		cfg:         cfg,
		sessions:    NewSessionManager(cfg.HMACSecret, cfg.SessionTTL),
		log:         log,
		nodeIPCache: make(map[string]string),
	}
}

// GetSessions 返回会话管理器引用。
func (si *SecureInterceptor) GetSessions() *SessionManager {
	return si.sessions
}

// UnaryServerInterceptor 返回一元RPC安全拦截器。
func (si *SecureInterceptor) UnaryServerInterceptor() func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if err := si.authenticate(ctx, info.FullMethod); err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

// StreamServerInterceptor 返回流式RPC安全拦截器。
func (si *SecureInterceptor) StreamServerInterceptor() func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if err := si.authenticate(ss.Context(), info.FullMethod); err != nil {
			return err
		}
		return handler(srv, ss)
	}
}

// authenticate 统一认证逻辑：mTLS证书 + 会话令牌 + IP钉扎 + 防重放。
func (si *SecureInterceptor) authenticate(ctx context.Context, method string) error {
	// Bootstrap方法使用特殊认证路径
	for _, bm := range si.cfg.BootstrapMethods {
		if method == bm {
			return si.authenticateBootstrap(ctx)
		}
	}

	// 非TLS模式：仅从metadata中提取node_id
	if si.cfg.DisableTLS {
		return si.authenticateInsecure(ctx)
	}

	// 完整mTLS认证路径
	return si.authenticateMTLS(ctx)
}

// authenticateMTLS 完整的mTLS认证流程。
func (si *SecureInterceptor) authenticateMTLS(ctx context.Context) error {
	// 1. 提取TLS证书信息
	p, ok := peer.FromContext(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "no peer info")
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return status.Error(codes.Unauthenticated, "not a TLS connection")
	}
	if len(tlsInfo.State.VerifiedChains) == 0 || len(tlsInfo.State.VerifiedChains[0]) == 0 {
		return status.Error(codes.Unauthenticated, "client certificate required")
	}
	cert := tlsInfo.State.VerifiedChains[0][0]

	// 2. 从证书提取节点ID
	nodeID := ""
	for _, u := range cert.URIs {
		if u.Scheme == "myfw" && strings.HasPrefix(u.Opaque, "node:") {
			nodeID = u.Opaque[len("node:"):]
			break
		}
	}
	if nodeID == "" && cert.Subject.CommonName != "" {
		nodeID = cert.Subject.CommonName
	}
	if nodeID == "" {
		return status.Error(codes.Unauthenticated, "no node id in certificate")
	}

	// 3. 提取客户端IP
	clientIP := extractIP(ctx)
	if clientIP == "" {
		return status.Error(codes.Unauthenticated, "cannot determine client IP")
	}

	// 4. IP钉扎检查
	if si.cfg.EnableIPPinning {
		si.mu.RLock()
		boundIP, exists := si.nodeIPCache[nodeID]
		si.mu.RUnlock()

		if exists && boundIP != clientIP {
			si.log.Warn("IP pinning violation",
				"node_id", nodeID,
				"bound_ip", boundIP,
				"actual_ip", clientIP)
			return status.Error(codes.PermissionDenied,
				fmt.Sprintf("IP mismatch: bound to %s, got %s", boundIP, clientIP))
		}

		if !exists {
			si.mu.Lock()
			si.nodeIPCache[nodeID] = clientIP
			si.mu.Unlock()
			si.log.Info("IP pinned for node", "node_id", nodeID, "ip", clientIP)
		}
	}

	// 5. 会话令牌验证（从metadata中获取）
	md, ok := metadata.FromIncomingContext(ctx)
	if ok {
		if tokens := md.Get("x-session-token"); len(tokens) > 0 {
			if sigs := md.Get("x-session-sig"); len(sigs) > 0 {
				if err := si.validateSessionToken(nodeID, tokens[0], sigs[0]); err != nil {
					si.log.Warn("session validation failed", "node_id", nodeID, "err", err)
					return status.Error(codes.Unauthenticated, "invalid session: "+err.Error())
				}
			}
		}
	}

	// 将nodeID存入上下文，供后续handler使用
	ctx = context.WithValue(ctx, NodeIDKey{}, nodeID)
	return nil
}

// authenticateInsecure 非TLS模式认证（仅用于开发环境）。
func (si *SecureInterceptor) authenticateInsecure(ctx context.Context) error {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "no metadata")
	}
	vals := md.Get("x-node-id")
	if len(vals) == 0 || vals[0] == "" {
		return status.Error(codes.Unauthenticated, "missing x-node-id")
	}
	return nil
}

// authenticateBootstrap Bootstrap方法认证（仅验证bootstrap token）。
func (si *SecureInterceptor) authenticateBootstrap(ctx context.Context) error {
	return nil
}

// validateSessionToken 验证会话令牌。
func (si *SecureInterceptor) validateSessionToken(nodeID, tokenStr, signature string) error {
	state, ok := si.sessions.GetSession(nodeID)
	if !ok {
		return fmt.Errorf("no active session")
	}

	// 验证签名
	payload := fmt.Sprintf("%s|%s|%s|%d|%d|%s",
		state.Token.NodeID, state.Token.Fingerprint, state.Token.IP,
		state.Token.IssuedAt, state.Token.ExpiresAt, state.Token.Nonce)

	mac := generateHMAC(si.cfg.HMACSecret, []byte(payload))
	if subtle.ConstantTimeCompare([]byte(signature), []byte(mac)) != 1 {
		return fmt.Errorf("invalid signature")
	}

	// 防重放：检查nonce是否已使用
	if state.LastNonce == state.Token.Nonce {
		return fmt.Errorf("nonce replay")
	}

	return nil
}

// CreateSessionMetadata 为Agent创建会话metadata，用于后续请求。
func CreateSessionMetadata(token *SessionToken, signature string) metadata.MD {
	return metadata.New(map[string]string{
		"x-session-token": tokenToString(token),
		"x-session-sig":   signature,
	})
}

// tokenToString 将令牌序列化为字符串（内部使用）。
func tokenToString(token *SessionToken) string {
	data, _ := json.Marshal(token)
	return string(data)
}

// TokenToString 将令牌序列化为字符串（导出版本）。
func TokenToString(token *SessionToken) string {
	return tokenToString(token)
}

// TokenFromString 从字符串反序列化令牌。
func TokenFromString(s string) (*SessionToken, error) {
	var token SessionToken
	if err := json.Unmarshal([]byte(s), &token); err != nil {
		return nil, err
	}
	return &token, nil
}

// extractIP 从gRPC上下文提取客户端IP。
func extractIP(ctx context.Context) string {
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

// generateHMAC 生成HMAC-SHA256签名。
func generateHMAC(key, data []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return hex.EncodeToString(mac.Sum(nil))
}

// NodeIDKey 上下文键类型，用于存储节点ID。
type NodeIDKey struct{}

// NodeIDFromContext 从上下文中提取节点ID。
func NodeIDFromContext(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(NodeIDKey{}).(string)
	return id, ok
}
