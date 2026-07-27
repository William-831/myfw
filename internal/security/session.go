// Package security 提供通信安全机制：会话令牌、HMAC签名、防重放、证书自动轮换。
// 设计目标：在纯内网环境下简化证书管理，同时防御横向移动、指令伪造和重放攻击。
package security

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// SessionToken 是轻量级会话令牌，绑定节点身份与连接信息。
// 不使用 JWT 库，直接 HMAC-SHA256 签名，避免引入外部依赖。
type SessionToken struct {
	NodeID        string    `json:"n"`  // 节点ID
	Fingerprint   string    `json:"f"` // 证书指纹
	IP            string    `json:"i"` // 首次连接IP（IP钉扎）
	IssuedAt      int64     `json:"t"` // 签发时间戳
	ExpiresAt     int64     `json:"e"` // 过期时间戳
	Nonce         string    `json:"q"` // 随机nonce，防重放
}

// SessionManager 管理活跃会话，提供令牌签发、验证和防重放能力。
type SessionManager struct {
	mu       sync.RWMutex
	sessions map[string]*SessionState // nodeID -> state
	secret   []byte                   // HMAC签名密钥
	ttl      time.Duration            // 会话有效期
}

// SessionState 是单个节点的会话状态。
type SessionState struct {
	Token         *SessionToken
	Secret        []byte    // 该会话的独立密钥
	LastNonce     string    // 上一次使用的nonce
	LastNonceTime time.Time // 上一次nonce的时间
	ConnectedAt   time.Time
	RemoteIP      string
}

// NewSessionManager 创建会话管理器。secret 是全局HMAC密钥。
func NewSessionManager(secret []byte, ttl time.Duration) *SessionManager {
	if len(secret) == 0 {
		secret = make([]byte, 32)
		rand.Read(secret)
	}
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	return &SessionManager{
		sessions: make(map[string]*SessionState),
		secret:   secret,
		ttl:      ttl,
	}
}

// IssueToken 为节点签发新的会话令牌。
func (sm *SessionManager) IssueToken(nodeID, fingerprint, ip string) (*SessionToken, string, error) {
	now := time.Now()
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, "", fmt.Errorf("session: generate nonce: %w", err)
	}

	// 为每个会话生成独立密钥
	sessionKey := make([]byte, 32)
	if _, err := rand.Read(sessionKey); err != nil {
		return nil, "", fmt.Errorf("session: generate key: %w", err)
	}

	token := &SessionToken{
		NodeID:      nodeID,
		Fingerprint: fingerprint,
		IP:          ip,
		IssuedAt:    now.Unix(),
		ExpiresAt:   now.Add(sm.ttl).Unix(),
		Nonce:       hex.EncodeToString(nonce),
	}

	// 签名：HMAC-SHA256(secret, nodeID|fingerprint|ip|issuedAt|expiresAt|nonce)
	payload := fmt.Sprintf("%s|%s|%s|%d|%d|%s", token.NodeID, token.Fingerprint, token.IP, token.IssuedAt, token.ExpiresAt, token.Nonce)
	mac := hmac.New(sha256.New, sm.secret)
	mac.Write([]byte(payload))
	signature := hex.EncodeToString(mac.Sum(nil))

	state := &SessionState{
		Token:       token,
		Secret:      sessionKey,
		ConnectedAt: now,
		RemoteIP:    ip,
	}

	sm.mu.Lock()
	sm.sessions[nodeID] = state
	sm.mu.Unlock()

	return token, signature, nil
}

// ValidateToken 验证会话令牌的签名和时效性。
func (sm *SessionManager) ValidateToken(token *SessionToken, signature string) error {
	if token == nil {
		return fmt.Errorf("session: nil token")
	}

	// 检查时效
	now := time.Now().Unix()
	if now > token.ExpiresAt {
		return fmt.Errorf("session: token expired")
	}
	if now < token.IssuedAt-60 { // 允许60秒时钟偏差
		return fmt.Errorf("session: token not yet valid")
	}

	// 验证签名
	payload := fmt.Sprintf("%s|%s|%s|%d|%d|%s", token.NodeID, token.Fingerprint, token.IP, token.IssuedAt, token.ExpiresAt, token.Nonce)
	mac := hmac.New(sha256.New, sm.secret)
	mac.Write([]byte(payload))
	expected := hex.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(signature), []byte(expected)) {
		return fmt.Errorf("session: invalid signature")
	}

	// 防重放检查
	sm.mu.RLock()
	state, ok := sm.sessions[token.NodeID]
	sm.mu.RUnlock()

	if ok && state.LastNonce == token.Nonce {
		return fmt.Errorf("session: nonce replay detected")
	}

	return nil
}

// ConsumeNonce 标记nonce已使用，防止重放。
func (sm *SessionManager) ConsumeNonce(nodeID, nonce string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	if state, ok := sm.sessions[nodeID]; ok {
		state.LastNonce = nonce
		state.LastNonceTime = time.Now()
	}
}

// GetSession 获取节点的活跃会话状态。
func (sm *SessionManager) GetSession(nodeID string) (*SessionState, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	state, ok := sm.sessions[nodeID]
	if !ok {
		return nil, false
	}
	// 检查是否过期
	if time.Now().Unix() > state.Token.ExpiresAt {
		return nil, false
	}
	return state, true
}

// RemoveSession 移除节点会话（断线时调用）。
func (sm *SessionManager) RemoveSession(nodeID string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	delete(sm.sessions, nodeID)
}

// CleanupExpired 清理过期会话，应定期调用。
func (sm *SessionManager) CleanupExpired() int {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	now := time.Now().Unix()
	count := 0
	for id, state := range sm.sessions {
		if now > state.Token.ExpiresAt {
			delete(sm.sessions, id)
			count++
		}
	}
	return count
}

// SignPayload 使用会话密钥对载荷签名，用于防篡改。
func SignPayload(sessionKey []byte, payload []byte) string {
	mac := hmac.New(sha256.New, sessionKey)
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifyPayload 验证载荷签名。
func VerifyPayload(sessionKey []byte, payload []byte, signature string) bool {
	mac := hmac.New(sha256.New, sessionKey)
	mac.Write(payload)
	expected := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(signature), []byte(expected))
}

// GenerateNonce 生成随机nonce。
func GenerateNonce() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}
