package security

import (
	"testing"
	"time"
)

func TestIssueAndValidateToken(t *testing.T) {
	secret := []byte("test-secret-key-for-hmac-signing-32b")
	sm := NewSessionManager(secret, 1*time.Hour)

	token, sig, err := sm.IssueToken("node-001", "fp-abc", "10.0.0.1")
	if err != nil {
		t.Fatalf("IssueToken failed: %v", err)
	}
	if token.NodeID != "node-001" {
		t.Errorf("NodeID = %q, want node-001", token.NodeID)
	}
	if token.IP != "10.0.0.1" {
		t.Errorf("IP = %q, want 10.0.0.1", token.IP)
	}
	if token.Nonce == "" {
		t.Error("Nonce should not be empty")
	}
	if sig == "" {
		t.Error("signature should not be empty")
	}

	// 验证签名
	if err := sm.ValidateToken(token, sig); err != nil {
		t.Errorf("ValidateToken failed: %v", err)
	}
}

func TestValidateToken_Expired(t *testing.T) {
	secret := []byte("test-secret-key-for-hmac-signing-32b")
	sm := NewSessionManager(secret, 1*time.Hour)

	token, sig, _ := sm.IssueToken("node-002", "", "10.0.0.2")
	// 模拟过期：修改 ExpiresAt
	token.ExpiresAt = time.Now().Add(-1 * time.Hour).Unix()

	if err := sm.ValidateToken(token, sig); err == nil {
		t.Error("ValidateToken should fail for expired token")
	}
}

func TestValidateToken_BadSignature(t *testing.T) {
	secret := []byte("test-secret-key-for-hmac-signing-32b")
	sm := NewSessionManager(secret, 1*time.Hour)

	token, _, _ := sm.IssueToken("node-003", "", "10.0.0.3")
	badSig := "0000000000000000000000000000000000000000000000000000000000000000"

	if err := sm.ValidateToken(token, badSig); err == nil {
		t.Error("ValidateToken should fail for bad signature")
	}
}

func TestValidateToken_Replay(t *testing.T) {
	secret := []byte("test-secret-key-for-hmac-signing-32b")
	sm := NewSessionManager(secret, 1*time.Hour)

	token, sig, _ := sm.IssueToken("node-004", "", "10.0.0.4")

	// 第一次验证通过
	if err := sm.ValidateToken(token, sig); err != nil {
		t.Fatalf("first ValidateToken failed: %v", err)
	}

	// 消费nonce
	sm.ConsumeNonce("node-004", token.Nonce)

	// 第二次验证应失败（nonce重放）
	if err := sm.ValidateToken(token, sig); err == nil {
		t.Error("ValidateToken should detect nonce replay")
	}
}

func TestGetAndRemoveSession(t *testing.T) {
	secret := []byte("test-secret-key-for-hmac-signing-32b")
	sm := NewSessionManager(secret, 1*time.Hour)

	sm.IssueToken("node-005", "", "10.0.0.5")

	state, ok := sm.GetSession("node-005")
	if !ok || state == nil {
		t.Fatal("GetSession should find existing session")
	}

	sm.RemoveSession("node-005")

	_, ok = sm.GetSession("node-005")
	if ok {
		t.Error("GetSession should not find removed session")
	}
}

func TestCleanupExpired(t *testing.T) {
	secret := []byte("test-secret-key-for-hmac-signing-32b")
	// 使用1秒TTL，确保在Unix秒级精度下能正确过期
	sm := NewSessionManager(secret, 1*time.Second)

	sm.IssueToken("node-006", "", "10.0.0.6")
	// 手动将过期时间设为过去，绕过精度问题
	sm.mu.Lock()
	if state, ok := sm.sessions["node-006"]; ok {
		state.Token.ExpiresAt = time.Now().Add(-1 * time.Hour).Unix()
	}
	sm.mu.Unlock()

	count := sm.CleanupExpired()
	if count != 1 {
		t.Errorf("CleanupExpired removed %d, want 1", count)
	}
}

func TestSignAndVerifyPayload(t *testing.T) {
	key := []byte("session-key-for-payload-signing-32b")
	payload := []byte("iptables -A MYFW-INPUT -s 10.0.0.0/8 -j ACCEPT")

	sig := SignPayload(key, payload)
	if sig == "" {
		t.Fatal("SignPayload returned empty signature")
	}

	if !VerifyPayload(key, payload, sig) {
		t.Error("VerifyPayload should return true for valid signature")
	}

	// 篡改payload
	tampered := []byte("iptables -A MYFW-INPUT -s 10.0.0.0/8 -j DROP")
	if VerifyPayload(key, tampered, sig) {
		t.Error("VerifyPayload should return false for tampered payload")
	}
}

func TestGenerateNonce_Unique(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		n := GenerateNonce()
		if seen[n] {
			t.Fatalf("GenerateNonce produced duplicate: %s", n)
		}
		seen[n] = true
	}
}

func TestIssueToken_DifferentSecrets(t *testing.T) {
	secret1 := []byte("secret-key-1---------------------32b")
	secret2 := []byte("secret-key-2---------------------32b")

	sm1 := NewSessionManager(secret1, 1*time.Hour)
	sm2 := NewSessionManager(secret2, 1*time.Hour)

	token, sig, _ := sm1.IssueToken("node-007", "", "10.0.0.7")

	// 用不同密钥验证应失败
	if err := sm2.ValidateToken(token, sig); err == nil {
		t.Error("ValidateToken should fail with wrong secret")
	}
}
