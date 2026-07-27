package security

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"testing"
	"time"
)

func TestCreateSessionMetadata(t *testing.T) {
	token := &SessionToken{
		NodeID:      "node-001",
		Fingerprint: "fp-abc",
		IP:          "10.0.0.1",
		IssuedAt:    time.Now().Unix(),
		ExpiresAt:   time.Now().Add(1 * time.Hour).Unix(),
		Nonce:       "test-nonce-123",
	}
	sig := "test-signature"

	md := CreateSessionMetadata(token, sig)

	tokenStr := md.Get("x-session-token")
	if len(tokenStr) == 0 {
		t.Error("x-session-token should not be empty")
	}

	sigStr := md.Get("x-session-sig")
	if len(sigStr) == 0 || sigStr[0] != sig {
		t.Errorf("x-session-sig = %q, want %q", sigStr, sig)
	}

	// 验证token可以反序列化回来
	var parsed SessionToken
	if err := json.Unmarshal([]byte(tokenStr[0]), &parsed); err != nil {
		t.Fatalf("failed to parse token: %v", err)
	}
	if parsed.NodeID != "node-001" {
		t.Errorf("parsed NodeID = %q, want node-001", parsed.NodeID)
	}
}

func TestTokenToString_RoundTrip(t *testing.T) {
	original := &SessionToken{
		NodeID:      "node-002",
		Fingerprint: "fp-def",
		IP:          "10.0.0.2",
		IssuedAt:    1234567890,
		ExpiresAt:   1234567890 + 3600,
		Nonce:       "nonce-abc",
	}

	str := TokenToString(original)
	if str == "" {
		t.Fatal("TokenToString returned empty string")
	}

	parsed, err := TokenFromString(str)
	if err != nil {
		t.Fatalf("TokenFromString failed: %v", err)
	}
	if parsed.NodeID != original.NodeID {
		t.Errorf("NodeID = %q, want %q", parsed.NodeID, original.NodeID)
	}
	if parsed.Nonce != original.Nonce {
		t.Errorf("Nonce = %q, want %q", parsed.Nonce, original.Nonce)
	}
}

func TestTokenFromString_Invalid(t *testing.T) {
	_, err := TokenFromString("not-json")
	if err == nil {
		t.Error("TokenFromString should fail for invalid JSON")
	}
}

func TestNodeIDFromContext(t *testing.T) {
	// 测试有nodeID的context
	ctx := context.WithValue(context.Background(), NodeIDKey{}, "test-node-id")
	id, ok := NodeIDFromContext(ctx)
	if !ok || id != "test-node-id" {
		t.Errorf("NodeIDFromContext = (%q, %v), want (test-node-id, true)", id, ok)
	}

	// 测试没有nodeID的context
	_, ok = NodeIDFromContext(context.Background())
	if ok {
		t.Error("NodeIDFromContext should return false for empty context")
	}
}

func TestNewSecureInterceptor(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	sec := NewSecureInterceptor(SecureConfig{
		DisableTLS:       true,
		SessionTTL:       1 * time.Hour,
		HMACSecret:       []byte("test-secret"),
		EnableIPPinning:  false,
		AntiReplayWindow: 300,
	}, log)

	if sec.GetSessions() == nil {
		t.Error("GetSessions should not return nil")
	}
}

func TestGenerateHMAC(t *testing.T) {
	key := []byte("test-key")
	data := []byte("test-data")

	sig1 := generateHMAC(key, data)
	sig2 := generateHMAC(key, data)

	if sig1 != sig2 {
		t.Error("HMAC should be deterministic")
	}
	if sig1 == "" {
		t.Error("HMAC should not be empty")
	}

	// 不同数据应产生不同签名
	sig3 := generateHMAC(key, []byte("different-data"))
	if sig1 == sig3 {
		t.Error("Different data should produce different HMAC")
	}
}
