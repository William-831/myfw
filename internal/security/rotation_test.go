package security

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNeedsRotation_NoCert(t *testing.T) {
	dir := t.TempDir()
	rotator := NewCertRotation(RotationConfig{
		CertTTL:     1 * time.Hour,
		RenewBefore: 10 * time.Minute,
		KeyDir:      dir,
	})
	if !rotator.NeedsRotation() {
		t.Error("NeedsRotation should return true when no cert exists")
	}
}

func TestNeedsRotation_FreshCert(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "agent.crt")
	keyPath := filepath.Join(dir, "agent.key")

	// 生成测试证书（有效期24小时）
	certPEM, keyPEM := generateTestCert(t, 24*time.Hour)
	os.WriteFile(certPath, certPEM, 0644)
	os.WriteFile(keyPath, keyPEM, 0600)

	rotator := NewCertRotation(RotationConfig{
		CertTTL:     24 * time.Hour,
		RenewBefore: 5 * time.Hour,
		KeyDir:      dir,
	})
	if err := rotator.LoadExisting(); err != nil {
		t.Fatalf("LoadExisting failed: %v", err)
	}
	if rotator.NeedsRotation() {
		t.Error("NeedsRotation should return false for fresh cert")
	}
}

func TestNeedsRotation_ExpiredCert(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "agent.crt")
	keyPath := filepath.Join(dir, "agent.key")

	// 生成已过期的证书
	certPEM, keyPEM := generateTestCert(t, -1*time.Hour)
	os.WriteFile(certPath, certPEM, 0644)
	os.WriteFile(keyPath, keyPEM, 0600)

	rotator := NewCertRotation(RotationConfig{
		CertTTL:     24 * time.Hour,
		RenewBefore: 5 * time.Hour,
		KeyDir:      dir,
	})
	if err := rotator.LoadExisting(); err != nil {
		t.Fatalf("LoadExisting failed: %v", err)
	}
	if !rotator.NeedsRotation() {
		t.Error("NeedsRotation should return true for expired cert")
	}
}

func TestGenerateCSR(t *testing.T) {
	dir := t.TempDir()
	rotator := NewCertRotation(RotationConfig{
		CertTTL:     1 * time.Hour,
		RenewBefore: 10 * time.Minute,
		KeyDir:      dir,
	})

	csrPEM, keyPEM, err := rotator.GenerateCSR("test-node-001")
	if err != nil {
		t.Fatalf("GenerateCSR failed: %v", err)
	}
	if len(csrPEM) == 0 {
		t.Error("CSR PEM should not be empty")
	}
	if len(keyPEM) == 0 {
		t.Error("Key PEM should not be empty")
	}

	// 验证CSR可以解析
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		t.Fatal("Failed to decode CSR PEM")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse CSR: %v", err)
	}
	if csr.Subject.CommonName != "test-node-001" {
		t.Errorf("CSR CN = %q, want test-node-001", csr.Subject.CommonName)
	}
}

func TestApplyNewCert(t *testing.T) {
	dir := t.TempDir()
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	rotator := NewCertRotation(RotationConfig{
		CertTTL:     1 * time.Hour,
		RenewBefore: 10 * time.Minute,
		KeyDir:      dir,
		Logger:      log,
	})

	newCert, newKey := generateTestCert(t, 1*time.Hour)
	if err := rotator.ApplyNewCert(newCert, newKey); err != nil {
		t.Fatalf("ApplyNewCert failed: %v", err)
	}

	// 验证文件已写入
	certPath := filepath.Join(dir, "agent.crt")
	keyPath := filepath.Join(dir, "agent.key")

	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		t.Error("cert file should exist")
	}
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		t.Error("key file should exist")
	}

	// 验证内容匹配
	certData, _ := os.ReadFile(certPath)
	keyData, _ := os.ReadFile(keyPath)
	if string(certData) != string(newCert) {
		t.Error("cert content mismatch")
	}
	if string(keyData) != string(newKey) {
		t.Error("key content mismatch")
	}
}

func TestLoadExisting_MissingFiles(t *testing.T) {
	dir := t.TempDir()
	rotator := NewCertRotation(RotationConfig{
		CertTTL:     1 * time.Hour,
		RenewBefore: 10 * time.Minute,
		KeyDir:      dir,
	})

	if err := rotator.LoadExisting(); err == nil {
		t.Error("LoadExisting should fail when files don't exist")
	}
}

// generateTestCert 生成测试用的自签名证书。
func generateTestCert(t *testing.T, validity time.Duration) (certPEM, keyPEM []byte) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-node"},
		NotBefore:    time.Now().Add(-1 * time.Minute),
		NotAfter:     time.Now().Add(validity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	return
}
