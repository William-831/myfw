package security

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"time"
)

// RotationConfig 证书轮换配置。
type RotationConfig struct {
	// CertTTL 证书有效期，默认24小时（内网环境短证书更安全）
	CertTTL time.Duration
	// RenewBefore 到期前多久开始轮换，默认有效期的20%
	RenewBefore time.Duration
	// KeyDir 证书存储目录
	KeyDir string
	// Logger
	Logger *slog.Logger
}

// DefaultRotationConfig 返回默认配置。
func DefaultRotationConfig() RotationConfig {
	return RotationConfig{
		CertTTL:     24 * time.Hour,
		RenewBefore: 5 * time.Hour, // 24h的约20%
		KeyDir:      "/var/lib/myfw-agent",
		Logger:      slog.Default(),
	}
}

// CertRotation 证书自动轮换器。
type CertRotation struct {
	cfg      RotationConfig
	keyPEM   []byte // 当前私钥
	certPEM  []byte // 当前证书
	keyPath  string
	certPath string
}

// NewCertRotation 创建证书轮换器。
func NewCertRotation(cfg RotationConfig) *CertRotation {
	return &CertRotation{
		cfg:      cfg,
		keyPath:  cfg.KeyDir + "/agent.key",
		certPath: cfg.KeyDir + "/agent.crt",
	}
}

// LoadExisting 加载已有的证书和密钥。
func (cr *CertRotation) LoadExisting() error {
	keyRaw, err := os.ReadFile(cr.keyPath)
	if err != nil {
		return fmt.Errorf("rotation: read key: %w", err)
	}
	certRaw, err := os.ReadFile(cr.certPath)
	if err != nil {
		return fmt.Errorf("rotation: read cert: %w", err)
	}
	cr.keyPEM = keyRaw
	cr.certPEM = certRaw
	return nil
}

// NeedsRotation 检查证书是否需要轮换。
func (cr *CertRotation) NeedsRotation() bool {
	if len(cr.certPEM) == 0 {
		return true
	}
	block, _ := pem.Decode(cr.certPEM)
	if block == nil {
		return true
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return true
	}
	remaining := time.Until(cert.NotAfter)
	return remaining < cr.cfg.RenewBefore
}

// GenerateCSR 生成新的密钥对和CSR。
func (cr *CertRotation) GenerateCSR(nodeID string) (csrPEM []byte, newKeyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("rotation: gen key: %w", err)
	}
	newKeyPEM, err = x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("rotation: marshal key: %w", err)
	}
	newKeyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: newKeyPEM})

	tmpl := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: nodeID},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		return nil, nil, fmt.Errorf("rotation: create csr: %w", err)
	}
	csrPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	return csrPEM, newKeyPEM, nil
}

// ApplyNewCert 持久化新的证书和密钥（原子写入）。
func (cr *CertRotation) ApplyNewCert(certPEM, keyPEM []byte) error {
	// 先写密钥，再写证书。密钥先落地确保崩溃安全。
	if err := atomicWrite(cr.keyPath, keyPEM, 0600); err != nil {
		return fmt.Errorf("rotation: write key: %w", err)
	}
	if err := atomicWrite(cr.certPath, certPEM, 0644); err != nil {
		return fmt.Errorf("rotation: write cert: %w", err)
	}
	cr.keyPEM = keyPEM
	cr.certPEM = certPEM
	cr.cfg.Logger.Info("certificate rotated successfully",
		"key_path", cr.keyPath,
		"cert_path", cr.certPath)
	return nil
}

// GetKeyPEM 获取当前私钥。
func (cr *CertRotation) GetKeyPEM() []byte { return cr.keyPEM }

// GetCertPEM 获取当前证书。
func (cr *CertRotation) GetCertPEM() []byte { return cr.certPEM }

// StartRotationLoop 启动后台轮换循环：用 Timer 定点唤醒而非轮询。
// 续签成功后按新证书重算唤醒时间，失败 1h 重试。正常仅临期一次唤醒，零轮询开销。
func (cr *CertRotation) StartRotationLoop(ctx context.Context, renewFn func(ctx context.Context) error) {
	go func() {
		for {
			if delay := cr.nextRenewDelay(); delay > 0 {
				timer := time.NewTimer(delay)
				select {
				case <-ctx.Done():
					timer.Stop()
					return
				case <-timer.C:
				}
			}
			cr.cfg.Logger.Info("certificate nearing expiry, attempting renewal")
			if err := renewFn(ctx); err != nil {
				cr.cfg.Logger.Error("certificate renewal failed", "err", err)
				// 失败后 1h 重试
				timer := time.NewTimer(time.Hour)
				select {
				case <-ctx.Done():
					timer.Stop()
					return
				case <-timer.C:
				}
			}
		}
	}()
}

// nextRenewDelay 返回距续签触发的剩余时间；<=0 表示需立即续签。
func (cr *CertRotation) nextRenewDelay() time.Duration {
	if len(cr.certPEM) == 0 {
		return 0
	}
	block, _ := pem.Decode(cr.certPEM)
	if block == nil {
		return 0
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return 0
	}
	return time.Until(cert.NotAfter) - cr.cfg.RenewBefore
}

// atomicWrite 原子写入文件（先写临时文件再重命名）。
func atomicWrite(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
