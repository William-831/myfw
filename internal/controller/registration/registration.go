// Package registration implements the Registration gRPC service: it accepts
// a one-time bootstrap token + CSR from a new Agent, signs a client
// certificate, and inserts a PENDING node record awaiting admin approval.
// See docs/design.md § 13.3 and docs/development-plan.md § M3.
package registration

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"gorm.io/gorm"

	myfwv1 "iptables-tool/api/myfw/v1"
	"iptables-tool/internal/model"
	"iptables-tool/internal/pki"
)

// AuditSink is the minimum surface the audit module must expose; kept small so
// registration doesn't depend on the concrete audit package.
type AuditSink interface {
	Write(ctx context.Context, entry model.AuditLog) error
}

// Service implements myfwv1.RegistrationServer.
type Service struct {
	myfwv1.UnimplementedRegistrationServer

	DB           *gorm.DB
	CA           *pki.CA
	AgentCertTTL time.Duration
	Audit        AuditSink
}

// New constructs a Service. Callers must set all fields.
func New(db *gorm.DB, ca *pki.CA, ttl time.Duration, audit AuditSink) *Service {
	return &Service{DB: db, CA: ca, AgentCertTTL: ttl, Audit: audit}
}

// Register exchanges a bootstrap token + CSR for a signed client certificate.
// The newly-registered node is inserted in PENDING state; it can heartbeat
// once the client cert is used, but the Controller will not dispatch rules
// until an admin approves it.
func (s *Service) Register(ctx context.Context, req *myfwv1.RegisterRequest) (*myfwv1.RegisterResponse, error) {
	if req == nil || req.CandidateId == "" || len(req.CsrPem) == 0 {
		return nil, status.Error(codes.InvalidArgument, "candidate_id and csr_pem are required")
	}
	// 空 token 走续签分支（依赖 mTLS 已认证旧证书）；非空 token 走首次注册
	if req.BootstrapToken == "" {
		return s.renewCert(ctx, req)
	}

	// Consume the bootstrap token inside a transaction so a race between two
	// concurrent Register calls cannot both succeed.
	var (
		finalID  string
		certPEM  []byte
		notAfter time.Time
		nodeStat model.NodeStatus
	)
	err := s.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var tok model.BootstrapToken
		if err := tx.Where("token = ?", req.BootstrapToken).First(&tok).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return status.Error(codes.PermissionDenied, "invalid bootstrap token")
			}
			return err
		}
		if tok.UsedAt != nil {
			return status.Error(codes.PermissionDenied, "bootstrap token already used")
		}
		if time.Now().After(tok.ExpiresAt) {
			return status.Error(codes.PermissionDenied, "bootstrap token expired")
		}

		// Resolve final node id — the candidate id is used verbatim unless it
		// already exists, in which case we append a short random suffix.
		id, err := allocateNodeID(tx, req.CandidateId)
		if err != nil {
			return err
		}

		// Sign the client certificate for this node.
		// 如果 CA 为空（禁用 mTLS），跳过证书签名
		var (
			signed []byte
			na     time.Time
			fp     string
		)
		if s.CA != nil {
			signed, na, err = s.CA.SignAgentCert(req.CsrPem, id, s.AgentCertTTL)
			if err != nil {
				return status.Errorf(codes.InvalidArgument, "sign csr: %v", err)
			}
			fp, err = pki.FingerprintPEM(signed)
			if err != nil {
				return status.Errorf(codes.Internal, "fingerprint: %v", err)
			}
		} else {
			// 禁用 mTLS 时，使用节点 ID 作为唯一指纹
			na = time.Now().Add(s.AgentCertTTL)
			fp = "no-mtls-" + id
		}

		// Persist node (PENDING), capability, and certificate binding.
		node := model.Node{
			ID:        id,
			Status:    model.NodeStatusPending,
			Name:      tok.Note, // 添加节点时填写的名称（bootstrap token note）
			Hostname:  fingerprintHostname(req),
			IP:        nodeIPFromRequest(req, ctx),
			MachineID: fingerprintMachineID(req),
			Arch:      fingerprintArch(req),
		}
		if err := tx.Create(&node).Error; err != nil {
			return status.Errorf(codes.Internal, "persist node: %v", err)
		}

		if req.Capability != nil {
			raw, _ := json.Marshal(req.Capability)
			cap := model.NodeCapability{
				NodeID:          id,
				Distro:          req.Capability.Distro,
				KernelVersion:   req.Capability.KernelVersion,
				IptablesVersion: req.Capability.IptablesVersion,
				SelectedBackend: req.Capability.SelectedBackend.String(),
				NftSupported:    req.Capability.NftSupported,
				DockerPresent:   req.Capability.DockerPresent,
				K8sPresent:      req.Capability.KubernetesPresent,
				Raw:             string(raw),
			}
			if err := tx.Create(&cap).Error; err != nil {
				return status.Errorf(codes.Internal, "persist capability: %v", err)
			}
		}

		cert := model.Certificate{
			NodeID:      id,
			Fingerprint: fp,
			NotBefore:   time.Now().UTC(),
			NotAfter:    na,
		}
		if err := tx.Create(&cert).Error; err != nil {
			return status.Errorf(codes.Internal, "persist cert: %v", err)
		}

		// Mark token as consumed.
		now := time.Now().UTC()
		if err := tx.Model(&tok).Update("used_at", &now).Error; err != nil {
			return status.Errorf(codes.Internal, "consume token: %v", err)
		}

		finalID, certPEM, notAfter, nodeStat = id, signed, na, model.NodeStatusPending
		return nil
	})
	if err != nil {
		return nil, err
	}

	// Best-effort audit; the registration itself has succeeded regardless.
	if s.Audit != nil {
		detail, _ := json.Marshal(map[string]any{
			"candidate_id": req.CandidateId,
			"not_after":    notAfter,
			"fingerprint":  fingerprintFromPEM(certPEM),
		})
		_ = s.Audit.Write(ctx, model.AuditLog{
			Actor:  "agent",
			Action: "node.register",
			NodeID: finalID,
			Detail: string(detail),
		})
	}

	return &myfwv1.RegisterResponse{
		NodeId:        finalID,
		ClientCertPem: certPEM,
		NodeStatus:    string(nodeStat),
	}, nil
}

// renewCert 处理空 token 的续签请求：用 mTLS 旧证书身份签发新证书，
// 事务内吊销旧证书并新增证书记录。设计见 docs/design.md § 13。
func (s *Service) renewCert(ctx context.Context, req *myfwv1.RegisterRequest) (*myfwv1.RegisterResponse, error) {
	if s.CA == nil {
		return nil, status.Error(codes.Unavailable, "certificate renewal requires mTLS enabled")
	}
	cert, err := clientCertFromContext(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}
	nodeID, err := pki.NodeIDFromCert(cert)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}
	if nodeID != req.CandidateId {
		return nil, status.Error(codes.PermissionDenied, "candidate_id does not match certificate")
	}
	oldFP := pki.Fingerprint(cert)

	// 校验旧证书未吊销 + 节点非归档
	var oldCert model.Certificate
	if err := s.DB.WithContext(ctx).Where("fingerprint = ?", oldFP).First(&oldCert).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Error(codes.PermissionDenied, "unknown certificate")
		}
		return nil, status.Error(codes.Internal, "certificate lookup failed")
	}
	if oldCert.Revoked {
		return nil, status.Error(codes.PermissionDenied, "certificate revoked")
	}
	var node model.Node
	if err := s.DB.WithContext(ctx).Where("id = ?", nodeID).First(&node).Error; err != nil {
		return nil, status.Error(codes.PermissionDenied, "unknown node")
	}
	if node.Status == model.NodeStatusArchived {
		return nil, status.Error(codes.PermissionDenied, "node archived")
	}

	// 签发新证书
	signed, notAfter, err := s.CA.SignAgentCert(req.CsrPem, nodeID, s.AgentCertTTL)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "sign csr: %v", err)
	}
	newFP, err := pki.FingerprintPEM(signed)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "fingerprint: %v", err)
	}

	// 事务：吊销旧证书 + 新增新证书记录
	now := time.Now().UTC()
	if err := s.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&model.Certificate{}).Where("id = ?", oldCert.ID).Updates(map[string]any{
			"revoked":    true,
			"revoked_at": &now,
		}).Error; err != nil {
			return err
		}
		return tx.Create(&model.Certificate{
			NodeID:      nodeID,
			Fingerprint: newFP,
			NotBefore:   now,
			NotAfter:    notAfter,
		}).Error
	}); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	trigger := req.Trigger
	if trigger == "" {
		trigger = "auto" // 向后兼容旧 Agent
	}
	if s.Audit != nil {
		detail, _ := json.Marshal(map[string]any{
			"node_id":         nodeID,
			"old_fingerprint": oldFP,
			"new_fingerprint": newFP,
			"not_after":       notAfter,
			"trigger":         trigger,
		})
		_ = s.Audit.Write(ctx, model.AuditLog{
			Actor:  trigger, // "auto" / "manual"
			Action: "node.cert_renew",
			NodeID: nodeID,
			Detail: string(detail),
		})
	}

	return &myfwv1.RegisterResponse{
		NodeId:        nodeID,
		ClientCertPem: signed,
		NodeStatus:    string(node.Status),
	}, nil
}

// clientCertFromContext 从 gRPC mTLS 握手提取已验证的客户端证书。
func clientCertFromContext(ctx context.Context) (*x509.Certificate, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return nil, errors.New("no peer info")
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return nil, errors.New("not a TLS connection")
	}
	if len(tlsInfo.State.VerifiedChains) == 0 || len(tlsInfo.State.VerifiedChains[0]) == 0 {
		return nil, errors.New("client certificate required")
	}
	return tlsInfo.State.VerifiedChains[0][0], nil
}

// allocateNodeID keeps the candidate id whenever possible so /var/lib/myfw-agent/node.id
// on the Agent side matches what the Controller stores. On collision we append
// a short random suffix (design.md § 13.3.2).
func allocateNodeID(tx *gorm.DB, candidate string) (string, error) {
	var count int64
	if err := tx.Model(&model.Node{}).Where("id = ?", candidate).Count(&count).Error; err != nil {
		return "", err
	}
	if count == 0 {
		return candidate, nil
	}
	// Truncate the candidate a bit and append 4 random hex chars.
	buf := make([]byte, 2)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return fmt.Sprintf("%s_%s", candidate, hex.EncodeToString(buf)), nil
}

// constant-time token compare kept as a helper for the future revoke/lookup
// paths; not used above since the query is by exact match already.
func tokenEqual(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }

func fingerprintHostname(req *myfwv1.RegisterRequest) string {
	if req.Fingerprint != nil {
		return req.Fingerprint.Hostname
	}
	return ""
}
func fingerprintMachineID(req *myfwv1.RegisterRequest) string {
	if req.Fingerprint != nil {
		return req.Fingerprint.MachineId
	}
	return ""
}
func fingerprintArch(req *myfwv1.RegisterRequest) string {
	if req.Fingerprint != nil {
		return req.Fingerprint.Arch
	}
	return ""
}

// extractIP 从 gRPC 上下文中提取客户端 IP 地址
func extractIP(ctx context.Context) string {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return ""
	}
	addr, ok := p.Addr.(*net.TCPAddr)
	if !ok {
		// 尝试解析字符串形式的地址
		host, _, err := net.SplitHostPort(p.Addr.String())
		if err != nil {
			return p.Addr.String()
		}
		return host
	}
	return addr.IP.String()
}

// nodeIPFromRequest 优先取 Agent 上报的本机 IP（fingerprint.ip_addresses，已排除 loopback），
// 若 Agent 未上报则回退到 gRPC 连接的 peer IP，避免同机部署时误存 127.0.0.1。
func nodeIPFromRequest(req *myfwv1.RegisterRequest, ctx context.Context) string {
	if req.Fingerprint != nil {
		for _, ip := range req.Fingerprint.IpAddresses {
			if ip == "" || ip == "127.0.0.1" || ip == "::1" {
				continue
			}
			return ip
		}
	}
	return extractIP(ctx)
}

func fingerprintFromPEM(certPEM []byte) string {
	fp, _ := pki.FingerprintPEM(certPEM)
	return fp
}
