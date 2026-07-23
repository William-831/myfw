// Package registration implements the Registration gRPC service: it accepts
// a one-time bootstrap token + CSR from a new Agent, signs a client
// certificate, and inserts a PENDING node record awaiting admin approval.
// See docs/design.md § 13.3 and docs/development-plan.md § M3.
package registration

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"google.golang.org/grpc/codes"
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
	if req == nil || req.BootstrapToken == "" || req.CandidateId == "" || len(req.CsrPem) == 0 {
		return nil, status.Error(codes.InvalidArgument, "bootstrap_token, candidate_id and csr_pem are required")
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
		signed, na, err := s.CA.SignAgentCert(req.CsrPem, id, s.AgentCertTTL)
		if err != nil {
			return status.Errorf(codes.InvalidArgument, "sign csr: %v", err)
		}
		fp, err := pki.FingerprintPEM(signed)
		if err != nil {
			return status.Errorf(codes.Internal, "fingerprint: %v", err)
		}

		// Persist node (PENDING), capability, and certificate binding.
		node := model.Node{
			ID:        id,
			Status:    model.NodeStatusPending,
			Hostname:  fingerprintHostname(req),
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
func fingerprintFromPEM(certPEM []byte) string {
	fp, _ := pki.FingerprintPEM(certPEM)
	return fp
}
