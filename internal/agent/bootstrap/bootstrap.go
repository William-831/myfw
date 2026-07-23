// Package bootstrap owns the Agent's first-time registration flow: it derives
// a stable candidate node id, generates a fresh EC private key and CSR, sends
// them to the Controller together with a one-time bootstrap token, and
// persists the returned client certificate. See docs/design.md § 13.3.
package bootstrap

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	myfwv1 "iptables-tool/api/myfw/v1"
)

// Identity holds the durable pieces of a node's identity that live under
// DataDir. It survives Agent restarts and re-bootstraps.
type Identity struct {
	NodeID string // "n_<32 hex>"
	Salt   []byte // 32 random bytes, used to derive NodeID
}

// LoadOrCreateIdentity returns the identity stored under dataDir, creating a
// fresh one on first launch. The candidate node id is derived from
// machine-id || hostname || salt so it is stable across Agent restarts on the
// same host but distinct across cloud-image clones (which share machine-id).
func LoadOrCreateIdentity(dataDir string) (*Identity, error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("bootstrap: mkdir %s: %w", dataDir, err)
	}

	saltPath := filepath.Join(dataDir, "salt")
	idPath := filepath.Join(dataDir, "node.id")

	salt, err := readOrCreateSalt(saltPath)
	if err != nil {
		return nil, err
	}

	// If node.id already exists on disk, trust it: id is meant to be stable.
	if raw, err := os.ReadFile(idPath); err == nil {
		id := string(rtrimNL(raw))
		if id != "" {
			return &Identity{NodeID: id, Salt: salt}, nil
		}
	}

	id, err := deriveNodeID(salt)
	if err != nil {
		return nil, err
	}
	if err := writeFileAtomic(idPath, []byte(id+"\n"), 0o600); err != nil {
		return nil, err
	}
	return &Identity{NodeID: id, Salt: salt}, nil
}

// deriveNodeID computes candidate_id = "n_" + hex(sha256(machine_id || hostname || salt))[:32].
func deriveNodeID(salt []byte) (string, error) {
	machineID := readMachineID()
	host, _ := os.Hostname()

	h := sha256.New()
	h.Write([]byte(machineID))
	h.Write([]byte{0})
	h.Write([]byte(host))
	h.Write([]byte{0})
	h.Write(salt)

	sum := h.Sum(nil)
	return "n_" + hex.EncodeToString(sum)[:32], nil
}

// readMachineID reads /etc/machine-id (Linux) or falls back to a hostname-
// derived value on other OSes so tests / macOS dev machines still work.
func readMachineID() string {
	if raw, err := os.ReadFile("/etc/machine-id"); err == nil {
		return string(rtrimNL(raw))
	}
	if raw, err := os.ReadFile("/var/lib/dbus/machine-id"); err == nil {
		return string(rtrimNL(raw))
	}
	host, _ := os.Hostname()
	return "no-machine-id:" + runtime.GOOS + ":" + host
}

func readOrCreateSalt(path string) ([]byte, error) {
	if raw, err := os.ReadFile(path); err == nil && len(raw) >= 32 {
		return raw[:32], nil
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return nil, err
	}
	if err := writeFileAtomic(path, buf, 0o600); err != nil {
		return nil, err
	}
	return buf, nil
}

// KeyAndCSR is the material an Agent generates locally: the private key stays
// on disk, only the CSR travels to the Controller.
type KeyAndCSR struct {
	KeyPEM []byte
	CSRPEM []byte
}

// GenerateKeyAndCSR builds a new EC P-256 keypair and a CSR whose CN is the
// candidate node id. The Controller re-encodes the id into a URI SAN when it
// signs, so we don't need to set one here.
func GenerateKeyAndCSR(candidateID string) (*KeyAndCSR, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("bootstrap: gen key: %w", err)
	}
	tmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: candidateID}}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		return nil, fmt.Errorf("bootstrap: create csr: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("bootstrap: marshal key: %w", err)
	}
	return &KeyAndCSR{
		KeyPEM: pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
		CSRPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}),
	}, nil
}

// Register runs the full first-time flow using the given Registration client
// and persists both the private key and the signed certificate to their
// configured paths. It returns the final node id and status assigned by the
// Controller.
type Persist struct {
	CertFile string
	KeyFile  string
}

type Result struct {
	NodeID     string
	NodeStatus string
}

// Do runs the bootstrap flow. keyGen lets tests supply a fixed key; pass nil
// to have a fresh one generated. fingerprint and capability are attached to
// the Register request.
func Do(
	ctx context.Context,
	client myfwv1.RegistrationClient,
	candidateID string,
	token string,
	fp *myfwv1.MachineFingerprint,
	cap *myfwv1.Capability,
	dst Persist,
) (*Result, error) {
	if client == nil {
		return nil, errors.New("bootstrap: registration client is nil")
	}
	if token == "" {
		return nil, errors.New("bootstrap: empty bootstrap token")
	}
	kc, err := GenerateKeyAndCSR(candidateID)
	if err != nil {
		return nil, err
	}

	resp, err := client.Register(ctx, &myfwv1.RegisterRequest{
		BootstrapToken: token,
		CandidateId:    candidateID,
		CsrPem:         kc.CSRPEM,
		Fingerprint:    fp,
		Capability:     cap,
	})
	if err != nil {
		return nil, fmt.Errorf("bootstrap: Register RPC: %w", err)
	}
	if resp == nil || len(resp.ClientCertPem) == 0 || resp.NodeId == "" {
		return nil, errors.New("bootstrap: empty response")
	}

	// Persist private key FIRST, then cert. This ordering means a crash
	// between the two writes leaves the cert without a matching key on disk,
	// which the Agent will detect at next start and re-bootstrap only if the
	// operator explicitly clears the state — safer than the reverse ordering
	// where a leftover key without a cert looks correctly bootstrapped.
	if err := writeFileAtomic(dst.KeyFile, kc.KeyPEM, 0o600); err != nil {
		return nil, err
	}
	if err := writeFileAtomic(dst.CertFile, resp.ClientCertPem, 0o644); err != nil {
		return nil, err
	}
	return &Result{NodeID: resp.NodeId, NodeStatus: resp.NodeStatus}, nil
}

// --- filesystem helpers -----------------------------------------------------

// writeFileAtomic writes data to path via a temp file + rename, and chmods to
// the requested mode. It's atomic w.r.t. concurrent readers on the same FS.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	return os.Rename(tmpName, path)
}

func rtrimNL(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}
