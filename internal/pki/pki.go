// Package pki manages the Controller's private CA: loading, signing client
// certificates for Agents, and computing the fingerprints that bind a
// certificate to a node identity.
// See docs/design.md § 13.2 / § 13.3.
package pki

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"time"
)

// CA holds the loaded private CA material used to sign Agent client certs.
type CA struct {
	Cert *x509.Certificate
	Key  crypto.Signer
}

// LoadCA reads a PEM-encoded CA certificate and private key from disk.
func LoadCA(certFile, keyFile string) (*CA, error) {
	cert, err := readCert(certFile)
	if err != nil {
		return nil, fmt.Errorf("pki: read CA cert: %w", err)
	}
	key, err := readKey(keyFile)
	if err != nil {
		return nil, fmt.Errorf("pki: read CA key: %w", err)
	}
	return &CA{Cert: cert, Key: key}, nil
}

// SignAgentCert signs a client certificate for the given nodeID from a
// PEM-encoded CSR. The resulting certificate is valid for ttl and carries
// nodeID both as CN and as a URI SAN ("myfw:node:<id>") so that connection-
// layer interceptors can bind an incoming request to its node.
func (c *CA) SignAgentCert(csrPEM []byte, nodeID string, ttl time.Duration) (certPEM []byte, notAfter time.Time, err error) {
	csr, err := parseCSR(csrPEM)
	if err != nil {
		return nil, time.Time{}, err
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, time.Time{}, fmt.Errorf("pki: csr signature: %w", err)
	}

	serial, err := randSerial()
	if err != nil {
		return nil, time.Time{}, err
	}

	nodeURI := &url.URL{Scheme: "myfw", Opaque: "node:" + nodeID}
	now := time.Now().UTC()
	notAfter = now.Add(ttl)

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: nodeID},
		NotBefore:    now.Add(-1 * time.Minute), // allow small clock skew
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:         []*url.URL{nodeURI},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.Cert, csr.PublicKey, c.Key)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("pki: create certificate: %w", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return certPEM, notAfter, nil
}

// Fingerprint returns the hex-encoded SHA-256 hash of the DER form of cert.
// This is what we persist and check on every subsequent connection.
func Fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// FingerprintPEM computes the fingerprint of a PEM-encoded certificate.
func FingerprintPEM(certPEM []byte) (string, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return "", errors.New("pki: not a PEM CERTIFICATE block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("pki: parse cert: %w", err)
	}
	return Fingerprint(cert), nil
}

// NodeIDFromCert extracts the node id encoded into a client certificate's
// URI SAN ("myfw:node:<id>"). Falls back to the Subject CN when no such URI
// is present, since older or externally-issued certs might use CN.
func NodeIDFromCert(cert *x509.Certificate) (string, error) {
	for _, u := range cert.URIs {
		if u.Scheme == "myfw" && len(u.Opaque) > len("node:") && u.Opaque[:len("node:")] == "node:" {
			return u.Opaque[len("node:"):], nil
		}
	}
	if cert.Subject.CommonName != "" {
		return cert.Subject.CommonName, nil
	}
	return "", errors.New("pki: no node id in certificate")
}

// --- helpers -----------------------------------------------------------------

func readCert(path string) (*x509.Certificate, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("not a PEM CERTIFICATE")
	}
	return x509.ParseCertificate(block.Bytes)
}

func readKey(path string) (crypto.Signer, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("not a PEM block")
	}
	// Support both PKCS#1 ("RSA PRIVATE KEY") and PKCS#8 ("PRIVATE KEY").
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		signer, ok := k.(crypto.Signer)
		if !ok {
			return nil, errors.New("key does not implement crypto.Signer")
		}
		return signer, nil
	}
	if k, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	return nil, errors.New("unsupported private key format")
}

func parseCSR(csrPEM []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return nil, errors.New("pki: csr not PEM-encoded")
	}
	return x509.ParseCertificateRequest(block.Bytes)
}

func randSerial() (*big.Int, error) {
	// 128-bit random serial. RFC 5280 allows up to 20 bytes.
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, limit)
}
