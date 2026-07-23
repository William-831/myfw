package pki

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"
)

func TestSignAgentCertRoundTrip(t *testing.T) {
	caDir := writeDevCA(t)
	ca, err := LoadCA(caDir+"/ca.pem", caDir+"/ca.key")
	if err != nil {
		t.Fatalf("LoadCA: %v", err)
	}

	nodeID := "n_abc123"
	csrPEM := makeCSR(t, "unused-cn")
	certPEM, notAfter, err := ca.SignAgentCert(csrPEM, nodeID, time.Hour)
	if err != nil {
		t.Fatalf("SignAgentCert: %v", err)
	}
	if !time.Now().Before(notAfter) {
		t.Fatalf("notAfter should be in the future, got %v", notAfter)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("signed cert not PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse signed cert: %v", err)
	}

	// node id round-trips through the URI SAN.
	extracted, err := NodeIDFromCert(cert)
	if err != nil {
		t.Fatalf("NodeIDFromCert: %v", err)
	}
	if extracted != nodeID {
		t.Fatalf("node id round-trip: want %q got %q", nodeID, extracted)
	}

	// Fingerprint deterministic, well-formed.
	fp1, err := FingerprintPEM(certPEM)
	if err != nil {
		t.Fatalf("FingerprintPEM: %v", err)
	}
	if fp1[:7] != "sha256:" {
		t.Fatalf("fingerprint prefix wrong: %q", fp1)
	}
	if fp2 := Fingerprint(cert); fp2 != fp1 {
		t.Fatalf("fingerprint not stable: %q vs %q", fp1, fp2)
	}

	// Signed cert must be usable as a client cert.
	found := false
	for _, u := range cert.ExtKeyUsage {
		if u == x509.ExtKeyUsageClientAuth {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("signed cert missing ClientAuth ExtKeyUsage")
	}
}

func TestSignAgentCertRejectsBadCSR(t *testing.T) {
	caDir := writeDevCA(t)
	ca, err := LoadCA(caDir+"/ca.pem", caDir+"/ca.key")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ca.SignAgentCert([]byte("not a csr"), "n_x", time.Hour); err == nil {
		t.Fatal("expected error for garbage input")
	}
}
