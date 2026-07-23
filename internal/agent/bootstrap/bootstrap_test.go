package bootstrap

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadOrCreateIdentityIsStable(t *testing.T) {
	dir := t.TempDir()

	id1, err := LoadOrCreateIdentity(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(id1.NodeID, "n_") || len(id1.NodeID) != 34 {
		t.Fatalf("unexpected node id format: %q", id1.NodeID)
	}
	if len(id1.Salt) != 32 {
		t.Fatalf("salt should be 32 bytes, got %d", len(id1.Salt))
	}

	// Reading node.id straight off disk should match.
	raw, err := os.ReadFile(filepath.Join(dir, "node.id"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(raw)) != id1.NodeID {
		t.Fatalf("on-disk id != returned id: %q vs %q", raw, id1.NodeID)
	}

	// A second call in the same dir must return the SAME id (stability).
	id2, err := LoadOrCreateIdentity(dir)
	if err != nil {
		t.Fatal(err)
	}
	if id2.NodeID != id1.NodeID {
		t.Fatalf("node id not stable across calls: %q -> %q", id1.NodeID, id2.NodeID)
	}
}

func TestLoadOrCreateIdentityDifferentSaltsDifferentIDs(t *testing.T) {
	// Two independent data dirs get independent salts and therefore different ids.
	a, err := LoadOrCreateIdentity(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	b, err := LoadOrCreateIdentity(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if a.NodeID == b.NodeID {
		t.Fatalf("independent salts should yield different ids, got %q both", a.NodeID)
	}
}

func TestGenerateKeyAndCSR(t *testing.T) {
	kc, err := GenerateKeyAndCSR("n_abc")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(kc.KeyPEM), "EC PRIVATE KEY") {
		t.Fatalf("private key PEM missing header: %s", kc.KeyPEM)
	}
	if !strings.Contains(string(kc.CSRPEM), "CERTIFICATE REQUEST") {
		t.Fatalf("CSR PEM missing header: %s", kc.CSRPEM)
	}
}
