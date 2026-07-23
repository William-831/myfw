package bootstrap_test

// End-to-end bootstrap test: starts the M3 Controller gRPC server + REST
// handler in-process against SQLite, then runs the Agent's bootstrap flow
// against it. Verifies that (a) a signed cert lands on disk with the right
// node id encoded in it, and (b) the bootstrap token is single-use.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	myfwv1 "iptables-tool/api/myfw/v1"
	"iptables-tool/internal/agent/bootstrap"
	agentcap "iptables-tool/internal/agent/capability"
	"iptables-tool/internal/config"
	ctrlserver "iptables-tool/internal/controller/server"
	"iptables-tool/internal/db"
	"iptables-tool/internal/pki"
)

// findCA walks up from the test directory looking for dev-ca/ca.pem.
func findCA(t *testing.T) string {
	t.Helper()
	dir, _ := os.Getwd()
	for i := 0; i < 6; i++ {
		p := filepath.Join(dir, "dev-ca")
		if _, err := os.Stat(filepath.Join(p, "ca.pem")); err == nil {
			return p
		}
		dir = filepath.Dir(dir)
	}
	t.Skip("dev-ca not found; run `make gen-ca` from repo root")
	return ""
}

func TestAgentBootstrapAgainstRealController(t *testing.T) {
	caDir := findCA(t)

	// --- Controller: real DB, real gRPC on random port ---
	t.Setenv("MYFW_DB_DRIVER", "sqlite")
	t.Setenv("MYFW_DB_DSN", filepath.Join(t.TempDir(), "srv.db"))
	gdb, err := db.OpenFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(gdb); err != nil {
		t.Fatal(err)
	}

	cfg := config.Default()
	cfg.Server.GRPC.TLS = config.TLSConfig{
		CAFile:   filepath.Join(caDir, "ca.pem"),
		CertFile: filepath.Join(caDir, "server.crt"),
		KeyFile:  filepath.Join(caDir, "server.key"),
	}
	cfg.CA = config.CAConfig{
		CertFile:     filepath.Join(caDir, "ca.pem"),
		KeyFile:      filepath.Join(caDir, "ca.key"),
		AgentCertTTL: time.Hour,
	}
	cfg.Bootstrap.TokenTTL = 15 * time.Minute

	srv, err := ctrlserver.New(cfg, ctrlserver.TestLogger(), gdb)
	if err != nil {
		t.Fatal(err)
	}

	grpcLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	grpcAddr := grpcLn.Addr().String()
	go func() { _ = srv.GRPCServerForTest().Serve(grpcLn) }()
	t.Cleanup(srv.GRPCServerForTest().Stop)

	// Web (mint bootstrap token).
	webSrv := httptest.NewServer(ctrlserver.BuildWebHandler(gdb, cfg.Bootstrap.TokenTTL))
	t.Cleanup(webSrv.Close)

	tokMap := postJSON(t, webSrv.URL+"/api/v1/nodes/bootstrap", `{"note":"agent e2e"}`)
	token, _ := tokMap["token"].(string)
	if token == "" {
		t.Fatalf("no token: %v", tokMap)
	}

	// --- Agent: run bootstrap ---
	dataDir := t.TempDir()
	certFile := filepath.Join(dataDir, "agent.crt")
	keyFile := filepath.Join(dataDir, "agent.key")

	pool := loadPool(t, filepath.Join(caDir, "ca.pem"))
	conn, err := grpc.NewClient(grpcAddr, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
		RootCAs:    pool,
		ServerName: "localhost",
	})))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	regClient := myfwv1.NewRegistrationClient(conn)

	id, err := bootstrap.LoadOrCreateIdentity(dataDir)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res, err := bootstrap.Do(ctx, regClient, id.NodeID, token,
		bootstrap.MachineFingerprint(),
		agentcap.Detect(ctx),
		bootstrap.Persist{CertFile: certFile, KeyFile: keyFile})
	if err != nil {
		t.Fatalf("bootstrap.Do: %v", err)
	}
	if res.NodeID != id.NodeID {
		t.Fatalf("expected node id %q, got %q", id.NodeID, res.NodeID)
	}
	if res.NodeStatus != "PENDING" {
		t.Fatalf("expected PENDING, got %q", res.NodeStatus)
	}

	// Signed cert on disk carries the right node id in its URI SAN.
	certRaw, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}
	block, _ := pem.Decode(certRaw)
	if block == nil {
		t.Fatal("cert not PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := pki.NodeIDFromCert(cert); got != id.NodeID {
		t.Fatalf("cert node id = %q, want %q", got, id.NodeID)
	}

	// Private key on disk is a valid EC key that pairs with the cert.
	if _, err := tls.LoadX509KeyPair(certFile, keyFile); err != nil {
		t.Fatalf("cert/key not a valid pair: %v", err)
	}
	keyRaw, _ := os.ReadFile(keyFile)
	if !strings.Contains(string(keyRaw), "EC PRIVATE KEY") {
		t.Fatalf("key file missing EC PRIVATE KEY header")
	}

	// Reusing the same token must fail — single-use is enforced end-to-end.
	if _, err := bootstrap.Do(ctx, regClient, id.NodeID+"_dup", token,
		bootstrap.MachineFingerprint(),
		agentcap.Detect(ctx),
		bootstrap.Persist{CertFile: filepath.Join(dataDir, "x.crt"), KeyFile: filepath.Join(dataDir, "x.key")},
	); err == nil {
		t.Fatal("expected token reuse to fail")
	}
}

// --- helpers ---------------------------------------------------------------

func loadPool(t *testing.T, path string) *x509.CertPool {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	p := x509.NewCertPool()
	if !p.AppendCertsFromPEM(raw) {
		t.Fatal("no certs in CA")
	}
	return p
}

func postJSON(t *testing.T, url, body string) map[string]any {
	t.Helper()
	resp, err := http.Post(url, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		t.Fatalf("HTTP %d: %s", resp.StatusCode, string(raw))
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("decode: %v (%s)", err, string(raw))
	}
	return m
}
