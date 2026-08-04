package server_test

// M5 end-to-end: Controller (real gRPC + REST) ← in-process Agent (real
// bootstrap + real conn.Loop + iptables driver on a fake executor). This is
// the closest possible thing to a Linux VM test: only the low-level exec
// interface is faked, everything above it (proto, gRPC, mTLS, auth, stream
// dispatch, driver logic) runs the exact production code path.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
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
	"iptables-tool/internal/agent/conn"
	iptdriver "iptables-tool/internal/agent/driver/iptables"
	"iptables-tool/internal/agent/driver/iptables/fakeexec"
	"iptables-tool/internal/agent/handler"
	"iptables-tool/internal/config"
	ctrlserver "iptables-tool/internal/controller/server"
	"iptables-tool/internal/controller/stream"
	"iptables-tool/internal/db"
)

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

func TestApplyEndToEnd(t *testing.T) {
	caDir := findCA(t)

	// --- Controller ---
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
	grpcLn, _ := net.Listen("tcp", "127.0.0.1:0")
	grpcAddr := grpcLn.Addr().String()
	go func() { _ = srv.GRPCServerForTest().Serve(grpcLn) }()
	t.Cleanup(srv.GRPCServerForTest().Stop)

	// Web must share the same *stream.Service as the gRPC server so REST
	// applies dispatch onto the same registry the Agent connected to.
	sharedStream := srv.StreamForTest()
	webSrv := httptest.NewServer(ctrlserver.BuildWebHandlerWithStream(gdb, cfg.Bootstrap.TokenTTL, sharedStream))
	t.Cleanup(webSrv.Close)

	// --- mint bootstrap token ---
	tok := postJSON(t, webSrv.URL+"/api/v1/nodes/bootstrap", `{"note":"m5 e2e"}`)["token"].(string)

	// --- Agent side: bootstrap, then approve, then start conn.Loop ---
	dataDir := t.TempDir()
	certFile := filepath.Join(dataDir, "agent.crt")
	keyFile := filepath.Join(dataDir, "agent.key")

	pool := loadPool(t, filepath.Join(caDir, "ca.pem"))
	bootConn, _ := grpc.NewClient(grpcAddr, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
		RootCAs: pool, ServerName: "localhost",
	})))
	defer bootConn.Close()

	id, _ := bootstrap.LoadOrCreateIdentity(dataDir)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	res, err := bootstrap.Do(ctx, myfwv1.NewRegistrationClient(bootConn),
		id.NodeID, tok,
		bootstrap.MachineFingerprint(),
		agentcap.Detect(ctx),
		bootstrap.Persist{CertFile: certFile, KeyFile: keyFile},
	)
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	nodeID := res.NodeID

	// Approve so the node is ACTIVE — PENDING nodes aren't rejected at the
	// auth layer in M3, but production dispatch should never target PENDING
	// (task_routes doesn't gate on status yet either, but making the flow
	// realistic here documents the expected behavior).
	postJSON(t, webSrv.URL+"/api/v1/nodes/"+nodeID+"/approve", "")

	// --- start Agent's authenticated stream with a Handler backed by the
	//     iptables Driver on a fake executor. ---
	clientCert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	streamConn, err := grpc.NewClient(grpcAddr, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
		RootCAs:      pool,
		Certificates: []tls.Certificate{clientCert},
		ServerName:   "localhost",
	})))
	if err != nil {
		t.Fatal(err)
	}
	defer streamConn.Close()

	fakeIpt := fakeexec.New()
	drv := iptdriver.New(fakeIpt, myfwv1.FirewallBackend_FIREWALL_BACKEND_IPTABLES_NFT)
	h := handler.New(drv, ctrlserver.TestLogger())

	// Loop runs until ctx is cancelled. Give it its own goroutine.
	loopDone := make(chan struct{})
	sendCh := make(chan *myfwv1.AgentToController, 8)
	go func() {
		_ = conn.Loop(ctx, streamConn, ctrlserver.TestLogger(), nodeID,
			agentcap.Detect(ctx), h,
			conn.HeartbeatOptions{Interval: 200 * time.Millisecond, InitialBackoff: 100 * time.Millisecond},
			sendCh, nil)
		close(loopDone)
	}()

	// Wait for the Agent to appear in the registry.
	if !waitForConnected(sharedStream, nodeID, 3*time.Second) {
		t.Fatalf("agent never showed up in registry")
	}

	// --- dispatch an Apply via REST ---
	applyBody := `{
		"rules": [
			{"id":"r1","direction":"INBOUND","source":"10.0.0.0/24","protocol":"TCP","port_range":"22","action":"ACCEPT","priority":10},
			{"id":"r2","direction":"INBOUND","source":"192.168.1.0/24","protocol":"TCP","port_range":"80","action":"ACCEPT","priority":20},
			{"id":"r3","action":"DNAT","protocol":"TCP","port_range":"443","nat_to":"10.0.0.5:8443","priority":30}
		]
	}`
	got := postJSON(t, webSrv.URL+"/api/v1/nodes/"+nodeID+"/apply", applyBody)

	if ok, _ := got["ok"].(bool); !ok {
		t.Fatalf("apply not ok: %v", got)
	}
	rh, _ := got["result_hash"].(string)
	if !strings.HasPrefix(rh, "sha256:") {
		t.Fatalf("bad result_hash: %v", got)
	}

	// --- verify the fake iptables really has the rules ---
	inputChain := fakeIpt.Tables["filter"]["MYFW-INPUT"]
	if len(inputChain) != 2 {
		t.Fatalf("MYFW-INPUT should have 2 rules, got %d: %v", len(inputChain), inputChain)
	}
	if !anyContains(inputChain, "-s 10.0.0.0/24") {
		t.Fatalf("MYFW-INPUT missing r1: %v", inputChain)
	}
	if !anyContains(inputChain, "-s 192.168.1.0/24") {
		t.Fatalf("MYFW-INPUT missing r2: %v", inputChain)
	}
	if got := len(fakeIpt.Tables["nat"]["MYFW-PREROUTING"]); got != 1 {
		t.Fatalf("MYFW-PREROUTING should have 1 DNAT rule, got %d", got)
	}

	cancel()
	select {
	case <-loopDone:
	case <-time.After(2 * time.Second):
		t.Fatal("agent loop did not exit on ctx cancel")
	}
}

func waitForConnected(s *stream.Service, nodeID string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		for _, id := range s.Reg.Connected() {
			if id == nodeID {
				return true
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

func anyContains(ss []string, needle string) bool {
	for _, s := range ss {
		if strings.Contains(s, needle) {
			return true
		}
	}
	return false
}

// --- test helpers ---------------------------------------------------------

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
	if len(raw) == 0 {
		return map[string]any{}
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("decode: %v (%s)", err, string(raw))
	}
	return m
}
