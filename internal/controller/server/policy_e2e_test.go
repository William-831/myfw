package server_test

// M6 end-to-end: create a Policy via REST, dispatch its Apply, verify each
// target Agent's local (fake) iptables state contains the compiled rules —
// with all wiring in production code paths (mTLS gRPC + AgentStream + real
// compiler + real dispatcher + real driver interface on a fake exec).

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
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
	"iptables-tool/internal/db"
	"iptables-tool/internal/model"
)

// bootAgent is a helper that runs the full bootstrap + connects an authenticated
// stream backed by a fake iptables driver. Returns the fakeexec so tests can
// inspect the resulting rules.
func bootAgent(t *testing.T, caDir, grpcAddr, webURL string) (nodeID string, fake *fakeexec.Fake, cancelLoop context.CancelFunc) {
	t.Helper()

	// Mint a bootstrap token via REST.
	tokRaw := postJSON(t, webURL+"/api/v1/nodes/bootstrap", `{"note":"m6-e2e"}`)
	token := tokRaw["token"].(string)

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
	res, err := bootstrap.Do(ctx, myfwv1.NewRegistrationClient(bootConn),
		id.NodeID, token,
		bootstrap.MachineFingerprint(),
		agentcap.Detect(ctx),
		bootstrap.Persist{CertFile: certFile, KeyFile: keyFile},
	)
	if err != nil {
		cancel()
		t.Fatalf("bootstrap: %v", err)
	}
	nodeID = res.NodeID

	// Approve so downstream apply gates (future auth policy) will be happy.
	postJSON(t, webURL+"/api/v1/nodes/"+nodeID+"/approve", "")

	// Authenticated long-lived stream.
	clientCert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	streamConn, err := grpc.NewClient(grpcAddr, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
		RootCAs: pool, ServerName: "localhost",
		Certificates: []tls.Certificate{clientCert},
	})))
	if err != nil {
		cancel()
		t.Fatal(err)
	}

	fake = fakeexec.New()
	drv := iptdriver.New(fake, myfwv1.FirewallBackend_FIREWALL_BACKEND_IPTABLES_NFT)
	h := handler.New(drv, ctrlserver.TestLogger())

	sendCh := make(chan *myfwv1.AgentToController, 8)
	go func() {
		_ = conn.Loop(ctx, streamConn, ctrlserver.TestLogger(), nodeID,
			agentcap.Detect(ctx), h,
			conn.HeartbeatOptions{Interval: 200 * time.Millisecond, InitialBackoff: 100 * time.Millisecond},
			sendCh)
		_ = streamConn.Close()
	}()

	return nodeID, fake, cancel
}

// TestPolicyApplyEndToEnd is the M6 flagship: two agents connect; create a
// policy that targets one of them explicitly via node_ids; POST
// /api/v1/policies/:id/apply; verify the targeted agent got the rule and the
// other agent didn't.
func TestPolicyApplyEndToEnd(t *testing.T) {
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

	sharedStream := srv.StreamForTest()
	webSrv := httptest.NewServer(ctrlserver.BuildWebHandlerWithStream(gdb, cfg.Bootstrap.TokenTTL, sharedStream))
	t.Cleanup(webSrv.Close)

	// --- Two Agents ---
	nodeA, fakeA, cancelA := bootAgent(t, caDir, grpcAddr, webSrv.URL)
	t.Cleanup(cancelA)
	nodeB, fakeB, cancelB := bootAgent(t, caDir, grpcAddr, webSrv.URL)
	t.Cleanup(cancelB)

	// Wait for both to appear in the registry.
	if !waitForConnected(sharedStream, nodeA, 3*time.Second) ||
		!waitForConnected(sharedStream, nodeB, 3*time.Second) {
		t.Fatal("both agents did not connect")
	}

	// --- Create a Policy targeting only nodeA ---
	body := map[string]any{
		"name":       "allow-ssh-A",
		"direction":  "INBOUND",
		"source":     "10.0.0.0/24",
		"protocol":   "TCP",
		"port_range": "22",
		"action":     "ACCEPT",
		"priority":   10,
		"enabled":    true,
		"targets": map[string]any{
			"node_ids": []string{nodeA},
		},
	}
	buf, _ := json.Marshal(body)
	created := postJSON(t, webSrv.URL+"/api/v1/policies", string(buf))
	policyID, _ := created["id"].(float64) // JSON numbers -> float64
	if policyID == 0 {
		t.Fatalf("no policy id: %v", created)
	}

	// --- Apply it ---
	applyResp := postJSONRaw(t, webSrv.URL+"/api/v1/policies/"+intStr(int(policyID))+"/apply",
		`{"auto_approve":true}`)
	// Multi-status (207) or 200 both fine; each outcome is what matters.
	// When auto_approve=true the Coordinator dispatches immediately and the
	// response arrives synchronously (tasks array).
	tasks, _ := applyResp["tasks"].([]any)
	if len(tasks) != 1 {
		t.Fatalf("expected 1 task (only nodeA targeted), got %d: %v", len(tasks), applyResp)
	}
	first, _ := tasks[0].(map[string]any)
	status, _ := first["status"].(string)
	if status != "confirm_wait" && status != "applying" && status != "confirmed" {
		t.Fatalf("unexpected task status (want confirm_wait/applying/confirmed): %v", first)
	}

	// --- Verify nodeA has the rule, nodeB doesn't ---
	// The Coordinator dispatches asynchronously; give the agent a moment to
	// process the ApplyTask and execute it through the fake driver.
	waitForRules(t, fakeA, 2*time.Second, func(rules []string) bool {
		return len(rules) == 1 && strings.Contains(rules[0], "-s 10.0.0.0/24")
	}, "nodeA MYFW-INPUT should have the SSH rule")
	inputB := fakeB.Tables["filter"]["MYFW-INPUT"]
	if len(inputB) != 0 {
		t.Fatalf("nodeB should have NO rules, got %v", inputB)
	}
}

// TestApplyAllPoliciesFanOut targets both agents via labels; verifies fan-out.
func TestApplyAllPoliciesFanOut(t *testing.T) {
	caDir := findCA(t)
	t.Setenv("MYFW_DB_DRIVER", "sqlite")
	t.Setenv("MYFW_DB_DSN", filepath.Join(t.TempDir(), "srv.db"))
	gdb, _ := db.OpenFromEnv()
	_ = db.Migrate(gdb)

	cfg := config.Default()
	cfg.Server.GRPC.TLS = config.TLSConfig{
		CAFile:   filepath.Join(caDir, "ca.pem"),
		CertFile: filepath.Join(caDir, "server.crt"),
		KeyFile:  filepath.Join(caDir, "server.key"),
	}
	cfg.CA = config.CAConfig{
		CertFile: filepath.Join(caDir, "ca.pem"),
		KeyFile:  filepath.Join(caDir, "ca.key"), AgentCertTTL: time.Hour,
	}
	cfg.Bootstrap.TokenTTL = 15 * time.Minute

	srv, _ := ctrlserver.New(cfg, ctrlserver.TestLogger(), gdb)
	grpcLn, _ := net.Listen("tcp", "127.0.0.1:0")
	grpcAddr := grpcLn.Addr().String()
	go func() { _ = srv.GRPCServerForTest().Serve(grpcLn) }()
	t.Cleanup(srv.GRPCServerForTest().Stop)

	sharedStream := srv.StreamForTest()
	webSrv := httptest.NewServer(ctrlserver.BuildWebHandlerWithStream(gdb, cfg.Bootstrap.TokenTTL, sharedStream))
	t.Cleanup(webSrv.Close)

	nodeA, fakeA, cancelA := bootAgent(t, caDir, grpcAddr, webSrv.URL)
	t.Cleanup(cancelA)
	nodeB, fakeB, cancelB := bootAgent(t, caDir, grpcAddr, webSrv.URL)
	t.Cleanup(cancelB)

	if !waitForConnected(sharedStream, nodeA, 3*time.Second) ||
		!waitForConnected(sharedStream, nodeB, 3*time.Second) {
		t.Fatal("agents did not connect")
	}

	// Give both nodes the same label.
	if err := gdb.Model(&model.Node{}).Where("id IN ?", []string{nodeA, nodeB}).
		Update("labels", `["prod"]`).Error; err != nil {
		t.Fatalf("label update: %v", err)
	}

	// One policy targeting label "prod" — applies to both.
	body := map[string]any{
		"name": "block-danger", "direction": "INBOUND",
		"source": "1.2.3.4", "action": "DROP", "priority": 5, "enabled": true,
		"targets": map[string]any{"labels": []string{"prod"}},
	}
	buf, _ := json.Marshal(body)
	postJSON(t, webSrv.URL+"/api/v1/policies", string(buf))

	applyResp := postJSONRaw(t, webSrv.URL+"/api/v1/policies/apply-all", `{"auto_approve":true}`)
	tasks, _ := applyResp["tasks"].([]any)
	if len(tasks) != 2 {
		t.Fatalf("expected 2 tasks, got %d: %v", len(tasks), applyResp)
	}

	// Both nodes must have the drop rule (async dispatch, wait for it).
	for name, fake := range map[string]*fakeexec.Fake{"A": fakeA, "B": fakeB} {
		waitForRules(t, fake, 2*time.Second, func(rules []string) bool {
			return len(rules) == 1 && strings.Contains(rules[0], "-s 1.2.3.4")
		}, "node"+name+" should have 1 DROP rule")
	}
}

// waitForRules polls fake until the MYFW-INPUT chain matches the predicate or
// timeout expires, then asserts. Avoids flaky test timing on slow CI.
func waitForRules(t *testing.T, fake *fakeexec.Fake, timeout time.Duration, match func([]string) bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if match(fake.Tables["filter"]["MYFW-INPUT"]) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("%s; last seen: %v", msg, fake.Tables["filter"]["MYFW-INPUT"])
}

// --- extra helpers ---------------------------------------------------------

func intStr(n int) string {
	// avoid pulling strconv into a test-only file that already has strings; small helper.
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

func postJSONRaw(t *testing.T, url, body string) map[string]any {
	// alias of postJSON that tolerates the 207 status code the policy apply
	// endpoint returns when at least one node failed. Any 2xx or 207 is OK.
	t.Helper()
	m := postJSONAllow(t, url, body, 500)
	return m
}

// postJSONAllow accepts responses with status code < allow2xxUpper.
func postJSONAllow(t *testing.T, url, body string, upper int) map[string]any {
	t.Helper()
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Post(url, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= upper {
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
