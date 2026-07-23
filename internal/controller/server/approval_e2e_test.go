package server_test

// M7 end-to-end: exercise the Coordinator's full approval lifecycle using a
// real Controller (gRPC + REST) and an in-process Agent with a fake iptables
// driver. Two paths:
//
//  1. Happy path: submit → approve → apply succeeds → confirm → CONFIRMED
//  2. Auto-rollback: submit → approve → apply succeeds → deadline expires → ROLLED_BACK
//
// These tests verify the state machine transitions, confirm/rollback delivery
// to the Agent, and the persisted task rows.

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"iptables-tool/internal/config"
	ctrlserver "iptables-tool/internal/controller/server"
	"iptables-tool/internal/controller/stream"
	"iptables-tool/internal/db"
	"iptables-tool/internal/model"
)

func setupM7(t *testing.T) (caDir, grpcAddr, webURL string, sharedStream *stream.Service) {
	t.Helper()
	caDir = findCA(t)

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
	// Start the Coordinator's background loops (result subscriber, recovery,
	// confirm-wait timers) — normally this happens inside Run().
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	srv.StartCoordinatorForTest(ctx)

	grpcLn, _ := net.Listen("tcp", "127.0.0.1:0")
	grpcAddr = grpcLn.Addr().String()
	go func() { _ = srv.GRPCServerForTest().Serve(grpcLn) }()
	t.Cleanup(srv.GRPCServerForTest().Stop)

	sharedStream = srv.StreamForTest()
	webSrv := httptest.NewServer(ctrlserver.BuildWebHandlerWithStream(gdb, cfg.Bootstrap.TokenTTL, sharedStream))
	t.Cleanup(webSrv.Close)
	webURL = webSrv.URL

	return caDir, grpcAddr, webURL, sharedStream
}

func TestApprovalAndConfirmFlow(t *testing.T) {
	caDir, grpcAddr, webURL, sharedStream := setupM7(t)

	// --- Boot agent (bootAgent already approves the node) ---
	nodeID, fake, cancelLoop := bootAgent(t, caDir, grpcAddr, webURL)
	t.Cleanup(cancelLoop)

	if !waitForConnected(sharedStream, nodeID, 3*time.Second) {
		t.Fatal("agent did not connect")
	}

	// --- Create policy targeting this node ---
	polJSON := map[string]any{
		"name": "allow-ssh", "direction": "INBOUND",
		"source": "10.0.0.0/24", "protocol": "TCP", "port_range": "22",
		"action": "ACCEPT", "priority": 10, "enabled": true,
		"targets": map[string]any{"node_ids": []string{nodeID}},
	}
	buf, _ := json.Marshal(polJSON)
	created := postJSON(t, webURL+"/api/v1/policies", string(buf))
	policyID := created["id"].(float64)

	// --- Apply with auto_approve=false (default) → PENDING_APPROVAL ---
	applyResp := postJSONAllowStatus(t, webURL+"/api/v1/policies/"+intStr(int(policyID))+"/apply", "{}", 300)
	tasks, _ := applyResp["tasks"].([]any)
	if len(tasks) != 1 {
		t.Fatalf("expected 1 task, got %d", len(tasks))
	}
	taskID, _ := tasks[0].(map[string]any)["id"].(string)
	if taskID == "" {
		t.Fatal("no task id")
	}

	// Verify task is PENDING_APPROVAL.
	task := getTask(t, webURL, taskID)
	if task["status"] != string(model.TaskPendingApproval) {
		t.Fatalf("expected pending_approval, got %v", task["status"])
	}

	// --- Approve the task (short confirm deadline for test speed) ---
	approveResp := postJSON(t, webURL+"/api/v1/tasks/"+taskID+"/approve",
		`{"confirm_deadline_seconds":300}`)
	if approveResp["status"] == string(model.TaskPendingApproval) {
		t.Fatal("approve did not advance the task")
	}

	// Wait for the agent to process and report back.
	waitForTaskStatus(t, webURL, taskID, string(model.TaskConfirmWait), 5*time.Second)

	// Verify the rules landed.
	waitForRules(t, fake, 3*time.Second, func(rules []string) bool {
		return len(rules) == 1 && strings.Contains(rules[0], "-s 10.0.0.0/24")
	}, "agent MYFW-INPUT should have the rule")

	// --- Confirm (admin verified the change is safe) ---
	confirmResp := postJSON(t, webURL+"/api/v1/tasks/"+taskID+"/confirm", "{}")
	if confirmResp["status"] != string(model.TaskConfirmed) {
		t.Fatalf("expected confirmed, got %v", confirmResp["status"])
	}

	// Agent should have received a ConfirmTask and cleared its snapshot.
	// (We can't easily assert snapshot state from here, but the state machine
	// moving to CONFIRMED is the key invariant.)
}

func TestAutoRollbackFlow(t *testing.T) {
	caDir, grpcAddr, webURL, sharedStream := setupM7(t)

	nodeID, fake, cancelLoop := bootAgent(t, caDir, grpcAddr, webURL)
	t.Cleanup(cancelLoop)
	if !waitForConnected(sharedStream, nodeID, 3*time.Second) {
		t.Fatal("agent did not connect")
	}

	// Create policy + apply.
	polJSON := map[string]any{
		"name": "allow-http", "direction": "INBOUND",
		"source": "10.0.0.0/24", "protocol": "TCP", "port_range": "80",
		"action": "ACCEPT", "priority": 10, "enabled": true,
		"targets": map[string]any{"node_ids": []string{nodeID}},
	}
	buf, _ := json.Marshal(polJSON)
	created := postJSON(t, webURL+"/api/v1/policies", string(buf))
	policyID := created["id"].(float64)

	applyResp := postJSONAllowStatus(t, webURL+"/api/v1/policies/"+intStr(int(policyID))+"/apply", "{}", 300)
	taskID, _ := applyResp["tasks"].([]any)[0].(map[string]any)["id"].(string)

	// Approve with a VERY short confirm deadline (2s).
	postJSON(t, webURL+"/api/v1/tasks/"+taskID+"/approve",
		`{"confirm_deadline_seconds":2}`)

	// Wait for CONFIRM_WAIT (apply succeeded).
	waitForTaskStatus(t, webURL, taskID, string(model.TaskConfirmWait), 5*time.Second)

	// Verify rule landed.
	waitForRules(t, fake, 3*time.Second, func(rules []string) bool {
		return len(rules) == 1 && strings.Contains(rules[0], "-s 10.0.0.0/24")
	}, "agent should have the rule before rollback")

	// --- Wait for the 2s deadline to expire → auto-rollback ---
	waitForTaskStatus(t, webURL, taskID, string(model.TaskRolledBack), 5*time.Second)

	// After rollback, the agent's OnRollback handler restores the snapshot,
	// which means the pre-apply state (empty MYFW) should be back.
	// Give it a moment to process the RollbackTask.
	waitForRules(t, fake, 3*time.Second, func(rules []string) bool {
		return len(rules) == 0
	}, "MYFW-INPUT should be empty after auto-rollback")
}

func TestRejectFlow(t *testing.T) {
	caDir, grpcAddr, webURL, sharedStream := setupM7(t)

	nodeID, _, cancelLoop := bootAgent(t, caDir, grpcAddr, webURL)
	t.Cleanup(cancelLoop)
	if !waitForConnected(sharedStream, nodeID, 3*time.Second) {
		t.Fatal("agent did not connect")
	}

	polJSON := map[string]any{
		"name": "bad-rule", "direction": "INBOUND",
		"action": "DROP", "priority": 999, "enabled": true,
		"targets": map[string]any{"node_ids": []string{nodeID}},
	}
	buf, _ := json.Marshal(polJSON)
	created := postJSON(t, webURL+"/api/v1/policies", string(buf))
	policyID := created["id"].(float64)

	applyResp := postJSONAllowStatus(t, webURL+"/api/v1/policies/"+intStr(int(policyID))+"/apply", "{}", 300)
	taskID, _ := applyResp["tasks"].([]any)[0].(map[string]any)["id"].(string)

	// Reject the task.
	rejectResp := postJSON(t, webURL+"/api/v1/tasks/"+taskID+"/reject",
		`{"reason":"this would break production"}`)
	if rejectResp["status"] != string(model.TaskFailed) {
		t.Fatalf("expected failed, got %v", rejectResp["status"])
	}
	if msg, _ := rejectResp["message"].(string); !strings.Contains(msg, "this would break production") {
		t.Fatalf("expected rejection reason in message, got %v", msg)
	}
}

// --- helpers ---------------------------------------------------------------

func getTask(t *testing.T, webURL, taskID string) map[string]any {
	t.Helper()
	resp, err := http.Get(webURL + "/api/v1/tasks/" + taskID)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		t.Fatalf("GET task %s: HTTP %d: %s", taskID, resp.StatusCode, string(raw))
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func waitForTaskStatus(t *testing.T, webURL, taskID, want string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		m := getTask(t, webURL, taskID)
		if m["status"] == want {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("task %s never reached status %q (last: %v)", taskID, want, getTask(t, webURL, taskID)["status"])
}

func postJSONAllowStatus(t *testing.T, url, body string, upper int) map[string]any {
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
