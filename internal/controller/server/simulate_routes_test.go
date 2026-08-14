package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"iptables-tool/internal/db"
	"iptables-tool/internal/model"
)

// bytesReader 便捷构造 POST body。
func bytesReader(b []byte) *bytes.Reader { return bytes.NewReader(b) }

// seedSimNode 构造 INPUT 链 + 一条 allow-http ACCEPT 实例的节点。
func seedSimNode(t *testing.T, gdb *gorm.DB, nodeID string) {
	t.Helper()
	if err := gdb.Create(&model.Node{ID: nodeID, Status: model.NodeStatusActive}).Error; err != nil {
		t.Fatalf("create node: %v", err)
	}
	chain := model.CustomChain{Name: "sim-input", Parent: "MYFW-INPUT", Table: "filter", Priority: 50, Enabled: true}
	if err := gdb.Create(&chain).Error; err != nil {
		t.Fatalf("create chain: %v", err)
	}
	if err := gdb.Create(&model.NodePolicyInstance{
		NodeID: nodeID, Name: "allow-http", GroupID: chain.ID,
		Protocol: "TCP", PortRange: "8080", Action: "ACCEPT", Priority: 10, Enabled: true,
	}).Error; err != nil {
		t.Fatalf("create instance: %v", err)
	}
}

// TestSimulateAPI_NodeMatch: 真实节点编译期望态 + 匹配流量 -> ACCEPT。
func TestSimulateAPI_NodeMatch(t *testing.T) {
	gdb := openSimTestDB(t)
	seedSimNode(t, gdb, "n1")

	h := BuildWebHandler(gdb, time.Minute)
	body, _ := json.Marshal(map[string]any{
		"node_id": "n1",
		"flow": map[string]any{
			"direction": "INPUT", "source_ip": "1.2.3.4", "dest_ip": "10.0.0.1",
			"protocol": "tcp", "src_port": 12345, "dst_port": 8080,
		},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/simulate", bytesReader(body))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200, body=%s", w.Code, w.Body.String())
	}
	var res struct {
		Verdict string `json:"verdict"`
		Steps   []struct {
			RuleID   string `json:"rule_id"`
			Action   string `json:"action"`
			Matched  bool   `json:"matched"`
		} `json:"steps"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if res.Verdict != "ACCEPT" {
		t.Fatalf("verdict: got %q, want ACCEPT, body=%s", res.Verdict, w.Body.String())
	}
	matched := false
	for _, s := range res.Steps {
		// 动作名已简化为 ACCEPT(去 ACTION_ 枚举前缀),供结论/前端使用
		if s.Matched && s.Action == "ACCEPT" {
			matched = true
		}
	}
	if !matched {
		t.Fatalf("期望存在命中的 ACCEPT 步骤, got %+v", res.Steps)
	}
}

// TestSimulateAPI_NoMatch: 不匹配端口 -> PASS。
func TestSimulateAPI_NoMatch(t *testing.T) {
	gdb := openSimTestDB(t)
	seedSimNode(t, gdb, "n1")

	h := BuildWebHandler(gdb, time.Minute)
	body, _ := json.Marshal(map[string]any{
		"node_id": "n1",
		"flow": map[string]any{
			"direction": "INPUT", "source_ip": "1.2.3.4", "dest_ip": "10.0.0.1",
			"protocol": "tcp", "src_port": 12345, "dst_port": 22,
		},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/simulate", bytesReader(body))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200", w.Code)
	}
	var res struct {
		Verdict string `json:"verdict"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if res.Verdict != "PASS" {
		t.Fatalf("verdict: got %q, want PASS", res.Verdict)
	}
}

// TestSimulateAPI_InvalidDirection: 不支持的方向 -> 400。
func TestSimulateAPI_InvalidDirection(t *testing.T) {
	gdb := openSimTestDB(t)
	seedSimNode(t, gdb, "n1")
	h := BuildWebHandler(gdb, time.Minute)

	body, _ := json.Marshal(map[string]any{
		"node_id": "n1",
		"flow":    map[string]any{"direction": "PREROUTING"},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/simulate", bytesReader(body))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400, body=%s", w.Code, w.Body.String())
	}
}

// TestSimulateAPI_UnknownNode: 节点不存在 -> 404。
func TestSimulateAPI_UnknownNode(t *testing.T) {
	gdb := openSimTestDB(t)
	h := BuildWebHandler(gdb, time.Minute)

	body, _ := json.Marshal(map[string]any{
		"node_id": "n-not-exist",
		"flow":    map[string]any{"direction": "INPUT"},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/simulate", bytesReader(body))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("status: got %d, want 404, body=%s", w.Code, w.Body.String())
	}
}

// TestSimulateAPI_MissingInput: 无 node_id -> 400(节点级入口,node_id 必填)。
func TestSimulateAPI_MissingInput(t *testing.T) {
	gdb := openSimTestDB(t)
	h := BuildWebHandler(gdb, time.Minute)

	body, _ := json.Marshal(map[string]any{
		"flow": map[string]any{"direction": "INPUT"},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/simulate", bytesReader(body))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400, body=%s", w.Code, w.Body.String())
	}
}

// openSimTestDB 打开内存 SQLite 并迁移。
func openSimTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	gdb, err := db.Open(db.Config{
		Driver:       db.DriverSQLite,
		DSN:          "file::memory:",
		MaxOpenConns: 1,
		MaxIdleConns: 1,
		LogLevel:     gormlogger.Silent,
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.Migrate(gdb); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return gdb
}
