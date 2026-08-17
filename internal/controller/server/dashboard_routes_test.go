package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	gormlogger "gorm.io/gorm/logger"

	"iptables-tool/internal/db"
	"iptables-tool/internal/model"
)

// TestDashboardConfigDrift 验证配置漂移仪表盘接口:统计各节点"模板已更新但实例未跟"
// 的实例数(配置侧语义漂移),与运行时规则漂移(node.drift 审计)区分(配置侧漂移治理 1.4)。
func TestDashboardConfigDrift(t *testing.T) {
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
	// 模板 SpecVersion=2;实例 SyncedSpecVersion<2 即为配置漂移
	gdb.Create(&model.PolicyTemplate{ID: 1, Name: "tpl", Action: "ACCEPT", SpecVersion: 2})
	// n1: 2 drift + 1 已同步
	gdb.Create(&model.NodePolicyInstance{ID: 1, NodeID: "n1", TemplateID: 1, Name: "a", Action: "ACCEPT", SyncedSpecVersion: 1})
	gdb.Create(&model.NodePolicyInstance{ID: 2, NodeID: "n1", TemplateID: 1, Name: "b", Action: "ACCEPT", SyncedSpecVersion: 1})
	gdb.Create(&model.NodePolicyInstance{ID: 3, NodeID: "n1", TemplateID: 1, Name: "c", Action: "ACCEPT", SyncedSpecVersion: 2})
	// n2: 1 drift
	gdb.Create(&model.NodePolicyInstance{ID: 4, NodeID: "n2", TemplateID: 1, Name: "d", Action: "ACCEPT", SyncedSpecVersion: 1})
	h := BuildWebHandler(gdb, time.Minute)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/dashboard/config-drift", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200, body=%s", w.Code, w.Body.String())
	}
	var body struct {
		Total int `json:"total"`
		Nodes []struct {
			NodeID string `json:"node_id"`
			Count  int    `json:"count"`
		} `json:"nodes"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v, body=%s", err, w.Body.String())
	}
	if body.Total != 3 {
		t.Fatalf("total 应为 3, got %d", body.Total)
	}
	if len(body.Nodes) != 2 {
		t.Fatalf("应有 2 个节点(n1/n2), got %v", body.Nodes)
	}
	byNode := map[string]int{}
	for _, n := range body.Nodes {
		byNode[n.NodeID] = n.Count
	}
	if byNode["n1"] != 2 || byNode["n2"] != 1 {
		t.Fatalf("节点 drift 计数应为 n1=2/n2=1, got %v", byNode)
	}
}

// TestConfigDriftRouteCaches 验证 config-drift 走 5s TTL 缓存:改 DB 消除 drift 后,
// TTL 内 GET 仍返回旧值(缓存命中,证明未重查 DB)。与 dashboard/stats 同缓存策略。
func TestConfigDriftRouteCaches(t *testing.T) {
	gdb := newRevisionTestDB(t)
	tpl := model.PolicyTemplate{Name: "t1", SpecVersion: 1, Enabled: true}
	if err := gdb.Create(&tpl).Error; err != nil {
		t.Fatal(err)
	}
	if err := gdb.Create(&model.NodePolicyInstance{NodeID: "n1", TemplateID: tpl.ID, Name: "i1", SyncedSpecVersion: 0}).Error; err != nil {
		t.Fatal(err)
	}
	h := BuildWebHandler(gdb, time.Minute)
	doGet := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/dashboard/config-drift", nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}
	w1 := doGet()
	if !strings.Contains(w1.Body.String(), `"total":1`) {
		t.Fatalf("首次应返回 total=1, got %s", w1.Body.String())
	}
	// 直接改 DB 同步实例消除 drift(绕过缓存失效点,验证 TTL 缓存命中)
	if err := gdb.Model(&model.NodePolicyInstance{}).Where("name = ?", "i1").Update("synced_spec_version", 1).Error; err != nil {
		t.Fatal(err)
	}
	// TTL 内命中缓存,仍返回旧值 total=1
	w2 := doGet()
	if !strings.Contains(w2.Body.String(), `"total":1`) {
		t.Fatalf("TTL 内缓存应命中返回 total=1, got %s", w2.Body.String())
	}
}
