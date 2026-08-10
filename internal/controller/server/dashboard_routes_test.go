package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
