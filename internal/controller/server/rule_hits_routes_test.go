package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"iptables-tool/internal/model"
)

// TestRuleHitsReportAggregate 验证 POST /api/v1/iptables/hits/:node_id:
// 同实例多条规则上报时 packets/bytes 取 max 聚合,按 (node,instance) upsert。
func TestRuleHitsReportAggregate(t *testing.T) {
	gdb := newRevisionTestDB(t)
	h := BuildWebHandler(gdb, time.Minute)

	// 同实例两条规则(主规则 packets=10, acl 规则 packets=5)-> 聚合 max=10
	body := `{"hits":[{"instance_id":1,"packets":10,"bytes":100},{"instance_id":1,"packets":5,"bytes":50}]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/iptables/hits/n1", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("report: got %d, body=%s", w.Code, w.Body.String())
	}

	var stat model.RuleHitStat
	if err := gdb.Where("node_id = ? AND instance_id = ?", "n1", 1).First(&stat).Error; err != nil {
		t.Fatalf("RuleHitStat 未写入: %v", err)
	}
	if stat.Packets != 10 || stat.Bytes != 100 {
		t.Fatalf("聚合 max 后 want packets=10 bytes=100, got packets=%d bytes=%d", stat.Packets, stat.Bytes)
	}

	// 二次上报(不同值)-> upsert 更新而非新增
	body2 := `{"hits":[{"instance_id":1,"packets":20,"bytes":200}]}`
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/iptables/hits/n1", strings.NewReader(body2))
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	h.ServeHTTP(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("report 2: got %d, body=%s", w2.Code, w2.Body.String())
	}
	var count int64
	gdb.Model(&model.RuleHitStat{}).Where("node_id = ? AND instance_id = ?", "n1", 1).Count(&count)
	if count != 1 {
		t.Fatalf("want 1 row (upsert), got %d", count)
	}
	gdb.Where("node_id = ? AND instance_id = ?", "n1", 1).First(&stat)
	if stat.Packets != 20 {
		t.Fatalf("upsert 后 want packets=20, got %d", stat.Packets)
	}
}

// TestRuleHitsQueryDeadJudgment 验证 GET /api/v1/iptables/rule-hits/:node_id 死规则判定:
// dead = enabled=true + 有 RuleHitStat + packets=0 + created_at 超阈值(默认 7 天)。
func TestRuleHitsQueryDeadJudgment(t *testing.T) {
	gdb := newRevisionTestDB(t)
	chain := model.CustomChain{Name: "acl-in", Parent: "MYFW-INPUT", Table: "filter", Priority: 50, Enabled: true}
	gdb.Create(&chain)

	// 实例 1:启用 + packets=0 + 8 天前创建 -> dead=true
	instDead := model.NodePolicyInstance{
		NodeID: "n1", Name: "dead-rule", GroupID: chain.ID,
		Protocol: "TCP", PortRange: "22", Action: "ACCEPT", Priority: 10, Enabled: true,
	}
	gdb.Create(&instDead)
	gdb.Model(&model.NodePolicyInstance{}).Where("id = ?", instDead.ID).
		Update("created_at", time.Now().Add(-8*24*time.Hour))
	gdb.Create(&model.RuleHitStat{NodeID: "n1", InstanceID: instDead.ID, Packets: 0, Bytes: 0, LastSeen: time.Now()})

	// 实例 2:启用 + packets>0 -> dead=false
	instAlive := model.NodePolicyInstance{
		NodeID: "n1", Name: "alive-rule", GroupID: chain.ID,
		Protocol: "TCP", PortRange: "80", Action: "ACCEPT", Priority: 20, Enabled: true,
	}
	gdb.Create(&instAlive)
	gdb.Model(&model.NodePolicyInstance{}).Where("id = ?", instAlive.ID).
		Update("created_at", time.Now().Add(-8*24*time.Hour))
	gdb.Create(&model.RuleHitStat{NodeID: "n1", InstanceID: instAlive.ID, Packets: 100, Bytes: 8000, LastSeen: time.Now()})

	// 实例 3:禁用 -> dead=false(不判定)
	instDisabled := model.NodePolicyInstance{
		NodeID: "n1", Name: "disabled-rule", GroupID: chain.ID,
		Protocol: "TCP", PortRange: "443", Action: "DROP", Priority: 30, Enabled: false,
	}
	gdb.Create(&instDisabled)
	gdb.Model(&model.NodePolicyInstance{}).Where("id = ?", instDisabled.ID).
		Update("created_at", time.Now().Add(-8*24*time.Hour))
	gdb.Create(&model.RuleHitStat{NodeID: "n1", InstanceID: instDisabled.ID, Packets: 0, Bytes: 0, LastSeen: time.Now()})

	// 实例 4:启用 + packets=0 + 1 天前创建(未超阈值)-> dead=false
	instNew := model.NodePolicyInstance{
		NodeID: "n1", Name: "new-rule", GroupID: chain.ID,
		Protocol: "TCP", PortRange: "8080", Action: "ACCEPT", Priority: 40, Enabled: true,
	}
	gdb.Create(&instNew)
	gdb.Model(&model.NodePolicyInstance{}).Where("id = ?", instNew.ID).
		Update("created_at", time.Now().Add(-1*24*time.Hour))
	gdb.Create(&model.RuleHitStat{NodeID: "n1", InstanceID: instNew.ID, Packets: 0, Bytes: 0, LastSeen: time.Now()})

	h := BuildWebHandler(gdb, time.Minute)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/iptables/rule-hits/n1", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("query: got %d, body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		Hits []struct {
			InstanceID uint   `json:"instance_id"`
			Name       string `json:"name"`
			Enabled    bool   `json:"enabled"`
			Packets    int64  `json:"packets"`
			Dead       bool   `json:"dead"`
		} `json:"hits"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v, body=%s", err, w.Body.String())
	}
	if len(resp.Hits) != 4 {
		t.Fatalf("want 4 hits, got %d: %+v", len(resp.Hits), resp.Hits)
	}
	deadByName := map[string]bool{}
	for _, hi := range resp.Hits {
		deadByName[hi.Name] = hi.Dead
	}
	if !deadByName["dead-rule"] {
		t.Errorf("dead-rule 应为 dead=true, got %+v", resp.Hits)
	}
	if deadByName["alive-rule"] {
		t.Errorf("alive-rule 应为 dead=false, got %+v", resp.Hits)
	}
	if deadByName["disabled-rule"] {
		t.Errorf("disabled-rule 应为 dead=false, got %+v", resp.Hits)
	}
	if deadByName["new-rule"] {
		t.Errorf("new-rule(未超阈值)应为 dead=false, got %+v", resp.Hits)
	}
}
