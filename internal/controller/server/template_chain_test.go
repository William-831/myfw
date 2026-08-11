package server

import (
	"net/http"
	"strconv"
	"strings"
	"testing"

	"iptables-tool/internal/model"
)

// TestCreateTemplateRejectsDNATOnFilterChain 验证 P3 API 层表一致性:
// DNAT 模板落 filter 表链被 400 拒绝(而非下发执行期才报 iptables 错)。
func TestCreateTemplateRejectsDNATOnFilterChain(t *testing.T) {
	gdb, h := newTestGDB(t)
	var ch model.CustomChain
	if err := gdb.Create(&model.CustomChain{
		Name: "natwrong", Parent: "MYFW-FORWARD", Table: "filter", Priority: 1, Enabled: true,
	}).Error; err != nil {
		t.Fatal(err)
	}
	gdb.Where("name = ?", "natwrong").First(&ch)

	body := `{"name":"t-nat","group_id":` + strconv.FormatUint(uint64(ch.ID), 10) + `,"action":"DNAT","nat_to":"1.2.3.4:8080"}`
	w := postJSON(t, h, http.MethodPost, "/api/v1/templates", body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400, body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "nat") {
		t.Fatalf("错误信息应含 nat 表提示, got %s", w.Body.String())
	}
}

// TestCreateInstanceRejectsDNATOnFilterChain 验证实例创建 API 层表一致性:
// DNAT 实例落 filter 组链被 400 拒绝(与模板同源校验)。
func TestCreateInstanceRejectsDNATOnFilterChain(t *testing.T) {
	gdb, h := newTestGDB(t)
	gdb.Create(&model.Node{ID: "n1", Status: model.NodeStatusActive})
	var ch model.CustomChain
	if err := gdb.Create(&model.CustomChain{
		Name: "natwrong", Parent: "MYFW-FORWARD", Table: "filter", Priority: 1, Enabled: true,
	}).Error; err != nil {
		t.Fatal(err)
	}
	gdb.Where("name = ?", "natwrong").First(&ch)

	body := `{"name":"i-nat","group_id":` + strconv.FormatUint(uint64(ch.ID), 10) + `,"action":"DNAT","nat_to":"1.2.3.4:8080"}`
	w := postJSON(t, h, http.MethodPost, "/api/v1/nodes/n1/instances", body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400, body=%s", w.Code, w.Body.String())
	}
}

// TestInstanceListChainUnavailable 验证 P2 生命周期显式化:
// 实例落点链被禁用时, 实例列表返回 chain_unavailable=true(不再静默失效)。
func TestInstanceListChainUnavailable(t *testing.T) {
	gdb, h := newTestGDB(t)
	gdb.Create(&model.Node{ID: "n1", Status: model.NodeStatusActive})
	var ch model.CustomChain
	if err := gdb.Create(&model.CustomChain{
		Name: "biz", Parent: "MYFW-FORWARD", Table: "filter", Priority: 1, Enabled: false, // 禁用
	}).Error; err != nil {
		t.Fatal(err)
	}
	gdb.Where("name = ?", "biz").First(&ch)
	gdb.Create(&model.NodePolicyInstance{
		Name: "r1", NodeID: "n1", GroupID: ch.ID, Action: "ACCEPT", Enabled: true,
	})

	w := postJSON(t, h, http.MethodGet, "/api/v1/nodes/n1/instances", "")
	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200, body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"chain_unavailable":true`) {
		t.Fatalf("实例应标记 chain_unavailable=true, body=%s", w.Body.String())
	}
}
