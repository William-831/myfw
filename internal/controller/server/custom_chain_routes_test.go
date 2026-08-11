package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"iptables-tool/internal/db"
	"iptables-tool/internal/model"
)

// newTestGDB 打开内存 sqlite + migrate,返回 DB 与完整 Web handler。
func newTestGDB(t *testing.T) (*gorm.DB, http.Handler) {
	t.Helper()
	gdb, err := db.Open(db.Config{
		Driver: db.DriverSQLite, DSN: "file::memory:",
		MaxOpenConns: 1, MaxIdleConns: 1, LogLevel: gormlogger.Silent,
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.Migrate(gdb); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return gdb, BuildWebHandler(gdb, time.Minute)
}

func postJSON(t *testing.T, h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

// TestCreateChainWithMultiMounts 验证链多挂载(P1b):POST mounts 列表被正确写入,
// 返回 mount_list 数组,且 Parent/Priority 同步为主挂载镜像(兼容字段)。
func TestCreateChainWithMultiMounts(t *testing.T) {
	gdb, h := newTestGDB(t)
	_ = gdb
	body := `{"name":"dmz","table":"filter","mounts":[{"parent":"MYFW-FORWARD","priority":10},{"parent":"MYFW-INPUT","priority":20}],"enabled":true}`
	w := postJSON(t, h, http.MethodPost, "/api/v1/custom-chains", body)
	if w.Code != http.StatusCreated {
		t.Fatalf("status: got %d, want 201, body=%s", w.Code, w.Body.String())
	}
	var view struct {
		MountList []model.ChainMount `json:"mount_list"`
		Parent    string             `json:"parent"`
		Priority  int                `json:"priority"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &view); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(view.MountList) != 2 {
		t.Fatalf("mount_list: got %d, want 2", len(view.MountList))
	}
	if view.MountList[0].Parent != "MYFW-FORWARD" || view.MountList[1].Parent != "MYFW-INPUT" {
		t.Fatalf("mount_list parents: got %+v", view.MountList)
	}
	// 兼容镜像:Parent/Priority = mounts[0](读取回退依赖此同步)
	if view.Parent != "MYFW-FORWARD" || view.Priority != 10 {
		t.Fatalf("兼容镜像 Parent/Priority: got %s/%d, want MYFW-FORWARD/10", view.Parent, view.Priority)
	}
}

// TestCreateChainFallbackSingleMount 验证兼容回退:旧前端只传 Parent/Priority 时,
// Mounts 留空,读取回退单挂载(存量零迁移)。
func TestCreateChainFallbackSingleMount(t *testing.T) {
	gdb, h := newTestGDB(t)
	_ = gdb
	body := `{"name":"legacy","parent":"MYFW-FORWARD","table":"filter","priority":30,"enabled":true}`
	w := postJSON(t, h, http.MethodPost, "/api/v1/custom-chains", body)
	if w.Code != http.StatusCreated {
		t.Fatalf("status: got %d, want 201, body=%s", w.Code, w.Body.String())
	}
	var view struct {
		MountList []model.ChainMount `json:"mount_list"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &view); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(view.MountList) != 1 || view.MountList[0].Parent != "MYFW-FORWARD" || view.MountList[0].Priority != 30 {
		t.Fatalf("回退单挂载: got %+v, want [MYFW-FORWARD/30]", view.MountList)
	}
}

// TestCreateChainRejectBadParent 验证挂载点 parent 非法被 400 拒绝(白名单校验)。
func TestCreateChainRejectBadParent(t *testing.T) {
	_, h := newTestGDB(t)
	body := `{"name":"bad","table":"filter","mounts":[{"parent":"MYFW-RAW","priority":1}]}`
	w := postJSON(t, h, http.MethodPost, "/api/v1/custom-chains", body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400, body=%s", w.Code, w.Body.String())
	}
}

// TestUpdateChainDisableAuditsAffectedInstances 验证 P2 生命周期显式化:
// 禁用链时写 chain.disabled 审计,detail 含受影响实例数(组链引用),不再静默失效。
func TestUpdateChainDisableAuditsAffectedInstances(t *testing.T) {
	gdb, h := newTestGDB(t)
	var ch model.CustomChain
	if err := gdb.Create(&model.CustomChain{
		Name: "biz", Parent: "MYFW-FORWARD", Table: "filter", Priority: 1, Enabled: true,
		Mounts: `[{"parent":"MYFW-FORWARD","priority":1}]`,
	}).Error; err != nil {
		t.Fatal(err)
	}
	gdb.Where("name = ?", "biz").First(&ch)
	// 组链引用实例 1 条
	gdb.Create(&model.NodePolicyInstance{
		Name: "r1", NodeID: "n1", GroupID: ch.ID, Action: "ACCEPT", Enabled: true,
	})

	body := `{"name":"biz","table":"filter","mounts":[{"parent":"MYFW-FORWARD","priority":1}],"enabled":false}`
	w := postJSON(t, h, http.MethodPut, "/api/v1/custom-chains/"+strconv.FormatUint(uint64(ch.ID), 10), body)
	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200, body=%s", w.Code, w.Body.String())
	}
	var logs []model.AuditLog
	gdb.Where("action = ?", "chain.disabled").Find(&logs)
	if len(logs) != 1 {
		t.Fatalf("chain.disabled 审计: got %d, want 1", len(logs))
	}
	if !strings.Contains(logs[0].Detail, `"affected_instances":1`) {
		t.Fatalf("审计 detail 应含 affected_instances=1, got %s", logs[0].Detail)
	}
}

// TestDeleteChainRejectedWhenReferenced 验证链被实例(落点链 ChainID)引用时删除被 409 拒绝。
func TestDeleteChainRejectedWhenReferenced(t *testing.T) {
	gdb, h := newTestGDB(t)
	var ch model.CustomChain
	if err := gdb.Create(&model.CustomChain{
		Name: "dmz", Parent: "MYFW-FORWARD", Table: "filter", Priority: 1, Enabled: true,
	}).Error; err != nil {
		t.Fatal(err)
	}
	gdb.Where("name = ?", "dmz").First(&ch)
	// 引用链:ChainID 指向该链(独立落点)
	gdb.Create(&model.NodePolicyInstance{
		Name: "r1", NodeID: "n1", GroupID: 0, ChainID: ch.ID, Action: "ACCEPT", Enabled: true,
	})

	w := postJSON(t, h, http.MethodDelete, "/api/v1/custom-chains/"+strconv.FormatUint(uint64(ch.ID), 10), "")
	if w.Code != http.StatusConflict {
		t.Fatalf("status: got %d, want 409, body=%s", w.Code, w.Body.String())
	}
}
