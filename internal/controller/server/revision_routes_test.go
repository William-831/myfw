package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"iptables-tool/internal/controller/compiler"
	"iptables-tool/internal/controller/revision"
	"iptables-tool/internal/db"
	"iptables-tool/internal/model"
)

// newRevisionTestDB 打开内存 SQLite 并完成迁移。
func newRevisionTestDB(t *testing.T) *gorm.DB {
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

// TestRevisionListAPI 验证 GET /api/v1/nodes/:id/revisions 返回历史版本(新->旧)。
func TestRevisionListAPI(t *testing.T) {
	gdb := newRevisionTestDB(t)
	gdb.Create(&model.NodeRuleRevision{NodeID: "n1", RevNo: 1, Source: "apply", Payload: "{}", Hash: "h1"})
	gdb.Create(&model.NodeRuleRevision{NodeID: "n1", RevNo: 2, Source: "apply", Payload: "{}", Hash: "h2"})

	h := BuildWebHandler(gdb, time.Minute)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/nodes/n1/revisions", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200, body=%s", w.Code, w.Body.String())
	}
	var body struct {
		Revisions []model.NodeRuleRevision `json:"revisions"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v, body=%s", err, w.Body.String())
	}
	if len(body.Revisions) != 2 || body.Revisions[0].RevNo != 2 || body.Revisions[1].RevNo != 1 {
		t.Fatalf("want newest-first [2 1], got %+v", body.Revisions)
	}
}

// TestRevisionRollbackAPI 验证 POST /api/v1/nodes/:id/revisions/:no/rollback:
// 回滚前归档当前版本(便于撤销) + 创建携带历史规则集的回滚任务。
func TestRevisionRollbackAPI(t *testing.T) {
	gdb := newRevisionTestDB(t)
	// 构造可编译节点:组链 + 实例
	chain := model.CustomChain{Name: "acl-fwd", Parent: "MYFW-FORWARD", Table: "filter", Priority: 50, Enabled: true}
	if err := gdb.Create(&chain).Error; err != nil {
		t.Fatalf("create chain: %v", err)
	}
	if err := gdb.Create(&model.NodePolicyInstance{
		NodeID: "n1", Name: "allow-ssh", GroupID: chain.ID,
		Protocol: "TCP", PortRange: "22", Action: "ACCEPT", Priority: 10, Enabled: true,
	}).Error; err != nil {
		t.Fatalf("create instance: %v", err)
	}
	// 用真实 Service 归档版本 rev1
	svc := revision.New(gdb, compiler.New(gdb), slog.Default())
	ctx := context.Background()
	if err := svc.ArchiveApply(ctx, "n1", "t1"); err != nil {
		t.Fatalf("archive rev1: %v", err)
	}

	h := BuildWebHandler(gdb, time.Minute)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/nodes/n1/revisions/1/rollback", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	// 测试环境节点离线:dispatch 必然失败,返回 502 属预期(在线才可真正回滚)。
	// 断言 DB 侧回滚链路结果:回滚前归档 + 回滚任务创建(携带历史规则集快照)。
	if w.Code != http.StatusBadGateway {
		t.Fatalf("离线节点回滚应返回 502, got %d, body=%s", w.Code, w.Body.String())
	}
	// 回滚前归档 + 历史 rev1:revisions 表至少有 2 条
	var revs []model.NodeRuleRevision
	if err := gdb.Where("node_id = ?", "n1").Find(&revs).Error; err != nil {
		t.Fatalf("查 revisions: %v", err)
	}
	if len(revs) < 2 {
		t.Fatalf("want >=2 revisions(历史+回滚前归档), got %d", len(revs))
	}
	// 回滚任务存在且携带历史规则集快照
	var tk model.Task
	if err := gdb.Where("node_id = ? AND rule_set_snapshot <> ''", "n1").First(&tk).Error; err != nil {
		t.Fatalf("回滚任务未创建: %v", err)
	}
	if tk.ChangeType != "rollback" {
		t.Fatalf("want change_type=rollback, got %q", tk.ChangeType)
	}
}
