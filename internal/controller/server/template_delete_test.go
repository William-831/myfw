package server

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"iptables-tool/internal/db"
	"iptables-tool/internal/model"
)

// TestDeleteInstanceNotApplied 验证删除节点上无规则的实例(applied=false)直接删 DB,返回 204。
func TestDeleteInstanceNotApplied(t *testing.T) {
	gdb, err := db.Open(db.Config{
		Driver: db.DriverSQLite, DSN: "file::memory:",
		MaxOpenConns: 1, MaxIdleConns: 1, LogLevel: gormlogger.Silent,
	})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.Migrate(gdb); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	gdb.Create(&model.NodePolicyInstance{ID: 1, NodeID: "n1", Name: "no-rule", Enabled: true, Applied: false})
	h := BuildWebHandler(gdb, time.Minute)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/instances/1", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("status: got %d, want 204, body=%s", w.Code, w.Body.String())
	}
	var inst model.NodePolicyInstance
	if err := gdb.First(&inst, 1).Error; !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("实例应已删除, err=%v", err)
	}
}

// TestDeleteInstanceAppliedNodeOffline 验证删除节点上有规则的实例(applied=true)但节点未连接时,
// 返回 409 且不修改实例状态(不产生孤儿标记)。
func TestDeleteInstanceAppliedNodeOffline(t *testing.T) {
	gdb, err := db.Open(db.Config{
		Driver: db.DriverSQLite, DSN: "file::memory:",
		MaxOpenConns: 1, MaxIdleConns: 1, LogLevel: gormlogger.Silent,
	})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.Migrate(gdb); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	gdb.Create(&model.NodePolicyInstance{ID: 2, NodeID: "n1", Name: "has-rule", Enabled: true, Applied: true})
	h := BuildWebHandler(gdb, time.Minute)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/instances/2", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusConflict {
		t.Fatalf("status: got %d, want 409, body=%s", w.Code, w.Body.String())
	}
	var inst model.NodePolicyInstance
	if err := gdb.First(&inst, 2).Error; err != nil {
		t.Fatalf("实例应保留: %v", err)
	}
	if inst.PendingDelete || !inst.Enabled || !inst.Applied {
		t.Fatalf("实例状态被误改: enabled=%v applied=%v pending_delete=%v",
			inst.Enabled, inst.Applied, inst.PendingDelete)
	}
}

// TestDeleteInstanceNotFound 验证删除不存在的实例返回 404。
func TestDeleteInstanceNotFound(t *testing.T) {
	gdb, err := db.Open(db.Config{
		Driver: db.DriverSQLite, DSN: "file::memory:",
		MaxOpenConns: 1, MaxIdleConns: 1, LogLevel: gormlogger.Silent,
	})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.Migrate(gdb); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	h := BuildWebHandler(gdb, time.Minute)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/instances/999", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("status: got %d, want 404, body=%s", w.Code, w.Body.String())
	}
}
