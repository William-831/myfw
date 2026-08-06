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

// TestExportTemplatesAPI 验证 GET /api/v1/templates/export 返回 bundle JSON 且包含预置数据。
func TestExportTemplatesAPI(t *testing.T) {
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
	// 预置数据
	gdb.Create(&model.Mark{Name: "test-mark", Value: 99, Description: "test"})
	h := BuildWebHandler(gdb, time.Minute)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/templates/export", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200, body=%s", w.Code, w.Body.String())
	}

	var body struct {
		Bundle any `json:"bundle"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v, body=%s", err, w.Body.String())
	}
	// 验证 bundle 包含 test-mark
	if !strings.Contains(w.Body.String(), "test-mark") {
		t.Fatalf("bundle should contain test-mark, body=%s", w.Body.String())
	}
}

// TestImportTemplatesAPI 验证 POST /api/v1/templates/import 导入 bundle 成功。
func TestImportTemplatesAPI(t *testing.T) {
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
	h := BuildWebHandler(gdb, time.Minute)

	body := `{"policy":"skip","bundle":{"version":"1.0","marks":[{"name":"test-import","value":88,"description":"test import"}]}}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/templates/import", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200, body=%s", w.Code, w.Body.String())
	}

	var result struct {
		MarksCreated int `json:"marks_created"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("unmarshal: %v, body=%s", err, w.Body.String())
	}
	if result.MarksCreated != 1 {
		t.Fatalf("marks_created: got %d, want 1", result.MarksCreated)
	}
}