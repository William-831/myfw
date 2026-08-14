package server

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// TestRequestLogger_LogsRequest:requestLogger 记录 method/path/status。
func TestRequestLogger_LogsRequest(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))

	r := gin.New()
	r.Use(requestLogger(logger))
	r.GET("/api/v1/health", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	out := buf.String()
	for _, want := range []string{"method=GET", "path=/api/v1/health", "status=200"} {
		if !strings.Contains(out, want) {
			t.Fatalf("日志应包含 %q,实际: %s", want, out)
		}
	}
}

// TestRequestLogger_RecordsStatus:非 2xx 状态同样记录。
func TestRequestLogger_RecordsStatus(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))

	r := gin.New()
	r.Use(requestLogger(logger))
	r.GET("/api/v1/missing", func(c *gin.Context) { c.Status(http.StatusNotFound) })

	req := httptest.NewRequest(http.MethodGet, "/api/v1/missing", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if !strings.Contains(buf.String(), "status=404") {
		t.Fatalf("日志应包含 status=404,实际: %s", buf.String())
	}
}

// TestRequestLogger_NoPanicWithoutUser:无用户信息(未登录)不 panic。
func TestRequestLogger_NoPanicWithoutUser(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))

	r := gin.New()
	r.Use(requestLogger(logger))
	r.GET("/api/v1/anonymous", func(c *gin.Context) { c.Status(http.StatusOK) })

	req := httptest.NewRequest(http.MethodGet, "/api/v1/anonymous", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("未登录请求不应被中间件拦截,实际 %d", w.Code)
	}
}
