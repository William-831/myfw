package server

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	gormlogger "gorm.io/gorm/logger"

	"iptables-tool/internal/controller/stream"
	"iptables-tool/internal/db"
	"iptables-tool/internal/model"
)

// TestDeleteNodeRevokesCertificate 验证删除节点：Node 物理删除、Certificate 标记
// revoked（保留指纹防 autoReregister 复活 + 拒绝重连）、关联数据清理。
func TestDeleteNodeRevokesCertificate(t *testing.T) {
	gdb, err := db.Open(db.Config{
		Driver:       db.DriverSQLite,
		DSN:          "file::memory:?cache=shared",
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

	// 插入 node（ACTIVE）+ 关联 capability + certificate
	gdb.Create(&model.Node{ID: "n_del", Status: model.NodeStatusActive})
	gdb.Create(&model.NodeCapability{NodeID: "n_del", SelectedBackend: "FIREWALL_BACKEND_IPTABLES_NFT"})
	gdb.Create(&model.Certificate{NodeID: "n_del", Fingerprint: "fp_del", Revoked: false})

	streamSvc := stream.New(gdb, slog.Default(), nil)
	h := BuildWebHandlerWithStream(gdb, time.Minute, streamSvc)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/nodes/n_del", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("状态码: got %d, want 204, body=%s", w.Code, w.Body.String())
	}

	// Node 已物理删除
	var n model.Node
	if err := gdb.Where("id = ?", "n_del").First(&n).Error; err == nil {
		t.Fatal("node 应已删除")
	}
	// NodeCapability 已清理
	var cap model.NodeCapability
	if err := gdb.Where("node_id = ?", "n_del").First(&cap).Error; err == nil {
		t.Fatal("NodeCapability 应已清理")
	}
	// Certificate 保留但标记 revoked
	var cert model.Certificate
	if err := gdb.Where("node_id = ?", "n_del").First(&cert).Error; err != nil {
		t.Fatal("Certificate 应保留（用于拒绝重连 + 审计）")
	}
	if !cert.Revoked {
		t.Fatal("Certificate 应标记 revoked")
	}
}
