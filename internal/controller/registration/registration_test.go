package registration

import (
	"context"
	"testing"
	"time"

	gormlogger "gorm.io/gorm/logger"

	myfwv1 "iptables-tool/api/myfw/v1"
	"iptables-tool/internal/db"
	"iptables-tool/internal/model"
)

// TestRegisterWritesNodeNameFromTokenNote 验证注册时把添加节点填写的名称
// （存于 BootstrapToken.Note）落到 Node.Name，供列表以"节点名称"展示。
func TestRegisterWritesNodeNameFromTokenNote(t *testing.T) {
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

	// 预置 bootstrap token，note 为用户填写的节点名称
	tok := model.BootstrapToken{
		Token:     "tok_test_name",
		Note:      "生产服务器-01",
		ExpiresAt: time.Now().Add(15 * time.Minute),
	}
	if err := gdb.Create(&tok).Error; err != nil {
		t.Fatalf("create token: %v", err)
	}

	// CA=nil 走禁用 mTLS 分支，无需构造证书链
	svc := New(gdb, nil, time.Hour, nil)

	resp, err := svc.Register(context.Background(), &myfwv1.RegisterRequest{
		CandidateId:    "n_name_test",
		CsrPem:         []byte("fake-csr"),
		BootstrapToken: "tok_test_name",
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if resp.NodeId == "" {
		t.Fatal("NodeId 应非空")
	}

	// 断言：Node.Name 来自 token.Note
	var node model.Node
	if err := gdb.Where("id = ?", resp.NodeId).First(&node).Error; err != nil {
		t.Fatalf("查询节点: %v", err)
	}
	if node.Name != tok.Note {
		t.Fatalf("Node.Name: got %q, want %q", node.Name, tok.Note)
	}
}
