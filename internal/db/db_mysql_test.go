package db

import (
	"os"
	"testing"
	"time"

	"gorm.io/gorm/logger"

	"iptables-tool/internal/model"
)

// TestMigrateAndCRUD_MySQL runs the same migration + CRUD path against a real
// MySQL-protocol database (e.g. OceanBase). It is skipped unless
// MYFW_TEST_MYSQL_DSN is set, so CI/dev without a DB stays green while the
// prod backend can be verified on demand:
//
//	MYFW_TEST_MYSQL_DSN='user:pass@tcp(ob:2881)/myfw_test?charset=utf8mb4&parseTime=true&loc=Local' go test ./internal/db/...
func TestMigrateAndCRUD_MySQL(t *testing.T) {
	dsn := os.Getenv("MYFW_TEST_MYSQL_DSN")
	if dsn == "" {
		t.Skip("set MYFW_TEST_MYSQL_DSN to run the MySQL/OceanBase migration test")
	}

	gdb, err := Open(Config{
		Driver:       DriverMySQL,
		DSN:          dsn,
		MaxOpenConns: 5,
		MaxIdleConns: 2,
		LogLevel:     logger.Silent,
	})
	if err != nil {
		t.Fatalf("open mysql: %v", err)
	}
	if err := Migrate(gdb); err != nil {
		t.Fatalf("migrate mysql: %v", err)
	}

	now := time.Now()
	node := &model.Node{
		ID:        "n_mysql_test",
		Status:    model.NodeStatusActive,
		Hostname:  "ob-vm",
		MachineID: "mid-ob",
		Arch:      "amd64",
		LastSeen:  &now,
	}
	// Clean up any leftover from a previous run, then round-trip.
	gdb.Where("id = ?", node.ID).Delete(&model.Node{})
	if err := gdb.Create(node).Error; err != nil {
		t.Fatalf("create node: %v", err)
	}
	var got model.Node
	if err := gdb.First(&got, "id = ?", node.ID).Error; err != nil {
		t.Fatalf("read node: %v", err)
	}
	if got.Hostname != "ob-vm" {
		t.Fatalf("unexpected node: %+v", got)
	}
	gdb.Where("id = ?", node.ID).Delete(&model.Node{})
}
