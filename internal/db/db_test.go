package db

import (
	"testing"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"iptables-tool/internal/model"
)

// openTestSQLite opens an isolated in-memory SQLite DB for a test.
func openTestSQLite(t *testing.T) *gorm.DB {
	t.Helper()
	cfg := Config{
		Driver:       DriverSQLite,
		DSN:          "file::memory:?cache=shared",
		MaxOpenConns: 1, // shared in-memory needs a single conn to persist
		MaxIdleConns: 1,
		LogLevel:     logger.Silent,
	}
	gdb, err := Open(cfg)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := Migrate(gdb); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return gdb
}

func TestConfigFromEnv(t *testing.T) {
	t.Setenv(envDriver, "")
	t.Setenv(envDSN, "")
	// default -> sqlite ./dev.db
	c, err := ConfigFromEnv()
	if err != nil {
		t.Fatalf("default config: %v", err)
	}
	if c.Driver != DriverSQLite || c.DSN != defaultDSNs {
		t.Fatalf("want sqlite/%s, got %s/%s", defaultDSNs, c.Driver, c.DSN)
	}

	// mysql without DSN -> error (no silent downgrade)
	t.Setenv(envDriver, "mysql")
	t.Setenv(envDSN, "")
	if _, err := ConfigFromEnv(); err == nil {
		t.Fatal("expected error for mysql driver with empty DSN")
	}

	// unknown driver -> error
	t.Setenv(envDriver, "postgres")
	if _, err := ConfigFromEnv(); err == nil {
		t.Fatal("expected error for unsupported driver")
	}
}

func TestMigrateAndCRUD(t *testing.T) {
	gdb := openTestSQLite(t)

	// Create a node.
	now := time.Now()
	node := &model.Node{
		ID:        "n_test001",
		Status:    model.NodeStatusPending,
		Hostname:  "vm-1",
		MachineID: "mid-abc",
		Arch:      "amd64",
		LastSeen:  &now,
	}
	if err := gdb.Create(node).Error; err != nil {
		t.Fatalf("create node: %v", err)
	}

	// Read it back.
	var got model.Node
	if err := gdb.First(&got, "id = ?", "n_test001").Error; err != nil {
		t.Fatalf("read node: %v", err)
	}
	if got.Status != model.NodeStatusPending || got.Hostname != "vm-1" {
		t.Fatalf("unexpected node: %+v", got)
	}

	// Update status to ACTIVE.
	if err := gdb.Model(&got).Update("status", model.NodeStatusActive).Error; err != nil {
		t.Fatalf("update node: %v", err)
	}

	// Bind a certificate.
	cert := &model.Certificate{
		NodeID:      node.ID,
		Fingerprint: "sha256:deadbeef",
		SerialHex:   "01",
		NotBefore:   now,
		NotAfter:    now.Add(24 * time.Hour),
	}
	if err := gdb.Create(cert).Error; err != nil {
		t.Fatalf("create cert: %v", err)
	}

	// Unique fingerprint constraint should reject duplicates.
	dup := &model.Certificate{NodeID: node.ID, Fingerprint: "sha256:deadbeef"}
	if err := gdb.Create(dup).Error; err == nil {
		t.Fatal("expected unique constraint violation on fingerprint")
	}

	// Count all tables migrated by inserting one audit row.
	if err := gdb.Create(&model.AuditLog{Actor: "admin", Action: "node.approve", NodeID: node.ID}).Error; err != nil {
		t.Fatalf("create audit: %v", err)
	}
	var auditCount int64
	gdb.Model(&model.AuditLog{}).Count(&auditCount)
	if auditCount != 1 {
		t.Fatalf("want 1 audit row, got %d", auditCount)
	}
}
