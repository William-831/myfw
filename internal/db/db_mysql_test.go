package db

import (
	"os"
	"testing"
	"time"

	gomysql "github.com/go-sql-driver/mysql"
	"gorm.io/gorm/logger"

	"iptables-tool/internal/model"
)

// TestParseDSNExtractsDBName 验证 DSN 解析正确提取库名、构造无库名 DSN。
func TestParseDSNExtractsDBName(t *testing.T) {
	dsn := "user:pass@tcp(10.0.0.5:2881)/myfw?charset=utf8mb4&parseTime=true"
	cfg, err := gomysql.ParseDSN(dsn)
	if err != nil {
		t.Fatalf("parse dsn: %v", err)
	}
	if cfg.DBName != "myfw" {
		t.Fatalf("DBName: got %q, want %q", cfg.DBName, "myfw")
	}
	// 构造无库名 DSN
	cfg.DBName = ""
	noDB := cfg.FormatDSN()
	// 不应包含库名
	if _, err := gomysql.ParseDSN(noDB); err != nil {
		t.Fatalf("parse no-db dsn: %v", err)
	}
	noCfg, _ := gomysql.ParseDSN(noDB)
	if noCfg.DBName != "" {
		t.Fatalf("no-db DSN should have empty DBName, got %q", noCfg.DBName)
	}
}

// TestEnsureMySQLDBConfig 验证 ensureMySQLDatabase 的开关逻辑：
// SQLite 跳过、开关关闭跳过。
func TestEnsureMySQLDBConfig(t *testing.T) {
	// SQLite 应跳过（不报错）
	t.Setenv("MYFW_DB_AUTOCREATE", "true")
	cfg := Config{Driver: DriverSQLite, DSN: "file::memory:?cache=shared"}
	if err := ensureMySQLDatabase(cfg); err != nil {
		t.Fatalf("sqlite should be skipped: %v", err)
	}

	// MySQL 但开关关闭，不连接真实 DB，应跳过
	t.Setenv("MYFW_DB_AUTOCREATE", "false")
	cfg = Config{Driver: DriverMySQL, DSN: "user:pass@tcp(10.0.0.5:2881)/myfw?charset=utf8mb4"}
	if err := ensureMySQLDatabase(cfg); err != nil {
		t.Fatalf("autocreate disabled should skip: %v", err)
	}
}

// TestEnsureMySQLDBIntegration 在真实 MySQL/OceanBase 上验证自动建库。
// 需要 MYFW_TEST_MYSQL_DSN 指向一个库名**不存在**的 DSN，验证建库后连接成功。
// 跳过条件：MYFW_TEST_MYSQL_DSN 未设置。
func TestEnsureMySQLDBIntegration(t *testing.T) {
	dsn := os.Getenv("MYFW_TEST_MYSQL_DSN")
	if dsn == "" {
		t.Skip("set MYFW_TEST_MYSQL_DSN to run the auto-create DB integration test")
	}

	// 用不存在的库名验证自动建库
	cfg := Config{
		Driver:       DriverMySQL,
		DSN:          dsn,
		MaxOpenConns: 1,
		MaxIdleConns: 1,
		LogLevel:     logger.Silent,
	}
	// 先确保数据库不存在：删除（忽略错误），然后验证自动建库
	if err := ensureMySQLDatabase(cfg); err != nil {
		t.Fatalf("ensure mysql database: %v", err)
	}
	// 建库后应能正常 Open
	gdb, err := Open(cfg)
	if err != nil {
		t.Fatalf("open after ensure: %v", err)
	}
	sqlDB, err := gdb.DB()
	if err != nil {
		t.Fatalf("get sql.DB: %v", err)
	}
	if err := sqlDB.Ping(); err != nil {
		t.Fatalf("ping after ensure: %v", err)
	}
	sqlDB.Close()
}

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
