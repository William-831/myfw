package model

import (
	"strings"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// openIndexTestDB 打开隔离 SQLite 内存库并迁移 Task/AuditLog 两表(验证复合索引落库)。
func openIndexTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := "file:indextest_" + strings.ReplaceAll(t.Name(), "/", "_") + "?mode=memory&cache=shared"
	gdb, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	sqlDB, err := gdb.DB()
	if err != nil {
		t.Fatalf("get sql db: %v", err)
	}
	sqlDB.SetMaxOpenConns(1)
	if err := gdb.AutoMigrate(&Task{}, &AuditLog{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return gdb
}

// sqliteIndexCols 查询索引的列组成(sqlite_master 的 SQL 定义里解析)。
func sqliteIndexCols(t *testing.T, gdb *gorm.DB, indexName string) []string {
	t.Helper()
	var ddl string
	if err := gdb.Raw(`SELECT sql FROM sqlite_master WHERE type='index' AND name=?`, indexName).Scan(&ddl).Error; err != nil {
		t.Fatalf("query index %s: %v", indexName, err)
	}
	if ddl == "" {
		t.Fatalf("索引 %s 不存在", indexName)
	}
	// 形如 CREATE INDEX idx_xxx ON tasks(node_id,status);提取括号内列名
	open := strings.Index(ddl, "(")
	close := strings.LastIndex(ddl, ")")
	if open < 0 || close < 0 {
		t.Fatalf("无法解析索引定义: %s", ddl)
	}
	cols := strings.Split(ddl[open+1:close], ",")
	out := make([]string, 0, len(cols))
	for _, c := range cols {
		c = strings.TrimSpace(c)
		out = append(out, strings.Trim(c, "`\"")) // SQLite DDL 可能带反引号/双引号包裹列名
	}
	return out
}

func TestTaskNodeStatusCompositeIndex(t *testing.T) {
	gdb := openIndexTestDB(t)
	cols := sqliteIndexCols(t, gdb, "idx_task_node_status")
	if len(cols) != 2 || cols[0] != "node_id" || cols[1] != "status" {
		t.Fatalf("idx_task_node_status 列序错误: %v(期望 [node_id status])", cols)
	}
}

func TestAuditNodeCreatedCompositeIndex(t *testing.T) {
	gdb := openIndexTestDB(t)
	cols := sqliteIndexCols(t, gdb, "idx_audit_node_created")
	if len(cols) != 2 || cols[0] != "node_id" || cols[1] != "created_at" {
		t.Fatalf("idx_audit_node_created 列序错误: %v(期望 [node_id created_at])", cols)
	}
}
