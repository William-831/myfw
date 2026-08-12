package model

import (
	"strings"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// openSeedTestDB 打开隔离的 SQLite 内存库并迁移 CustomChain/SystemSetting 两表。
// DSN 按测试名唯一化,避免 shared 内存库在测试间互相污染。
func openSeedTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := "file:seedtest_" + strings.ReplaceAll(t.Name(), "/", "_") + "?mode=memory&cache=shared"
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
	sqlDB.SetMaxOpenConns(1) // shared in-memory 需单连接持久
	if err := gdb.AutoMigrate(&CustomChain{}, &SystemSetting{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return gdb
}

func countSeedChains(t *testing.T, gdb *gorm.DB) int64 {
	t.Helper()
	var n int64
	if err := gdb.Model(&CustomChain{}).Count(&n).Error; err != nil {
		t.Fatalf("count chains: %v", err)
	}
	return n
}

func hasSeedMark(t *testing.T, gdb *gorm.DB) bool {
	t.Helper()
	var s SystemSetting
	err := gdb.Where("key = ?", seedMarkKey).First(&s).Error
	if err == gorm.ErrRecordNotFound {
		return false
	}
	if err != nil {
		t.Fatalf("read mark: %v", err)
	}
	return s.Value == "done"
}

func TestSeedCustomChains_FirstTime(t *testing.T) {
	gdb := openSeedTestDB(t)
	if err := SeedCustomChains(gdb); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if n := countSeedChains(t, gdb); n != int64(len(builtinCustomChains)) {
		t.Fatalf("want %d chains, got %d", len(builtinCustomChains), n)
	}
	if !hasSeedMark(t, gdb) {
		t.Fatal("want seed mark written after first seeding")
	}
}

func TestSeedCustomChains_MarkDoneSkips(t *testing.T) {
	gdb := openSeedTestDB(t)
	if err := gdb.Create(&SystemSetting{Key: seedMarkKey, Value: "done"}).Error; err != nil {
		t.Fatalf("pre-write mark: %v", err)
	}
	if err := SeedCustomChains(gdb); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if n := countSeedChains(t, gdb); n != 0 {
		t.Fatalf("want 0 chains (mark done skips), got %d", n)
	}
}

func TestSeedCustomChains_DeletedNotRebuilt(t *testing.T) {
	gdb := openSeedTestDB(t)
	// 首次播种
	if err := SeedCustomChains(gdb); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// 用户删除一条预置链
	if err := gdb.Where("name = ?", builtinCustomChains[0].Name).Delete(&CustomChain{}).Error; err != nil {
		t.Fatalf("delete chain: %v", err)
	}
	// 重启(再次 Seed):标记已 done,已删除的链不重建
	if err := SeedCustomChains(gdb); err != nil {
		t.Fatalf("reseed: %v", err)
	}
	var n int64
	gdb.Model(&CustomChain{}).Where("name = ?", builtinCustomChains[0].Name).Count(&n)
	if n != 0 {
		t.Fatalf("deleted chain %q must not be rebuilt, got %d rows", builtinCustomChains[0].Name, n)
	}
}

func TestSeedCustomChains_PartialFailureNoMark(t *testing.T) {
	gdb := openSeedTestDB(t)
	// 用 SQLite 触发器模拟某条预置链插入失败(部分成功)
	if err := gdb.Exec(`CREATE TRIGGER block_seed BEFORE INSERT ON custom_chains
		WHEN NEW.name = 'nat-prerouting' BEGIN SELECT RAISE(ABORT, 'blocked'); END`).Error; err != nil {
		t.Fatalf("create trigger: %v", err)
	}
	if err := SeedCustomChains(gdb); err == nil {
		t.Fatal("want error on partial seed failure")
	}
	if hasSeedMark(t, gdb) {
		t.Fatal("mark must NOT be written on partial failure")
	}
	// 被阻断的链未创建(失败点之后的链也未播种,但保证失败点链确实未建)
	var n int64
	gdb.Model(&CustomChain{}).Where("name = ?", "nat-prerouting").Count(&n)
	if n != 0 {
		t.Fatalf("blocked chain must not exist, got %d", n)
	}
}
