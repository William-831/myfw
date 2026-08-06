package templateio

import (
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"iptables-tool/internal/model"
)

// openTestDB opens an isolated in-memory SQLite DB and migrates all models.
func openTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	gdb, err := gorm.Open(sqlite.Open("file::memory:"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	sqlDB, err := gdb.DB()
	if err != nil {
		t.Fatalf("get sql.DB: %v", err)
	}
	sqlDB.SetMaxOpenConns(1) // shared in-memory needs a single conn to persist
	if err := gdb.AutoMigrate(model.AllModels()...); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return gdb
}

// seedTestData prepopulates marks, custom chains, and templates for tests.
func seedTestData(t *testing.T, gdb *gorm.DB) {
	t.Helper()
	// Marks
	gdb.Create(&model.Mark{Name: "ops", Value: 15, Description: "运维流量"})
	gdb.Create(&model.Mark{Name: "dev", Value: 255, Description: "开发流量"})

	// Custom chains
	gdb.Create(&model.CustomChain{Name: "business-input", Parent: "MYFW-INPUT", Table: "filter", Priority: 50, Enabled: true})
	gdb.Create(&model.CustomChain{Name: "mark-mangle", Parent: "MYFW-MANGLE", Table: "mangle", Priority: 50, Enabled: true})

	// Templates (group business-input=1, mark-mangle=2)
	var chain1, chain2 model.CustomChain
	gdb.Where("name = ?", "business-input").First(&chain1)
	gdb.Where("name = ?", "mark-mangle").First(&chain2)

	gdb.Create(&model.PolicyTemplate{
		Name: "ops-mark-input-62022", GroupID: chain1.ID,
		Action: "MARK", Mark: 15, Protocol: "tcp", PortRange: "62022", Enabled: true,
		Description: "运维端口打标",
	})
	gdb.Create(&model.PolicyTemplate{
		Name: "dev-mark-input-8080", GroupID: chain1.ID,
		Action: "MARK", Mark: 255, Protocol: "tcp", PortRange: "8080", Enabled: true,
	})
	gdb.Create(&model.PolicyTemplate{
		Name: "ops-mark-mangle-62022", GroupID: chain2.ID,
		Action: "MARK", Mark: 15, Protocol: "tcp", PortRange: "62022", Enabled: true,
	})
}

// TestExportBundleContainsAll 验证导出包含所有 Mark/CustomChain/PolicyTemplate。
func TestExportBundleContainsAll(t *testing.T) {
	gdb := openTestDB(t)
	seedTestData(t, gdb)

	bundle, err := Export(gdb)
	if err != nil {
		t.Fatalf("export: %v", err)
	}

	if bundle.Version != "1.0" {
		t.Fatalf("version: got %q, want %q", bundle.Version, "1.0")
	}
	if bundle.ExportedAt.IsZero() {
		t.Fatal("exported_at should be set")
	}
	if len(bundle.Marks) != 2 {
		t.Fatalf("marks count: got %d, want 2", len(bundle.Marks))
	}
	if len(bundle.CustomChains) != 2 {
		t.Fatalf("custom_chains count: got %d, want 2", len(bundle.CustomChains))
	}
	if len(bundle.Templates) != 3 {
		t.Fatalf("templates count: got %d, want 3", len(bundle.Templates))
	}
}

// TestExportTemplateNameResolved 验证导出时 GroupID 已转为 GroupName。
func TestExportTemplateNameResolved(t *testing.T) {
	gdb := openTestDB(t)
	seedTestData(t, gdb)

	bundle, err := Export(gdb)
	if err != nil {
		t.Fatalf("export: %v", err)
	}

	for _, tpl := range bundle.Templates {
		if tpl.GroupName == "" {
			t.Fatalf("template %q has empty group_name", tpl.Name)
		}
	}
	// ops-mark-input-62022 应归 business-input
	if bundle.Templates[0].Name == "ops-mark-input-62022" && bundle.Templates[0].GroupName != "business-input" {
		t.Fatalf("expected group_name=business-input, got %q", bundle.Templates[0].GroupName)
	}
}

// TestImportSkipExisting 验证 skip 策略跳过已存在的记录。
func TestImportSkipExisting(t *testing.T) {
	gdb := openTestDB(t)
	seedTestData(t, gdb)

	bundle := &Bundle{
		Version:    "1.0",
		ExportedAt: time.Now(),
		Marks:      []model.Mark{{Name: "ops", Value: 15}, {Name: "new-mark", Value: 99}},
		CustomChains: []model.CustomChain{
			{Name: "business-input", Parent: "MYFW-INPUT", Table: "filter", Priority: 50, Enabled: true},
			{Name: "new-chain", Parent: "MYFW-INPUT", Table: "filter", Priority: 60, Enabled: true},
		},
		Templates: []TemplateExport{
			{PolicyTemplate: model.PolicyTemplate{Name: "ops-mark-input-62022", Action: "MARK", Mark: 15, Protocol: "tcp", PortRange: "62022", Enabled: true}, GroupName: "business-input"},
			{PolicyTemplate: model.PolicyTemplate{Name: "new-rule", Action: "ACCEPT", Protocol: "tcp", PortRange: "443", Enabled: true}, GroupName: "new-chain"},
		},
	}
	result, err := Import(gdb, bundle, ImportSkip)
	if err != nil {
		t.Fatalf("import: %v", err)
	}

	if result.MarksCreated != 1 {
		t.Fatalf("marks_created: got %d, want 1 (new-mark only)", result.MarksCreated)
	}
	if result.MarksSkipped != 1 {
		t.Fatalf("marks_skipped: got %d, want 1 (ops only)", result.MarksSkipped)
	}
	if result.ChainsCreated != 1 {
		t.Fatalf("chains_created: got %d, want 1 (new-chain only)", result.ChainsCreated)
	}
	if result.ChainsSkipped != 1 {
		t.Fatalf("chains_skipped: got %d, want 1 (business-input only)", result.ChainsSkipped)
	}
	if result.TemplatesCreated != 1 {
		t.Fatalf("templates_created: got %d, want 1 (new-rule only)", result.TemplatesCreated)
	}
	if result.TemplatesSkipped != 1 {
		t.Fatalf("templates_skipped: got %d, want 1 (ops-mark-input-62022 only)", result.TemplatesSkipped)
	}
}

// TestImportOverwriteExisting 验证 overwrite 策略覆盖已存在的记录。
func TestImportOverwriteExisting(t *testing.T) {
	gdb := openTestDB(t)
	seedTestData(t, gdb)

	bundle := &Bundle{
		Version:    "1.0",
		ExportedAt: time.Now(),
		Marks: []model.Mark{{Name: "ops", Value: 15, Description: "覆盖描述"}},
		CustomChains: []model.CustomChain{
			{Name: "business-input", Description: "覆盖描述"},
		},
		Templates: []TemplateExport{
			{PolicyTemplate: model.PolicyTemplate{Name: "ops-mark-input-62022", Action: "MARK", Mark: 15, Protocol: "tcp", PortRange: "62022", Description: "覆盖描述", Enabled: true}, GroupName: "business-input"},
		},
	}
	result, err := Import(gdb, bundle, ImportOverwrite)
	if err != nil {
		t.Fatalf("import: %v", err)
	}

	if result.MarksOverwritten != 1 {
		t.Fatalf("marks_overwritten: got %d, want 1", result.MarksOverwritten)
	}
	if result.ChainsOverwritten != 1 {
		t.Fatalf("chains_overwritten: got %d, want 1", result.ChainsOverwritten)
	}
	if result.TemplatesOverwritten != 1 {
		t.Fatalf("templates_overwritten: got %d, want 1", result.TemplatesOverwritten)
	}

	// 验证 description 已更新
	var m model.Mark
	gdb.Where("name = ?", "ops").First(&m)
	if m.Description != "覆盖描述" {
		t.Fatalf("mark description: got %q, want %q", m.Description, "覆盖描述")
	}
}

// TestImportFailOnConflict 验证 fail 策略遇冲突即报错回滚。
func TestImportFailOnConflict(t *testing.T) {
	gdb := openTestDB(t)
	seedTestData(t, gdb)

	bundle := &Bundle{
		Version:    "1.0",
		ExportedAt: time.Now(),
		Marks: []model.Mark{{Name: "ops", Value: 15}},
	}
	_, err := Import(gdb, bundle, ImportFail)
	if err == nil {
		t.Fatal("expected error for fail policy on conflict")
	}
}

// TestImportTransactionRollback 验证导入失败时整体回滚。
func TestImportTransactionRollback(t *testing.T) {
	gdb := openTestDB(t)
	seedTestData(t, gdb)

	// 第二个模板引用了不存在的 group_name，应导致整体回滚
	bundle := &Bundle{
		Version:    "1.0",
		ExportedAt: time.Now(),
		Marks:      []model.Mark{{Name: "new-mark", Value: 99}},
		Templates: []TemplateExport{
			{PolicyTemplate: model.PolicyTemplate{Name: "new-rule", Action: "ACCEPT", Enabled: true}, GroupName: "nonexistent-chain"},
		},
	}
	_, err := Import(gdb, bundle, ImportSkip)
	if err == nil {
		t.Fatal("expected error for nonexistent group_name")
	}
	t.Logf("import err: %v", err)

	// new-mark 应回滚，不应存在
	var count int64
	gdb.Model(&model.Mark{}).Where("name = ?", "new-mark").Count(&count)
	t.Logf("new-mark count after rollback: %d", count)
	if count > 0 {
		// 手动清理以便后续测试不干扰
		gdb.Where("name = ?", "new-mark").Delete(&model.Mark{})
		t.Fatal("new-mark should have been rolled back")
	}
}

// TestImportResolvesGroupByName 验证导入时按 group_name 正确解析到 CustomChain.ID。
func TestImportResolvesGroupByName(t *testing.T) {
	gdb := openTestDB(t)
	seedTestData(t, gdb)

	bundle := &Bundle{
		Version:    "1.0",
		ExportedAt: time.Now(),
		Templates: []TemplateExport{
			{PolicyTemplate: model.PolicyTemplate{Name: "imported-rule", Action: "ACCEPT", Protocol: "tcp", PortRange: "80", Enabled: true}, GroupName: "business-input"},
		},
	}
	result, err := Import(gdb, bundle, ImportSkip)
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if result.TemplatesCreated != 1 {
		t.Fatalf("templates_created: got %d, want 1", result.TemplatesCreated)
	}

	var tpl model.PolicyTemplate
	gdb.Where("name = ?", "imported-rule").First(&tpl)
	if tpl.GroupID == 0 {
		t.Fatal("GroupID should be resolved to non-zero")
	}
	var chain model.CustomChain
	gdb.First(&chain, tpl.GroupID)
	if chain.Name != "business-input" {
		t.Fatalf("chain name: got %q, want %q", chain.Name, "business-input")
	}
}