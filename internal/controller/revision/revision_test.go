package revision

import (
	"context"
	"log/slog"
	"testing"

	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"iptables-tool/internal/controller/compiler"
	"iptables-tool/internal/db"
	"iptables-tool/internal/model"
)

// openRevisionTestDB 打开内存 SQLite 并完成全部迁移,返回 *gorm.DB。
func openRevisionTestDB(t *testing.T) *gorm.DB {
	t.Helper()
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
	return gdb
}

func newRevisionTestSvc(t *testing.T) (*Service, *gorm.DB) {
	t.Helper()
	gdb := openRevisionTestDB(t)
	return &Service{DB: gdb, Comp: compiler.New(gdb), Log: slog.Default()}, gdb
}

// seedNodeOneRule 构造一个节点 + 一条可编译的实例(1 条期望规则)。
func seedNodeOneRule(t *testing.T, gdb *gorm.DB, nodeID string) {
	t.Helper()
	chain := model.CustomChain{Name: "acl-fwd", Parent: "MYFW-FORWARD", Table: "filter", Priority: 50, Enabled: true}
	if err := gdb.Create(&chain).Error; err != nil {
		t.Fatalf("create chain: %v", err)
	}
	if err := gdb.Create(&model.NodePolicyInstance{
		NodeID: nodeID, Name: "allow-ssh", GroupID: chain.ID,
		Protocol: "TCP", PortRange: "22", Action: "ACCEPT", Priority: 10, Enabled: true,
	}).Error; err != nil {
		t.Fatalf("create instance: %v", err)
	}
}

func TestArchiveApply_CreatesRevision(t *testing.T) {
	svc, gdb := newRevisionTestSvc(t)
	seedNodeOneRule(t, gdb, "n1")

	if err := svc.ArchiveApply(context.Background(), "n1", "t_1"); err != nil {
		t.Fatalf("archive: %v", err)
	}
	var revs []model.NodeRuleRevision
	if err := gdb.Where("node_id = ?", "n1").Find(&revs).Error; err != nil {
		t.Fatalf("find revisions: %v", err)
	}
	if len(revs) != 1 {
		t.Fatalf("want 1 revision, got %d", len(revs))
	}
	r := revs[0]
	if r.RevNo != 1 {
		t.Fatalf("want rev_no=1, got %d", r.RevNo)
	}
	if r.Payload == "" {
		t.Fatal("payload must not be empty")
	}
	if r.Hash == "" {
		t.Fatal("hash must not be empty")
	}
	if r.TaskID != "t_1" {
		t.Fatalf("want task_id=t_1, got %q", r.TaskID)
	}
}

func TestArchiveApply_IncrementsRevNo(t *testing.T) {
	svc, gdb := newRevisionTestSvc(t)
	seedNodeOneRule(t, gdb, "n1")

	if err := svc.ArchiveApply(context.Background(), "n1", "t_1"); err != nil {
		t.Fatalf("archive 1: %v", err)
	}
	if err := svc.ArchiveApply(context.Background(), "n1", "t_2"); err != nil {
		t.Fatalf("archive 2: %v", err)
	}
	var revs []model.NodeRuleRevision
	if err := gdb.Where("node_id = ?", "n1").Order("rev_no ASC").Find(&revs).Error; err != nil {
		t.Fatalf("find revisions: %v", err)
	}
	if len(revs) != 2 || revs[0].RevNo != 1 || revs[1].RevNo != 2 {
		t.Fatalf("want rev_no [1 2], got %+v", revs)
	}
}

func TestArchiveApply_PruneKeepsRecent(t *testing.T) {
	svc, gdb := newRevisionTestSvc(t)
	// 空节点(无实例)也能归档空规则集,用于批量验证保留策略
	for i := 0; i < defaultKeep+10; i++ {
		if err := svc.ArchiveApply(context.Background(), "n1", "t"); err != nil {
			t.Fatalf("archive %d: %v", i, err)
		}
	}
	var n int64
	if err := gdb.Model(&model.NodeRuleRevision{}).Where("node_id = ?", "n1").Count(&n).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != defaultKeep {
		t.Fatalf("want %d revisions kept, got %d", defaultKeep, n)
	}
}

func TestList_ReturnsNewestFirst(t *testing.T) {
	svc, gdb := newRevisionTestSvc(t)
	seedNodeOneRule(t, gdb, "n1")
	for i := 0; i < 3; i++ {
		if err := svc.ArchiveApply(context.Background(), "n1", "t"); err != nil {
			t.Fatalf("archive %d: %v", i, err)
		}
	}
	revs, err := svc.List(context.Background(), "n1")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(revs) != 3 {
		t.Fatalf("want 3 revisions, got %d", len(revs))
	}
	if revs[0].RevNo != 3 || revs[2].RevNo != 1 {
		t.Fatalf("want newest-first [3 2 1], got %+v", revs)
	}
}

func TestLoad_RuleSetRoundTrip(t *testing.T) {
	svc, gdb := newRevisionTestSvc(t)
	seedNodeOneRule(t, gdb, "n1")
	if err := svc.ArchiveApply(context.Background(), "n1", "t_1"); err != nil {
		t.Fatalf("archive: %v", err)
	}
	rs, err := svc.Load(context.Background(), "n1", 1)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(rs.Rules) != 1 {
		t.Fatalf("want 1 rule in loaded ruleset, got %d", len(rs.Rules))
	}
	if rs.NodeId != "n1" {
		t.Fatalf("want node_id=n1, got %q", rs.NodeId)
	}
}

func TestLoad_NotFound(t *testing.T) {
	svc, gdb := newRevisionTestSvc(t)
	seedNodeOneRule(t, gdb, "n1")
	if _, err := svc.Load(context.Background(), "n1", 99); err == nil {
		t.Fatal("want error loading missing revision")
	}
}
