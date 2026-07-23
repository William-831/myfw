package policy

import (
	"context"
	"errors"
	"testing"

	"gorm.io/gorm/logger"

	"iptables-tool/internal/db"
)

func openTestDB(t *testing.T) *Service {
	t.Helper()
	// Per-test on-disk DB to avoid the shared-cache state leak between tests.
	t.Setenv("MYFW_DB_DRIVER", "sqlite")
	t.Setenv("MYFW_DB_DSN", t.TempDir()+"/pol.db")
	cfg, err := db.ConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	cfg.LogLevel = logger.Silent
	gdb, err := db.Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(gdb); err != nil {
		t.Fatal(err)
	}
	return New(gdb)
}

func TestCreateAndListAndUpdate(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	p, err := s.Create(ctx, PolicyInput{
		Name: "allow-ssh", Direction: "INBOUND",
		Source: "10.0.0.0/24", Protocol: "TCP", PortRange: "22",
		Action: "ACCEPT", Priority: 10,
		Targets: TargetsSpec{NodeIDs: []string{"n_a"}},
		Enabled: true,
	}, "tester")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if p.ID == 0 {
		t.Fatalf("no id assigned")
	}

	// Update.
	up, err := s.Update(ctx, p.ID, PolicyInput{
		Name: "allow-ssh", Direction: "INBOUND",
		Source: "10.0.1.0/24", Protocol: "TCP", PortRange: "22",
		Action: "ACCEPT", Priority: 10,
		Targets: TargetsSpec{NodeIDs: []string{"n_a", "n_b"}},
		Enabled: true,
	}, "tester")
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if up.Source != "10.0.1.0/24" {
		t.Fatalf("update did not stick")
	}

	// List.
	all, err := s.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 {
		t.Fatalf("expected 1 policy, got %d", len(all))
	}
}

func TestValidationRejectsMissingTargets(t *testing.T) {
	s := openTestDB(t)
	_, err := s.Create(context.Background(), PolicyInput{
		Name: "bad", Action: "ACCEPT",
	}, "tester")
	if err == nil {
		t.Fatal("expected validation error on empty targets")
	}
}

func TestValidationRejectsBadAction(t *testing.T) {
	s := openTestDB(t)
	_, err := s.Create(context.Background(), PolicyInput{
		Name: "bad", Action: "OPEN_SESAME",
		Targets: TargetsSpec{NodeIDs: []string{"n"}},
	}, "tester")
	if err == nil {
		t.Fatal("expected validation error on bad action")
	}
}

func TestUpdateNotFound(t *testing.T) {
	s := openTestDB(t)
	_, err := s.Update(context.Background(), 9999, PolicyInput{
		Name: "x", Action: "ACCEPT",
		Targets: TargetsSpec{NodeIDs: []string{"n"}},
	}, "tester")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}
