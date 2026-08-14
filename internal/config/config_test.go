package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestPolicyDefaults:默认策略阈值与现状硬编码一致(行为零变化)。
func TestPolicyDefaults(t *testing.T) {
	d := Default()
	if d.Policy.DeadRuleThresholdDays != 3 {
		t.Errorf("dead_rule_threshold_days: want 3, got %d", d.Policy.DeadRuleThresholdDays)
	}
	if d.Policy.ConfirmDeadlineDefault != 5*time.Minute {
		t.Errorf("confirm_deadline_default: want 5m, got %v", d.Policy.ConfirmDeadlineDefault)
	}
	if d.Policy.ApplyWaitTimeout != 8*time.Second {
		t.Errorf("apply_wait_timeout: want 8s, got %v", d.Policy.ApplyWaitTimeout)
	}
}

// TestPolicyYamlOverride:YAML 可覆盖策略阈值。
func TestPolicyYamlOverride(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "p.yaml")
	yaml := `
server:
  web:
    listen: ":8080"
  grpc:
    listen: ":9090"
    tls:
      ca_file: /tmp/ca.pem
      cert_file: /tmp/s.crt
      key_file: /tmp/s.key
      client_auth: require_and_verify
policy:
  dead_rule_threshold_days: 7
  confirm_deadline_default: 10m
  apply_wait_timeout: 5s
`
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Policy.DeadRuleThresholdDays != 7 {
		t.Errorf("dead days: want 7, got %d", cfg.Policy.DeadRuleThresholdDays)
	}
	if cfg.Policy.ConfirmDeadlineDefault != 10*time.Minute {
		t.Errorf("confirm deadline: want 10m, got %v", cfg.Policy.ConfirmDeadlineDefault)
	}
	if cfg.Policy.ApplyWaitTimeout != 5*time.Second {
		t.Errorf("apply timeout: want 5s, got %v", cfg.Policy.ApplyWaitTimeout)
	}
}

func TestLoadDefaultsAndValidate(t *testing.T) {
	// No file: defaults have empty TLS paths, so validate must fail (mTLS required).
	if _, err := Load(""); err == nil {
		t.Fatal("expected validation error: mTLS cert material missing")
	}
}

func TestLoadFileAndEnvOverride(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "c.yaml")
	yaml := `
server:
  web:
    listen: ":18080"
  grpc:
    listen: ":19090"
    tls:
      ca_file: /tmp/ca.pem
      cert_file: /tmp/s.crt
      key_file: /tmp/s.key
      client_auth: require_and_verify
database:
  driver: sqlite
  dsn: ./x.db
`
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}

	// Env override wins over file.
	t.Setenv("MYFW_DB_DRIVER", "mysql")
	t.Setenv("MYFW_DB_DSN", "u:p@tcp(h:2881)/db")
	t.Setenv("MYFW_WEB_LISTEN", ":28080")

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Server.Web.Listen != ":28080" {
		t.Errorf("web listen: want :28080 (env), got %s", cfg.Server.Web.Listen)
	}
	if cfg.Server.GRPC.Listen != ":19090" {
		t.Errorf("grpc listen: want :19090 (file), got %s", cfg.Server.GRPC.Listen)
	}
	if cfg.Database.Driver != "mysql" || cfg.Database.DSN != "u:p@tcp(h:2881)/db" {
		t.Errorf("db override failed: %+v", cfg.Database)
	}
}
