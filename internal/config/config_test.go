package config

import (
	"os"
	"path/filepath"
	"testing"
)

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
