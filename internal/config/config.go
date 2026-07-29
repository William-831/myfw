// Package config loads Controller configuration from a YAML file and applies
// environment-variable overrides. Precedence: env > file > built-in default.
// See docs/design.md § 2.3 and docs/deployment.md § 4.3.
package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the full Controller configuration tree.
type Config struct {
	Server    ServerConfig    `yaml:"server"`
	Database  DatabaseConfig  `yaml:"database"`
	CA        CAConfig        `yaml:"ca"`
	Bootstrap BootstrapConfig `yaml:"bootstrap"`
	Audit     AuditConfig     `yaml:"audit"`
	Log       LogConfig       `yaml:"log"`
	Security  SecurityConfig  `yaml:"security"`
}

type ServerConfig struct {
	Web  WebConfig  `yaml:"web"`
	GRPC GRPCConfig `yaml:"grpc"`
}

type WebConfig struct {
	Listen string `yaml:"listen"`
}

type GRPCConfig struct {
	Listen string    `yaml:"listen"`
	TLS    TLSConfig `yaml:"tls"`
}

// TLSConfig configures the mTLS on the gRPC endpoint.
type TLSConfig struct {
	Disable    bool   `yaml:"disable"`     // 禁用 mTLS（仅用于内网开发环境）
	CAFile     string `yaml:"ca_file"`
	CertFile   string `yaml:"cert_file"`
	KeyFile    string `yaml:"key_file"`
	ClientAuth string `yaml:"client_auth"` // require_and_verify (enforced)
}

// DatabaseConfig holds pool tuning; driver+DSN come from MYFW_DB_* env
// (see internal/db.ConfigFromEnv), not from the file, so secrets stay out of
// the image.
type DatabaseConfig struct {
	Driver          string        `yaml:"driver"`
	DSN             string        `yaml:"dsn"`
	MaxOpenConns    int           `yaml:"max_open_conns"`
	MaxIdleConns    int           `yaml:"max_idle_conns"`
	ConnMaxLifetime time.Duration `yaml:"conn_max_lifetime"`
}

type CAConfig struct {
	KeyFile              string        `yaml:"key_file"`
	CertFile             string        `yaml:"cert_file"`
	AgentCertTTL         time.Duration `yaml:"agent_cert_ttl"`
	AgentCertRenewBefore time.Duration `yaml:"agent_cert_renew_before"`
}

type BootstrapConfig struct {
	TokenTTL time.Duration `yaml:"token_ttl"`
}

type AuditConfig struct {
	RetentionDays int `yaml:"retention_days"`
}

type LogConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

// SecurityConfig holds trust-recovery toggles.
type SecurityConfig struct {
	// AutoReregister:Controller 数据库重建后,对已通过 CA 验证的存量 Agent
	// 自动补录 node(ACTIVE)+certificate,使其无需重新 bootstrap 即可恢复接入。
	// 前提:CA(dev-ca)未丢失。CA 丢失时旧证书签名失效,走正常 bootstrap 流程。
	AutoReregister bool `yaml:"auto_reregister"`
}

// Default returns a Config with sane built-in defaults.
func Default() Config {
	return Config{
		Server: ServerConfig{
			Web:  WebConfig{Listen: ":8080"},
			GRPC: GRPCConfig{Listen: ":9090", TLS: TLSConfig{ClientAuth: "require_and_verify"}},
		},
		Database:  DatabaseConfig{MaxOpenConns: 25, MaxIdleConns: 10, ConnMaxLifetime: 30 * time.Minute},
		CA:        CAConfig{AgentCertTTL: 8760 * time.Hour, AgentCertRenewBefore: 720 * time.Hour},
		Bootstrap: BootstrapConfig{TokenTTL: 15 * time.Minute},
		Audit:     AuditConfig{RetentionDays: 365},
		Log:       LogConfig{Level: "info", Format: "text"},
		Security:  SecurityConfig{AutoReregister: true},
	}
}

// Load reads the YAML file at path (if non-empty), layering it over defaults,
// then applies environment overrides.
func Load(path string) (Config, error) {
	cfg := Default()

	if path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			return Config{}, fmt.Errorf("config: read %s: %w", path, err)
		}
		if err := yaml.Unmarshal(raw, &cfg); err != nil {
			return Config{}, fmt.Errorf("config: parse %s: %w", path, err)
		}
	}

	applyEnvOverrides(&cfg)

	if err := cfg.validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// applyEnvOverrides layers a small set of env vars over the parsed config.
// Database driver/DSN are intentionally read here so the file need not carry
// secrets in production.
func applyEnvOverrides(cfg *Config) {
	if v := os.Getenv("MYFW_DB_DRIVER"); v != "" {
		cfg.Database.Driver = v
	}
	if v := os.Getenv("MYFW_DB_DSN"); v != "" {
		cfg.Database.DSN = v
	}
	if v := os.Getenv("MYFW_WEB_LISTEN"); v != "" {
		cfg.Server.Web.Listen = v
	}
	if v := os.Getenv("MYFW_GRPC_LISTEN"); v != "" {
		cfg.Server.GRPC.Listen = v
	}
}

func (c Config) validate() error {
	if c.Server.Web.Listen == "" {
		return fmt.Errorf("config: server.web.listen is empty")
	}
	if c.Server.GRPC.Listen == "" {
		return fmt.Errorf("config: server.grpc.listen is empty")
	}
	// mTLS 检查：如果禁用则跳过证书验证
	if !c.Server.GRPC.TLS.Disable {
		t := c.Server.GRPC.TLS
		if t.CAFile == "" || t.CertFile == "" || t.KeyFile == "" {
			return fmt.Errorf("config: server.grpc.tls requires ca_file, cert_file and key_file (mTLS is mandatory unless disabled)")
		}
	}
	return nil
}
