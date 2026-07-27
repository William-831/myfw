// Package config loads the Agent's configuration from a YAML file. Unlike the
// Controller, the Agent has very little to configure — mainly where to reach
// the Controller and where to find its mTLS material. Precedence remains
// env > file > default. See docs/design.md § 13 / docs/deployment.md § 5.3.
package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Controller ControllerConfig `yaml:"controller"`
	Node       NodeConfig       `yaml:"node"`
}

type ControllerConfig struct {
	Endpoint       string    `yaml:"endpoint"`    // host:port
	ServerName     string    `yaml:"server_name"` // TLS SNI (falls back to endpoint host)
	TLS            TLSConfig `yaml:"tls"`
	BootstrapToken string    `yaml:"bootstrap_token"`
}

type TLSConfig struct {
	Disable  bool   `yaml:"disable"`   // 禁用 TLS（仅用于内网开发环境）
	CAFile   string `yaml:"ca_file"`
	CertFile string `yaml:"cert_file"` // written by Agent after Register
	KeyFile  string `yaml:"key_file"`  // written by Agent after Register
}

type NodeConfig struct {
	// DataDir is where /var/lib/myfw-agent lives (node.id, salt, snapshots).
	DataDir string   `yaml:"data_dir"`
	Labels  []string `yaml:"labels"`
}

// Default returns a Config with sane built-in defaults.
func Default() Config {
	return Config{
		Node: NodeConfig{DataDir: "/var/lib/myfw-agent"},
	}
}

// Load reads path (if non-empty), layers it over defaults, and applies env
// overrides. It does NOT validate — call Validate on the returned Config just
// before use, since some fields (cert_file/key_file) are legitimately empty
// on the very first startup (pre-bootstrap).
func Load(path string) (Config, error) {
	cfg := Default()
	if path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			return Config{}, fmt.Errorf("agent config: read %s: %w", path, err)
		}
		if err := yaml.Unmarshal(raw, &cfg); err != nil {
			return Config{}, fmt.Errorf("agent config: parse %s: %w", path, err)
		}
	}
	applyEnv(&cfg)
	return cfg, nil
}

func applyEnv(cfg *Config) {
	if v := os.Getenv("MYFW_AGENT_ENDPOINT"); v != "" {
		cfg.Controller.Endpoint = v
	}
	if v := os.Getenv("MYFW_AGENT_BOOTSTRAP_TOKEN"); v != "" {
		cfg.Controller.BootstrapToken = v
	}
	if v := os.Getenv("MYFW_AGENT_DATA_DIR"); v != "" {
		cfg.Node.DataDir = v
	}
}

// Bootstrapped reports whether the Agent already holds a signed client cert
// (i.e. registration has completed at least once). When false, main should
// run the bootstrap flow before opening a long-lived connection.
func (c Config) Bootstrapped() bool {
	// 如果禁用 TLS，检查 bootstrap_done 标记文件是否存在
	if c.Controller.TLS.Disable {
		donePath := c.Node.DataDir + "/bootstrap_done"
		if _, err := os.Stat(donePath); err != nil {
			return false
		}
		return true
	}
	if c.Controller.TLS.CertFile == "" || c.Controller.TLS.KeyFile == "" {
		return false
	}
	for _, p := range []string{c.Controller.TLS.CertFile, c.Controller.TLS.KeyFile} {
		if _, err := os.Stat(p); err != nil {
			return false
		}
	}
	return true
}

// RequireForBootstrap is the minimum set of fields needed to run bootstrap.
func (c Config) RequireForBootstrap() error {
	if c.Controller.Endpoint == "" {
		return fmt.Errorf("agent config: controller.endpoint is empty")
	}
	// 如果禁用 TLS，跳过证书文件检查，但仍然需要 bootstrap_token
	if !c.Controller.TLS.Disable {
		if c.Controller.TLS.CAFile == "" {
			return fmt.Errorf("agent config: controller.tls.ca_file is empty")
		}
		if c.Controller.TLS.CertFile == "" || c.Controller.TLS.KeyFile == "" {
			return fmt.Errorf("agent config: controller.tls.{cert_file,key_file} must be set (targets for the signed cert)")
		}
	}
	// 无 mTLS 模式也需要 bootstrap_token 来注册节点
	if c.Controller.BootstrapToken == "" {
		return fmt.Errorf("agent config: controller.bootstrap_token is empty")
	}
	if c.Node.DataDir == "" {
		return fmt.Errorf("agent config: node.data_dir is empty")
	}
	return nil
}
