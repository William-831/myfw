// Package db opens and migrates the Controller's database. It supports two
// backends selected at runtime: SQLite (dev) and MySQL-protocol (OceanBase,
// prod). Business code is backend-agnostic. See docs/design.md § 2.
package db

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/glebarez/sqlite" // CGO-free SQLite driver for GORM
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"iptables-tool/internal/model"
)

// Config describes how to connect to the database. Fields are typically
// populated from environment variables via ConfigFromEnv.
type Config struct {
	Driver       string // "sqlite" | "mysql"
	DSN          string
	MaxOpenConns int
	MaxIdleConns int
	LogLevel     logger.LogLevel
}

const (
	DriverSQLite = "sqlite"
	DriverMySQL  = "mysql"

	envDriver   = "MYFW_DB_DRIVER"
	envDSN      = "MYFW_DB_DSN"
	envMaxOpen  = "MYFW_DB_MAX_OPEN_CONNS"
	envMaxIdle  = "MYFW_DB_MAX_IDLE_CONNS"
	defaultDSNs = "./dev.db"
)

// ConfigFromEnv builds a Config from MYFW_DB_* environment variables, falling
// back to a dev SQLite default when unset. It does NOT silently downgrade: if
// the driver is explicitly set to mysql, an empty DSN is an error.
func ConfigFromEnv() (Config, error) {
	c := Config{
		Driver:       getenv(envDriver, DriverSQLite),
		DSN:          os.Getenv(envDSN),
		MaxOpenConns: getenvInt(envMaxOpen, 25),
		MaxIdleConns: getenvInt(envMaxIdle, 10),
		LogLevel:     logger.Warn,
	}

	switch c.Driver {
	case DriverSQLite:
		if c.DSN == "" {
			c.DSN = defaultDSNs
		}
	case DriverMySQL:
		if c.DSN == "" {
			return Config{}, fmt.Errorf("db: %s=mysql requires %s to be set", envDriver, envDSN)
		}
	default:
		return Config{}, fmt.Errorf("db: unsupported %s=%q (want sqlite|mysql)", envDriver, c.Driver)
	}
	return c, nil
}

// Open connects to the database according to cfg and configures the pool.
func Open(cfg Config) (*gorm.DB, error) {
	var dialector gorm.Dialector
	switch cfg.Driver {
	case DriverSQLite:
		dialector = sqlite.Open(cfg.DSN)
	case DriverMySQL:
		dialector = mysql.Open(cfg.DSN)
	default:
		return nil, fmt.Errorf("db: unsupported driver %q", cfg.Driver)
	}

	gdb, err := gorm.Open(dialector, &gorm.Config{
		Logger: logger.Default.LogMode(cfg.LogLevel),
	})
	if err != nil {
		return nil, fmt.Errorf("db: open %s: %w", cfg.Driver, err)
	}

	sqlDB, err := gdb.DB()
	if err != nil {
		return nil, fmt.Errorf("db: get sql.DB: %w", err)
	}
	sqlDB.SetMaxOpenConns(cfg.MaxOpenConns)
	sqlDB.SetMaxIdleConns(cfg.MaxIdleConns)
	sqlDB.SetConnMaxLifetime(30 * time.Minute)

	return gdb, nil
}

// OpenFromEnv is the convenience path used by the Controller at startup.
func OpenFromEnv() (*gorm.DB, error) {
	cfg, err := ConfigFromEnv()
	if err != nil {
		return nil, err
	}
	return Open(cfg)
}

// Migrate runs AutoMigrate for all models. Backend-portable by design.
func Migrate(gdb *gorm.DB) error {
	if err := gdb.AutoMigrate(model.AllModels()...); err != nil {
		return fmt.Errorf("db: migrate: %w", err)
	}
	if err := model.MigratePolicyGroupID(gdb); err != nil {
		return fmt.Errorf("db: migrate policy group_id: %w", err)
	}
	if err := model.MigratePolicyToTemplate(gdb); err != nil {
		return fmt.Errorf("db: migrate policy to template: %w", err)
	}
	return nil
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func getenvInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}
