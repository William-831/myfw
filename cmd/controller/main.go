// Command controller is the entry point for the MYFW control-plane service.
//
// It hosts the Web API (Gin) and the gRPC endpoint that Agents connect to.
// See docs/design.md and docs/development-plan.md for the full architecture.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"iptables-tool/internal/config"
	"iptables-tool/internal/controller/server"
	"iptables-tool/internal/db"
)

// version is overridden at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "controller:", err)
		os.Exit(1)
	}
}

func run() error {
	configPath := flag.String("config", "configs/controller.dev.yaml", "path to config file")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("myfw-controller %s\n", version)
		return nil
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}

	log := newLogger(cfg.Log)
	log.Info("starting myfw-controller", "version", version, "config", *configPath)

	// Open and migrate the database (driver/DSN resolved from MYFW_DB_* env,
	// falling back to the file). No silent downgrade.
	gdb, err := db.OpenFromEnv()
	if err != nil {
		return err
	}
	if err := db.Migrate(gdb); err != nil {
		return err
	}
	log.Info("database ready")

	srv, err := server.New(cfg, log, gdb)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	return srv.Run(ctx)
}

func newLogger(cfg config.LogConfig) *slog.Logger {
	level := slog.LevelInfo
	switch cfg.Level {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	opts := &slog.HandlerOptions{Level: level}

	var h slog.Handler
	if cfg.Format == "json" {
		h = slog.NewJSONHandler(os.Stdout, opts)
	} else {
		h = slog.NewTextHandler(os.Stdout, opts)
	}
	return slog.New(h)
}
