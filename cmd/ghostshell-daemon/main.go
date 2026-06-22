package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"ghostshell/internal/config"
	"ghostshell/internal/daemon"
	"ghostshell/internal/logger"
)

// Version is stamped at build time via -ldflags "-X main.Version=…" (see Makefile).
var Version = "dev"

func main() {
	cfg := config.Load()
	logger.Set(logger.Level(cfg.LogLevel))
	closeLog, err := logger.TeeToFile(cfg.LogFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ghostshell-daemon: open log file:", err)
		os.Exit(1)
	}
	defer func() { _ = closeLog() }()

	logger.Infof("ghostshell-daemon: starting version=%s", Version)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()

	// reload carries freshly-parsed configs to the daemon on SIGHUP so it can
	// apply the hot-reloadable fields (log level, session cap) without a restart.
	reload := make(chan *config.Config, 1)
	sighup := make(chan os.Signal, 1)
	signal.Notify(sighup, syscall.SIGHUP)
	go func() {
		for range sighup {
			if err := logger.Reopen(cfg.LogFile); err != nil {
				logger.Warnf("ghostshell-daemon: reopen log: %v", err)
			} else {
				logger.Infof("ghostshell-daemon: log file reopened (SIGHUP)")
			}
			// Re-parse config without touching the Load() singleton and hand the
			// fresh values to the daemon. A full channel means a prior reload is
			// still pending — drop this one rather than block the signal handler.
			nc := config.Parse()
			select {
			case reload <- nc:
			default:
			}
		}
	}()

	if err := daemon.Run(ctx, cfg, reload); err != nil {
		fmt.Fprintln(os.Stderr, "ghostshell-daemon:", err)
		os.Exit(1)
	}
}
