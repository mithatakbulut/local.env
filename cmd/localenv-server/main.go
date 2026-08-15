// localenv-server is the self-hosted local.env HTTP server.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/localenv/localenv/internal/config"
	"github.com/localenv/localenv/internal/server"
	"github.com/localenv/localenv/internal/store/sqlite"
)

var version = "dev"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "backup" {
		os.Exit(runBackup(os.Args[2:], os.Stdout, os.Stderr))
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg, err := config.LoadFromEnv()
	if err != nil {
		logger.Error("invalid configuration", "error", err)
		os.Exit(1)
	}

	store, err := sqlite.Open(context.Background(), cfg.DataDir)
	if err != nil {
		logger.Error("database initialization failed", "error", err)
		os.Exit(1)
	}
	defer store.Close()

	app := server.NewWithLogger(cfg, store, logger)
	httpServer := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           app.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() { errCh <- httpServer.ListenAndServe() }()
	logger.Info("localenv server listening", "address", cfg.ListenAddr, "version", version)

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	select {
	case sig := <-signals:
		logger.Info("shutdown signal received", "signal", sig.String())
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(ctx); err != nil {
			logger.Error("graceful shutdown failed", "error", err)
			os.Exit(1)
		}
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			logger.Error("http server failed", "error", err)
			os.Exit(1)
		}
	}

}
