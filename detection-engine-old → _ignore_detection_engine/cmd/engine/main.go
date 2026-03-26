package main

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"edr-platform/detection-engine/internal/config"
	"edr-platform/detection-engine/internal/rules"
	"edr-platform/detection-engine/internal/service"
	"edr-platform/detection-engine/internal/store"
	"edr-platform/detection-engine/internal/stream"
	_ "github.com/jackc/pgx/v5/stdlib"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	cfg := config.LoadFromEnv()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	db, err := sql.Open("pgx", cfg.DatabaseURL)
	if err != nil {
		logger.Error("failed to open database", "error", err)
		os.Exit(1)
	}
	defer db.Close()

	store := store.New(db)
	redisStream := stream.New(cfg)
	defer redisStream.Close()

	rulesEngine, err := rules.LoadFromFile(cfg.RulesPath)
	if err != nil {
		logger.Error("failed to load detection rules", "error", err)
		os.Exit(1)
	}

	worker := service.NewWorker(logger, store, redisStream, rulesEngine, cfg.IntelRefreshInterval)

	go func() {
		if err := worker.Run(ctx); err != nil {
			logger.Error("detection worker stopped", "error", err)
			stop()
		}
	}()

	healthMux := http.NewServeMux()
	healthMux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		if err := store.Ping(r.Context()); err != nil {
			http.Error(w, "database unavailable", http.StatusServiceUnavailable)
			return
		}
		if err := redisStream.Ping(r.Context()); err != nil {
			http.Error(w, "redis unavailable", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	httpServer := &http.Server{
		Addr:         cfg.BindAddr,
		Handler:      healthMux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  30 * time.Second,
	}

	go func() {
		logger.Info("detection engine starting", "bind_addr", cfg.BindAddr)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("health server crashed", "error", err)
			stop()
		}
	}()

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		logger.Warn("failed to shutdown detection engine cleanly", "error", err)
	}
}
