package service

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"edr-platform/detection-engine/internal/intel"
	"edr-platform/detection-engine/internal/model"
	"edr-platform/detection-engine/internal/rules"
)

type IntelStore interface {
	LoadThreatIntel(ctx context.Context) (map[string]model.ThreatIndicator, error)
	SaveAlerts(ctx context.Context, alerts []model.Alert) error
}

type Stream interface {
	ConsumeTelemetry(ctx context.Context, handler func(context.Context, model.TelemetryEvent) error) error
	PublishAlert(ctx context.Context, alert model.Alert) error
}

type Worker struct {
	logger          *slog.Logger
	store           IntelStore
	stream          Stream
	rules           *rules.Engine
	refreshInterval time.Duration
	mu              sync.RWMutex
	indicators      map[string]model.ThreatIndicator
}

func NewWorker(logger *slog.Logger, store IntelStore, stream Stream, rulesEngine *rules.Engine, refreshInterval time.Duration) *Worker {
	return &Worker{
		logger:          logger,
		store:           store,
		stream:          stream,
		rules:           rulesEngine,
		refreshInterval: refreshInterval,
		indicators:      map[string]model.ThreatIndicator{},
	}
}

func (w *Worker) Run(ctx context.Context) error {
	if err := w.refreshIndicators(ctx); err != nil {
		return err
	}

	go w.refreshLoop(ctx)

	return w.stream.ConsumeTelemetry(ctx, func(ctx context.Context, event model.TelemetryEvent) error {
		matches := intel.MatchIndicators(w.snapshotIndicators(), event)
		alerts := w.rules.Evaluate(event, matches)
		if len(alerts) == 0 {
			return nil
		}

		if err := w.store.SaveAlerts(ctx, alerts); err != nil {
			return err
		}

		for _, alert := range alerts {
			if err := w.stream.PublishAlert(ctx, alert); err != nil {
				return err
			}
		}

		w.logger.Info("alerts generated", "endpoint_id", event.EndpointID, "count", len(alerts), "hostname", event.Hostname)
		return nil
	})
}

func (w *Worker) refreshLoop(ctx context.Context) {
	ticker := time.NewTicker(w.refreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := w.refreshIndicators(ctx); err != nil {
				w.logger.Warn("failed to refresh threat intel feed", "error", err)
			}
		}
	}
}

func (w *Worker) refreshIndicators(ctx context.Context) error {
	feed, err := w.store.LoadThreatIntel(ctx)
	if err != nil {
		return err
	}

	w.mu.Lock()
	w.indicators = feed
	w.mu.Unlock()
	return nil
}

func (w *Worker) snapshotIndicators() map[string]model.ThreatIndicator {
	w.mu.RLock()
	defer w.mu.RUnlock()

	copyFeed := make(map[string]model.ThreatIndicator, len(w.indicators))
	for key, value := range w.indicators {
		copyFeed[key] = value
	}
	return copyFeed
}
