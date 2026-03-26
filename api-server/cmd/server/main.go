package main

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"syscall"
	"time"

	"edr-platform/api-server/internal/config"

	_ "github.com/lib/pq"
)

const incidentCorrelationWindow = 10 * time.Minute

type Alert struct {
	ID         string `json:"id"`
	Title      string `json:"title"`
	Severity   string `json:"severity"`
	Status     string `json:"status"`
	OccurredAt string `json:"occurred_at"`
}

type Incident struct {
	ID        string  `json:"id"`
	Hostname  string  `json:"hostname"`
	Alerts    []Alert `json:"alerts"`
	Severity  string  `json:"severity"`
	Status    string  `json:"status"`
	CreatedAt string  `json:"created_at"`
}

type incidentAlertRow struct {
	ID         string
	Title      string
	Severity   string
	Status     string
	Hostname   string
	OccurredAt time.Time
}

type incidentAccumulator struct {
	ID             string
	Hostname       string
	Alerts         []Alert
	Severity       string
	Status         string
	CreatedAt      time.Time
	LastOccurredAt time.Time
}

func main() {
	cfg := config.LoadFromEnv()

	var err error
	db, err = openDatabase(cfg.DatabaseURL)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := ensureSchemaUpgrades(ctx, db); err != nil {
		log.Fatal(err)
	}

	server := &http.Server{
		Addr:              cfg.BindAddr,
		Handler:           loggingMiddleware(registerRoutes()),
		ReadHeaderTimeout: 5 * time.Second,
	}

	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-shutdown

		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), cfg.ShutdownGracePeriod)
		defer shutdownCancel()

		if err := server.Shutdown(shutdownCtx); err != nil {
			log.Printf("graceful shutdown failed: %v", err)
		}
	}()

	log.Printf("API server running on %s", cfg.BindAddr)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

func correlateIncidents(alertRows []incidentAlertRow, window time.Duration) []Incident {
	if len(alertRows) == 0 {
		return []Incident{}
	}

	sort.Slice(alertRows, func(i, j int) bool {
		if alertRows[i].Hostname == alertRows[j].Hostname {
			return alertRows[i].OccurredAt.Before(alertRows[j].OccurredAt)
		}
		return alertRows[i].Hostname < alertRows[j].Hostname
	})

	accumulators := make([]incidentAccumulator, 0)

	for _, row := range alertRows {
		alert := Alert{
			ID:         row.ID,
			Title:      row.Title,
			Severity:   row.Severity,
			Status:     row.Status,
			OccurredAt: row.OccurredAt.UTC().Format(time.RFC3339Nano),
		}

		lastIndex := len(accumulators) - 1
		if lastIndex >= 0 {
			last := &accumulators[lastIndex]
			if last.Hostname == row.Hostname && row.OccurredAt.Sub(last.LastOccurredAt) <= window {
				last.Alerts = append(last.Alerts, alert)
				last.LastOccurredAt = row.OccurredAt
				last.Severity = highestSeverity(last.Severity, row.Severity)
				last.Status = mostUrgentStatus(last.Status, row.Status)
				continue
			}
		}

		accumulators = append(accumulators, incidentAccumulator{
			ID:             incidentID(row.Hostname, row.OccurredAt, row.ID),
			Hostname:       row.Hostname,
			Alerts:         []Alert{alert},
			Severity:       row.Severity,
			Status:         row.Status,
			CreatedAt:      row.OccurredAt,
			LastOccurredAt: row.OccurredAt,
		})
	}

	incidents := make([]Incident, 0, len(accumulators))
	for _, accumulator := range accumulators {
		incidents = append(incidents, Incident{
			ID:        accumulator.ID,
			Hostname:  accumulator.Hostname,
			Alerts:    accumulator.Alerts,
			Severity:  accumulator.Severity,
			Status:    accumulator.Status,
			CreatedAt: accumulator.CreatedAt.UTC().Format(time.RFC3339Nano),
		})
	}

	sort.Slice(incidents, func(i, j int) bool {
		return incidents[i].CreatedAt > incidents[j].CreatedAt
	})

	return incidents
}

func highestSeverity(current string, candidate string) string {
	if severityRank(candidate) > severityRank(current) {
		return candidate
	}
	return current
}

func severityRank(severity string) int {
	switch severity {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func mostUrgentStatus(current string, candidate string) string {
	if statusRank(candidate) > statusRank(current) {
		return candidate
	}
	return current
}

func statusRank(status string) int {
	switch status {
	case "open":
		return 3
	case "investigating":
		return 2
	case "resolved":
		return 1
	default:
		return 0
	}
}

func incidentID(hostname string, createdAt time.Time, firstAlertID string) string {
	digest := sha1.Sum([]byte(hostname + "|" + createdAt.UTC().Format(time.RFC3339Nano) + "|" + firstAlertID))
	return "inc-" + hex.EncodeToString(digest[:8])
}
