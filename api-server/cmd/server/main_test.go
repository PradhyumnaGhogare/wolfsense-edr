package main

import (
	"testing"
	"time"
)

func TestCorrelateIncidents_GroupsByHostnameAndWindow(t *testing.T) {
	base := time.Date(2026, time.March, 24, 9, 0, 0, 0, time.UTC)

	incidents := correlateIncidents([]incidentAlertRow{
		{
			ID:         "alert-1",
			Title:      "First Alert",
			Severity:   "high",
			Status:     "open",
			Hostname:   "FIN-WS-042",
			OccurredAt: base,
		},
		{
			ID:         "alert-2",
			Title:      "Second Alert",
			Severity:   "critical",
			Status:     "investigating",
			Hostname:   "FIN-WS-042",
			OccurredAt: base.Add(8 * time.Minute),
		},
		{
			ID:         "alert-3",
			Title:      "Third Alert",
			Severity:   "medium",
			Status:     "resolved",
			Hostname:   "FIN-WS-042",
			OccurredAt: base.Add(21 * time.Minute),
		},
		{
			ID:         "alert-4",
			Title:      "Other Host Alert",
			Severity:   "low",
			Status:     "open",
			Hostname:   "ENG-WS-100",
			OccurredAt: base.Add(2 * time.Minute),
		},
	}, 10*time.Minute)

	if len(incidents) != 3 {
		t.Fatalf("expected 3 incidents, got %d", len(incidents))
	}

	finLatest := incidents[0]
	if finLatest.Hostname != "FIN-WS-042" {
		t.Fatalf("expected latest incident to belong to FIN-WS-042, got %q", finLatest.Hostname)
	}
	if len(finLatest.Alerts) != 1 {
		t.Fatalf("expected latest FIN incident to contain 1 alert, got %d", len(finLatest.Alerts))
	}

	engIncident := incidents[1]
	if engIncident.Hostname != "ENG-WS-100" {
		t.Fatalf("expected middle incident to belong to ENG-WS-100, got %q", engIncident.Hostname)
	}
	if engIncident.Severity != "low" {
		t.Fatalf("expected ENG severity to remain low, got %q", engIncident.Severity)
	}

	finGrouped := incidents[2]
	if finGrouped.Hostname != "FIN-WS-042" {
		t.Fatalf("expected earliest grouped incident to belong to FIN-WS-042, got %q", finGrouped.Hostname)
	}
	if len(finGrouped.Alerts) != 2 {
		t.Fatalf("expected grouped FIN incident to contain 2 alerts, got %d", len(finGrouped.Alerts))
	}
	if finGrouped.Severity != "critical" {
		t.Fatalf("expected grouped severity to escalate to critical, got %q", finGrouped.Severity)
	}
	if finGrouped.Status != "open" {
		t.Fatalf("expected grouped status to remain open, got %q", finGrouped.Status)
	}
}
