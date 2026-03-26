package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"
)

const (
	defaultOrganizationID    = "acme-corp"
	defaultAgentVersion      = "1.7.2"
)

var (
	db          *sql.DB
	ipv4Pattern = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
)

type OverviewStats struct {
	Alerts    int `json:"alerts"`
	Incidents int `json:"incidents"`
	Endpoints int `json:"endpoints"`
}

type ProcessNode struct {
	Name        string `json:"name"`
	Path        string `json:"path,omitempty"`
	PID         int    `json:"pid"`
	PPID        int    `json:"ppid,omitempty"`
	CommandLine string `json:"command_line"`
}

type AlertResponse struct {
	ID                string          `json:"id"`
	IncidentID        *string         `json:"incident_id,omitempty"`
	EndpointID        string          `json:"endpoint_id"`
	Hostname          string          `json:"hostname"`
	Title             string          `json:"title"`
	Summary           string          `json:"summary"`
	Detector          string          `json:"detector"`
	Process           string          `json:"process"`
	ProcessName       string          `json:"process_name"`
	ParentProcess     *string         `json:"parent_process,omitempty"`
	ParentProcessName *string         `json:"parent_process_name,omitempty"`
	CommandLine       *string         `json:"command_line,omitempty"`
	IP                string          `json:"ip"`
	MitreTactic       string          `json:"mitre_tactic"`
	MitreTechnique    string          `json:"mitre_technique"`
	MitreTechniqueID  string          `json:"mitre_technique_id"`
	Severity          string          `json:"severity"`
	Status            string          `json:"status"`
	Confidence        float64         `json:"confidence"`
	OccurredAt        time.Time       `json:"occurred_at"`
	ProcessTree       []ProcessNode   `json:"process_tree"`
	Evidence          json.RawMessage `json:"evidence"`
	Enrichment        json.RawMessage `json:"enrichment"`
	ThreatMatch       bool            `json:"threat_match"`
}

type IncidentResponse struct {
	ID           string    `json:"id"`
	Title        string    `json:"title"`
	Status       string    `json:"status"`
	Severity     string    `json:"severity"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	EndpointID   string    `json:"endpoint_id"`
	Hostname     string    `json:"hostname"`
	Summary      string    `json:"summary"`
	AnalystOwner string    `json:"analyst_owner"`
	AlertCount   int       `json:"alert_count"`
}

type EndpointResponse struct {
	ID              string          `json:"id"`
	OrganizationID  string          `json:"organization_id"`
	Hostname        string          `json:"hostname"`
	IP              string          `json:"ip"`
	LastSeenIP      string          `json:"last_seen_ip"`
	OS              string          `json:"os"`
	OSVersion       string          `json:"os_version"`
	Owner           string          `json:"owner"`
	AgentVersion    string          `json:"agent_version"`
	Status          string          `json:"status"`
	RiskScore       int             `json:"risk_score"`
	LastSeen        time.Time       `json:"last_seen"`
	LastTelemetryAt time.Time       `json:"last_telemetry_at"`
	Health          json.RawMessage `json:"health"`
	Tags            []string        `json:"tags"`
	AlertCount      int             `json:"alert_count"`
}

type ThreatIntelResponse struct {
	ID            string          `json:"id"`
	Indicator     string          `json:"indicator"`
	IndicatorType string          `json:"indicator_type"`
	Provider      string          `json:"provider"`
	Severity      string          `json:"severity"`
	Confidence    int             `json:"confidence"`
	Category      string          `json:"category"`
	FirstSeenAt   time.Time       `json:"first_seen_at"`
	LastSeenAt    time.Time       `json:"last_seen_at"`
	ExpiresAt     *time.Time      `json:"expires_at,omitempty"`
	Context       json.RawMessage `json:"context"`
	RelatedAlerts int             `json:"related_alerts"`
}

type MitreCoverageResponse struct {
	Technique   string `json:"technique"`
	TechniqueID string `json:"technique_id"`
	Tactic      string `json:"tactic"`
	Count       int    `json:"count"`
	Coverage    int    `json:"coverage"`
	Alerts      int    `json:"alerts"`
}

type dbRunner interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func openDatabase(databaseURL string) (*sql.DB, error) {
	database, err := sql.Open("postgres", databaseURL)
	if err != nil {
		return nil, err
	}

	database.SetMaxOpenConns(25)
	database.SetMaxIdleConns(10)
	database.SetConnMaxLifetime(30 * time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := database.PingContext(ctx); err != nil {
		database.Close()
		return nil, err
	}

	return database, nil
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		log.Printf("json encode failed: %v", err)
	}
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(start))
	})
}

func normalizeRawJSON(raw []byte, fallback string) json.RawMessage {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return json.RawMessage(fallback)
	}

	return json.RawMessage(raw)
}

func decodeStringArray(raw []byte) []string {
	if len(raw) == 0 {
		return []string{}
	}

	var values []string
	if err := json.Unmarshal(raw, &values); err != nil {
		return []string{}
	}

	return values
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func nullIfEmpty(value string) any {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return value
}

func maxSeverity(current string, candidate string) string {
	if severityRank(candidate) > severityRank(current) {
		return candidate
	}
	return current
}

func highestThreatSeverity(matches []ThreatIntelResponse) string {
	highest := "low"
	for _, match := range matches {
		highest = maxSeverity(highest, match.Severity)
	}
	return highest
}

func extractFirstIPv4(raw string) string {
	matches := ipv4Pattern.FindAllString(raw, -1)
	for _, match := range matches {
		parsed := net.ParseIP(match)
		if parsed != nil && parsed.To4() != nil {
			return match
		}
	}

	return ""
}
