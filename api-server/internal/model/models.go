package model

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// AlertSeverity represents the severity level of an alert.
type AlertSeverity string

const (
	SeverityLow      AlertSeverity = "low"
	SeverityMedium   AlertSeverity = "medium"
	SeverityHigh     AlertSeverity = "high"
	SeverityCritical AlertSeverity = "critical"
)

func (e *AlertSeverity) Scan(value interface{}) error {
	s, ok := value.(string)
	if !ok {
		return errors.New("type assertion to string failed")
	}
	*e = AlertSeverity(s)
	return nil
}

func (e AlertSeverity) Value() (driver.Value, error) {
	return string(e), nil
}

// AlertStatus represents the triage status of an alert.
type AlertStatus string

const (
	StatusOpen          AlertStatus = "open"
	StatusInvestigating AlertStatus = "investigating"
	StatusResolved      AlertStatus = "resolved"
	StatusClosed        AlertStatus = "closed"
)

func (e *AlertStatus) Scan(value interface{}) error {
	s, ok := value.(string)
	if !ok {
		return errors.New("type assertion to string failed")
	}
	*e = AlertStatus(s)
	return nil
}

func (e AlertStatus) Value() (driver.Value, error) {
	return string(e), nil
}

// RawJSON is a raw encoded JSON value. It implements Scannable and Valuer
// so it can be scanned from the database and marshaled into JSON.
type RawJSON json.RawMessage

func (j *RawJSON) Scan(value interface{}) error {
	bytes, ok := value.([]byte)
	if !ok {
		return errors.New("type assertion to []byte failed")
	}
	*j = append((*j)[0:0], bytes...)
	return nil
}

func (j RawJSON) Value() (driver.Value, error) {
	if len(j) == 0 {
		return nil, nil
	}
	return driver.Value(string(j)), nil
}

func (j RawJSON) MarshalJSON() ([]byte, error) {
	if len(j) == 0 {
		return []byte("null"), nil
	}
	return j, nil
}

func (j *RawJSON) UnmarshalJSON(data []byte) error {
	if j == nil {
		return errors.New("RawJSON: UnmarshalJSON on nil pointer")
	}
	*j = append((*j)[0:0], data...)
	return nil
}

type StringSlice []string

func (ss *StringSlice) Scan(src interface{}) error {
	var source string
	switch s := src.(type) {
	case string:
		source = s
	case []byte:
		source = string(s)
	default:
		return errors.New("incompatible type for StringSlice")
	}

	// Assuming the database format is like `{"item1", "item2"}`
	source = strings.Trim(source, "{}")
	if source == "" {
		*ss = []string{}
		return nil
	}
	parts := strings.Split(source, ",")
	*ss = make([]string, len(parts))
	for i, part := range parts {
		(*ss)[i] = strings.Trim(part, `"`)
	}
	return nil
}

func (ss StringSlice) Value() (driver.Value, error) {
	if len(ss) == 0 {
		return "{}", nil
	}
	var b strings.Builder
	b.WriteString("{")
	for i, s := range ss {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(fmt.Sprintf(`"%s"`, s))
	}
	b.WriteString("}")
	return b.String(), nil
}

// AlertFilters defines the available filter parameters for listing alerts.
type AlertFilters struct {
	Severity string
	Status   string
	Hostname string
	Limit    int
}

type ProcessNode struct {
	PID         int    `json:"pid"`
	ParentID    int    `json:"parent_id"`
	Name        string `json:"name"`
	Path        string `json:"path"`         // ✅ ADD
	CommandLine string `json:"command_line"` // ✅ ADD
}

// --- Other models for context ---

type Endpoint struct {
	ID              string      `json:"id"`
	OrganizationID  string      `json:"organization_id"`
	Hostname        string      `json:"hostname"`
	OSVersion       string      `json:"os_version"`
	AgentVersion    string      `json:"agent_version"`
	Status          string      `json:"status"`
	RiskScore       int         `json:"risk_score"`
	LastTelemetryAt time.Time   `json:"last_telemetry_at"`
	LastSeenIP      string      `json:"last_seen_ip"`
	Health          RawJSON     `json:"health"`
	Tags            StringSlice `json:"tags"`
}

type TelemetryEvent struct {
	ID          string    `json:"id"`
	EndpointID  string    `json:"endpoint_id"`
	Hostname    string    `json:"hostname"`
	EventType   string    `json:"event_type"`
	OccurredAt  time.Time `json:"occurred_at"`
	ProcessName string    `json:"process_name"`
	CommandLine string    `json:"command_line,omitempty"`
}

// ... other telemetry fields

type TelemetryBatchRequest struct {
	Endpoint Endpoint         `json:"endpoint"`
	Events   []TelemetryEvent `json:"events"`
	SentAt   time.Time        `json:"sent_at"`
}

type Incident struct {
	ID         string    `json:"id"`
	Title      string    `json:"title"`
	Status     string    `json:"status"`
	Severity   string    `json:"severity"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
	EndpointID string    `json:"endpoint_id"`
	Hostname   string    `json:"hostname"`
}

type ThreatIndicator struct {
	ID            string    `json:"id"`
	Indicator     string    `json:"indicator"`
	IndicatorType string    `json:"indicator_type"`
	Provider      string    `json:"provider"`
	Severity      string    `json:"severity"`
	FirstSeenAt   time.Time `json:"first_seen_at"`
}

type DashboardSummary struct {
	TotalEndpoints    int     `json:"total_endpoints"`
	ActiveAlerts      int     `json:"active_alerts"`
	CriticalIncidents int     `json:"critical_incidents"`
	RecentAlerts      []Alert `json:"recent_alerts"`
}

type MitreCoverage struct {
	TechniqueID string `json:"technique_id"`
	Technique   string `json:"technique"`
	Tactic      string `json:"tactic"`
	Coverage    int    `json:"coverage"`
}
