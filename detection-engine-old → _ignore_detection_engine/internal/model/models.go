package model

import "time"

type ProcessNode struct {
	Name        string `json:"name"`
	Path        string `json:"path,omitempty"`
	PID         int    `json:"pid"`
	PPID        int    `json:"ppid"`
	CommandLine string `json:"command_line"`
}

type NetworkContext struct {
	Protocol   string `json:"protocol,omitempty"`
	RemoteIP   string `json:"remote_ip,omitempty"`
	RemotePort int    `json:"remote_port,omitempty"`
}

type FileContext struct {
	Path       string `json:"path,omitempty"`
	Operation  string `json:"operation,omitempty"`
	HashSHA256 string `json:"hash_sha256,omitempty"`
}

type TelemetryEvent struct {
	ID                string            `json:"id"`
	OrganizationID    string            `json:"organization_id"`
	EndpointID        string            `json:"endpoint_id"`
	Hostname          string            `json:"hostname"`
	Username          string            `json:"username"`
	EventType         string            `json:"event_type"`
	OccurredAt        time.Time         `json:"occurred_at"`
	ProcessName       string            `json:"process_name"`
	ProcessPath       string            `json:"process_path,omitempty"`
	ProcessID         int               `json:"process_id"`
	ParentProcessName string            `json:"parent_process_name,omitempty"`
	ParentProcessID   int               `json:"parent_process_id,omitempty"`
	CommandLine       string            `json:"command_line,omitempty"`
	IntegrityLevel    string            `json:"integrity_level,omitempty"`
	ProcessTree       []ProcessNode     `json:"process_tree"`
	Network           *NetworkContext   `json:"network,omitempty"`
	File              *FileContext      `json:"file,omitempty"`
	Labels            map[string]string `json:"labels,omitempty"`
}

type ThreatIndicator struct {
	ID            string         `json:"id"`
	Indicator     string         `json:"indicator"`
	IndicatorType string         `json:"indicator_type"`
	Provider      string         `json:"provider"`
	Severity      string         `json:"severity"`
	Confidence    int            `json:"confidence"`
	Category      string         `json:"category"`
	FirstSeenAt   time.Time      `json:"first_seen_at"`
	LastSeenAt    time.Time      `json:"last_seen_at"`
	Context       map[string]any `json:"context"`
}

type DetectionRule struct {
	ID                  string   `json:"id"`
	Kind                string   `json:"kind,omitempty"`
	Title               string   `json:"title"`
	Description         string   `json:"description"`
	Detector            string   `json:"detector"`
	EventTypes          []string `json:"event_types"`
	ProcessNames        []string `json:"process_names"`
	ParentProcessNames  []string `json:"parent_process_names"`
	CommandLineContains []string `json:"command_line_contains"`
	ProcessTreeSequence []string `json:"process_tree_sequence"`
	Severity            string   `json:"severity"`
	MITRETactic         string   `json:"mitre_tactic"`
	MITRETechnique      string   `json:"mitre_technique"`
	MITRETechniqueID    string   `json:"mitre_technique_id"`
	Confidence          float64  `json:"confidence"`
}

type Alert struct {
	ID               string         `json:"id"`
	IncidentID       string         `json:"incident_id,omitempty"`
	DedupeKey        string         `json:"dedupe_key"`
	OccurredAt       time.Time      `json:"timestamp"`
	Hostname         string         `json:"hostname"`
	EndpointID       string         `json:"endpoint_id"`
	Title            string         `json:"title"`
	Summary          string         `json:"summary"`
	Detector         string         `json:"detector"`
	Process          string         `json:"process"`
	ParentProcess    string         `json:"parent_process"`
	CommandLine      string         `json:"command_line"`
	MITRETactic      string         `json:"mitre_tactic"`
	MITRETechnique   string         `json:"mitre_technique"`
	MITRETechniqueID string         `json:"mitre_technique_id"`
	Severity         string         `json:"severity"`
	Status           string         `json:"status"`
	Confidence       float64        `json:"confidence"`
	ProcessTree      []ProcessNode  `json:"process_tree"`
	Evidence         map[string]any `json:"evidence"`
	Enrichment       map[string]any `json:"enrichment"`
}
