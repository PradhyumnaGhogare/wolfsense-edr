package model

import "time"

type Alert struct {
	ID         string `json:"id"`
	EndpointID string `json:"endpoint_id"`
	Hostname   string `json:"hostname"`

	Title   string `json:"title"`
	Summary string `json:"summary"`

	Detector string `json:"detector"`

	ProcessName       string  `json:"process_name"`
	ParentProcessName *string `json:"parent_process_name"`
	CommandLine       *string `json:"command_line"`

	MitreTactic      string `json:"mitre_tactic"`
	MitreTechnique   string `json:"mitre_technique"`
	MitreTechniqueID string `json:"mitre_technique_id"`

	Severity   AlertSeverity `json:"severity"`
	Status     AlertStatus   `json:"status"`
	Confidence float64       `json:"confidence"`

	OccurredAt time.Time `json:"occurred_at"`
}
