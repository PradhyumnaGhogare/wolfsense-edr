package model

import "time"

type TelemetryEvent struct {
	ID         string    `json:"id"`
	EventType  string    `json:"event_type"`
	OccurredAt time.Time `json:"occurred_at"`

	ProcessName string `json:"process_name"`
	CommandLine string `json:"command_line"`

	EndpointID string `json:"endpoint_id"`
	Hostname   string `json:"hostname"`
}
