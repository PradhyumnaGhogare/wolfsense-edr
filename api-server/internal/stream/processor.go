package stream

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	"edr-platform/api-server/internal/model"

	"github.com/redis/go-redis/v9"
)

type RedisStream struct {
	client          *redis.Client
	telemetryStream string
}

func NewRedisStream(client *redis.Client, stream string) *RedisStream {
	return &RedisStream{
		client:          client,
		telemetryStream: stream,
	}
}

func (r *RedisStream) StartTelemetryProcessor(ctx context.Context, db *sql.DB) {

	lastID := "0"

	for {
		streams, err := r.client.XRead(ctx, &redis.XReadArgs{
			Streams: []string{r.telemetryStream, lastID},
			Block:   0,
		}).Result()

		if err != nil {
			fmt.Println("Redis read error:", err)
			continue
		}

		for _, stream := range streams {
			for _, msg := range stream.Messages {

				lastID = msg.ID

				rawVal, ok := msg.Values["payload"]
				if !ok {
					continue
				}

				raw, ok := rawVal.(string)
				if !ok {
					continue
				}

				var event model.TelemetryEvent

				if err := json.Unmarshal([]byte(raw), &event); err != nil {
					fmt.Println("JSON error:", err)
					continue
				}

				fmt.Println("Event:", event.CommandLine)

				if strings.Contains(strings.ToLower(event.CommandLine), "encodedcommand") {

					alert := model.Alert{
						ID:         "alert-" + event.ID,
						EndpointID: event.EndpointID,
						Hostname:   event.Hostname,

						Title:    "PowerShell Encoded Command",
						Summary:  "Detected encoded PowerShell execution",
						Detector: "stream-processor",

						ProcessName:       event.ProcessName,
						ParentProcessName: &event.ProcessName,
						CommandLine:       &event.CommandLine,

						MitreTactic:      "Execution",
						MitreTechnique:   "Command and Scripting Interpreter",
						MitreTechniqueID: "T1059.001",

						Severity:   model.SeverityHigh,
						Status:     model.StatusOpen,
						Confidence: 0.9,

						OccurredAt: event.OccurredAt,
					}

					fmt.Println("ALERT GENERATED:", alert.ID)

					_, err := db.ExecContext(ctx, `
						INSERT INTO alerts (
							id, endpoint_id, hostname, title, summary,
							detector, process_name, parent_process_name, command_line,
							mitre_tactic, mitre_technique, mitre_technique_id,
							severity, status, confidence, occurred_at
						) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
					`,
						alert.ID,
						alert.EndpointID,
						alert.Hostname,
						alert.Title,
						alert.Summary,
						alert.Detector,
						alert.ProcessName,
						alert.ParentProcessName,
						alert.CommandLine,
						alert.MitreTactic,
						alert.MitreTechnique,
						alert.MitreTechniqueID,
						alert.Severity,
						alert.Status,
						alert.Confidence,
						alert.OccurredAt,
					)

					if err != nil {
						fmt.Println("DB error:", err)
					}
				}
			}
		}
	}
}
