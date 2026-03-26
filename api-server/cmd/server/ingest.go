package main

import (
	"context"
	"crypto/sha1"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type telemetryEnvelope struct {
	Payload TelemetryPayload `json:"payload"`
}

type TelemetryPayload struct {
	ID          string        `json:"id"`
	EventType   string        `json:"event_type"`
	OccurredAt  time.Time     `json:"occurred_at"`
	ProcessName string        `json:"process_name"`
	CommandLine string        `json:"command_line"`
	EndpointID  string        `json:"endpoint_id"`
	Hostname    string        `json:"hostname"`
	Username    string        `json:"username"`
	EndpointIP  string        `json:"endpoint_ip"`
	RemoteIP    string        `json:"remote_ip"`
	IP          string        `json:"ip"`
	OS          string        `json:"os"`
	Owner       string        `json:"owner"`
	ProcessTree []ProcessNode `json:"process_tree"`
}

type detectionSpec struct {
	Detector         string
	Title            string
	Summary          string
	Severity         string
	Status           string
	Confidence       float64
	MitreTactic      string
	MitreTechnique   string
	MitreTechniqueID string
	IP               string
	Enrichment       map[string]any
}

func ensureSchemaUpgrades(ctx context.Context, runner dbRunner) error {
	statements := []string{
		`ALTER TABLE endpoints ADD COLUMN IF NOT EXISTS owner TEXT NOT NULL DEFAULT 'unassigned'`,
		`ALTER TABLE alerts ADD COLUMN IF NOT EXISTS ip TEXT`,
		`UPDATE endpoints SET owner = 'unassigned' WHERE owner IS NULL OR owner = ''`,
		`UPDATE alerts a
		 SET ip = COALESCE(NULLIF(a.ip, ''), NULLIF(a.evidence->>'remote_ip', ''), e.last_seen_ip)
		 FROM endpoints e
		 WHERE e.id = a.endpoint_id AND (a.ip IS NULL OR a.ip = '')`,
	}

	for _, statement := range statements {
		if _, err := runner.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("schema upgrade failed: %w", err)
		}
	}

	return nil
}

func ingestTelemetry(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		writeError(w, http.StatusBadRequest, "unable to read request body")
		return
	}

	payload, err := parseTelemetryPayload(body)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	payload = normalizeTelemetryPayload(payload)

	tx, err := db.BeginTx(r.Context(), nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer tx.Rollback()

	if err := upsertEndpoint(r.Context(), tx, payload); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	inserted, err := insertTelemetryEvent(r.Context(), tx, payload, body)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	generatedAlerts := 0
	if inserted {
		threatMatches, err := lookupThreatMatches(r.Context(), tx, payload.RemoteIP)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}

		detections := buildDetections(payload, threatMatches)
		for _, detection := range detections {
			incidentID, ensureErr := ensureIncident(r.Context(), tx, payload, detection)
			if ensureErr != nil {
				writeError(w, http.StatusInternalServerError, ensureErr.Error())
				return
			}

			if err := insertAlert(r.Context(), tx, payload, detection, incidentID); err != nil {
				writeError(w, http.StatusInternalServerError, err.Error())
				return
			}

			generatedAlerts++
		}
	}

	if err := tx.Commit(); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusAccepted, map[string]any{
		"ingested":         true,
		"telemetry_saved":  inserted,
		"endpoint_id":      payload.EndpointID,
		"alerts_generated": generatedAlerts,
	})
}

func parseTelemetryPayload(body []byte) (TelemetryPayload, error) {
	var envelope telemetryEnvelope
	if err := json.Unmarshal(body, &envelope); err == nil && (envelope.Payload.EndpointID != "" || envelope.Payload.Hostname != "" || envelope.Payload.ID != "") {
		return envelope.Payload, nil
	}

	var payload TelemetryPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		return TelemetryPayload{}, errors.New("invalid telemetry payload")
	}

	return payload, nil
}

func normalizeTelemetryPayload(payload TelemetryPayload) TelemetryPayload {
	if payload.OccurredAt.IsZero() {
		payload.OccurredAt = time.Now().UTC()
	} else {
		payload.OccurredAt = payload.OccurredAt.UTC()
	}

	payload.CommandLine = strings.TrimSpace(payload.CommandLine)
	payload.ProcessName = strings.TrimSpace(payload.ProcessName)
	payload.EndpointID = strings.TrimSpace(payload.EndpointID)
	payload.Hostname = strings.TrimSpace(payload.Hostname)
	payload.Username = strings.TrimSpace(payload.Username)
	payload.EndpointIP = strings.TrimSpace(payload.EndpointIP)
	payload.RemoteIP = strings.TrimSpace(payload.RemoteIP)
	payload.IP = strings.TrimSpace(payload.IP)
	payload.OS = strings.TrimSpace(payload.OS)
	payload.Owner = strings.TrimSpace(payload.Owner)

	if payload.RemoteIP == "" {
		payload.RemoteIP = firstNonEmpty(payload.IP, extractFirstIPv4(payload.CommandLine))
	}
	if payload.EndpointIP == "" {
		payload.EndpointIP = payload.IP
	}
	if payload.EndpointID == "" {
		payload.EndpointID = "endpoint-" + slugify(firstNonEmpty(payload.Hostname, payload.ProcessName, "unknown"))
	}
	if payload.ID == "" {
		payload.ID = hashID(
			"evt-",
			strings.Join([]string{
				payload.EndpointID,
				payload.Hostname,
				payload.ProcessName,
				payload.CommandLine,
				payload.OccurredAt.UTC().Format(time.RFC3339Nano),
			}, "|"),
		)
	}
	if payload.Hostname == "" {
		payload.Hostname = strings.ToUpper(payload.EndpointID)
	}
	if payload.ProcessName == "" {
		payload.ProcessName = "unknown-process"
	}
	if payload.OS == "" {
		payload.OS = "Windows"
	}
	if payload.Owner == "" {
		payload.Owner = "unassigned"
	}
	if payload.Username == "" {
		payload.Username = "unknown"
	}
	if len(payload.ProcessTree) == 0 {
		payload.ProcessTree = []ProcessNode{
			{
				Name:        payload.ProcessName,
				PID:         1,
				CommandLine: payload.CommandLine,
			},
		}
	}

	return payload
}

func upsertEndpoint(ctx context.Context, runner dbRunner, payload TelemetryPayload) error {
	_, err := runner.ExecContext(ctx, `
		INSERT INTO endpoints (
			id,
			organization_id,
			hostname,
			os_version,
			agent_version,
			status,
			risk_score,
			health,
			tags,
			last_telemetry_at,
			last_seen_ip,
			owner
		) VALUES (
			$1,
			$2,
			$3,
			$4,
			$5,
			'online',
			0,
			'{}'::jsonb,
			'[]'::jsonb,
			$6,
			$7,
			$8
		)
		ON CONFLICT (id) DO UPDATE SET
			hostname = EXCLUDED.hostname,
			os_version = CASE
				WHEN EXCLUDED.os_version <> '' THEN EXCLUDED.os_version
				ELSE endpoints.os_version
			END,
			status = 'online',
			last_telemetry_at = EXCLUDED.last_telemetry_at,
			last_seen_ip = CASE
				WHEN EXCLUDED.last_seen_ip <> '' THEN EXCLUDED.last_seen_ip
				ELSE endpoints.last_seen_ip
			END,
			owner = CASE
				WHEN EXCLUDED.owner <> '' THEN EXCLUDED.owner
				ELSE endpoints.owner
			END,
			updated_at = NOW()
	`,
		payload.EndpointID,
		defaultOrganizationID,
		payload.Hostname,
		payload.OS,
		defaultAgentVersion,
		payload.OccurredAt,
		payload.EndpointIP,
		payload.Owner,
	)

	return err
}

func insertTelemetryEvent(ctx context.Context, runner dbRunner, payload TelemetryPayload, rawBody []byte) (bool, error) {
	processTreeRaw, err := json.Marshal(payload.ProcessTree)
	if err != nil {
		return false, err
	}

	normalizedRaw, err := json.Marshal(payload)
	if err != nil {
		return false, err
	}

	var networkContext any
	if payload.RemoteIP != "" {
		networkContext = fmt.Sprintf(`{"remote_ip":%q}`, payload.RemoteIP)
	}

	result, err := runner.ExecContext(ctx, `
		INSERT INTO telemetry (
			id,
			endpoint_id,
			organization_id,
			hostname,
			username,
			occurred_at,
			event_type,
			process_name,
			process_path,
			process_id,
			parent_process_name,
			parent_process_id,
			command_line,
			integrity_level,
			process_tree,
			network_context,
			file_context,
			labels,
			raw_event,
			normalized_event
		) VALUES (
			$1,
			$2,
			$3,
			$4,
			$5,
			$6,
			$7,
			$8,
			'',
			0,
			NULL,
			NULL,
			$9,
			'medium',
			$10::jsonb,
			$11::jsonb,
			NULL,
			$12::jsonb,
			$13::jsonb,
			$14::jsonb
		)
		ON CONFLICT (id) DO NOTHING
	`,
		payload.ID,
		payload.EndpointID,
		defaultOrganizationID,
		payload.Hostname,
		payload.Username,
		payload.OccurredAt,
		firstNonEmpty(payload.EventType, "process_create"),
		payload.ProcessName,
		nullIfEmpty(payload.CommandLine),
		string(processTreeRaw),
		networkContext,
		`{"ingested_via":"http"}`,
		string(rawBody),
		string(normalizedRaw),
	)
	if err != nil {
		return false, err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, err
	}

	return rowsAffected > 0, nil
}

func lookupThreatMatches(ctx context.Context, runner dbRunner, ip string) ([]ThreatIntelResponse, error) {
	if ip == "" {
		return nil, nil
	}

	rows, err := runner.QueryContext(ctx, `
		SELECT
			id,
			indicator,
			indicator_type,
			provider,
			severity,
			confidence,
			category,
			first_seen_at,
			last_seen_at,
			expires_at,
			context
		FROM threat_intel
		WHERE indicator = $1
		ORDER BY confidence DESC
	`, ip)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	matches := make([]ThreatIntelResponse, 0)
	for rows.Next() {
		var match ThreatIntelResponse
		var expiresAt sql.NullTime
		var contextRaw []byte

		if err := rows.Scan(
			&match.ID,
			&match.Indicator,
			&match.IndicatorType,
			&match.Provider,
			&match.Severity,
			&match.Confidence,
			&match.Category,
			&match.FirstSeenAt,
			&match.LastSeenAt,
			&expiresAt,
			&contextRaw,
		); err != nil {
			return nil, err
		}

		if expiresAt.Valid {
			value := expiresAt.Time
			match.ExpiresAt = &value
		}
		match.Context = normalizeRawJSON(contextRaw, "{}")
		matches = append(matches, match)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return matches, nil
}

func buildDetections(payload TelemetryPayload, threatMatches []ThreatIntelResponse) []detectionSpec {
	detections := make([]detectionSpec, 0, 2)

	if strings.Contains(strings.ToLower(payload.CommandLine), "encodedcommand") {
		detections = append(detections, detectionSpec{
			Detector:         "encoded-command-detection",
			Title:            "PowerShell Encoded Command",
			Summary:          "Detected PowerShell execution using an encoded command.",
			Severity:         "high",
			Status:           "open",
			Confidence:       0.91,
			MitreTactic:      "Execution",
			MitreTechnique:   "Command and Scripting Interpreter",
			MitreTechniqueID: "T1059.001",
			IP:               payload.RemoteIP,
			Enrichment: map[string]any{
				"source": "http-ingest",
			},
		})
	}

	if len(threatMatches) > 0 {
		matchSummaries := make([]map[string]any, 0, len(threatMatches))
		for _, match := range threatMatches {
			matchSummaries = append(matchSummaries, map[string]any{
				"indicator": match.Indicator,
				"provider":  match.Provider,
				"severity":  match.Severity,
				"category":  match.Category,
			})
		}

		detections = append(detections, detectionSpec{
			Detector:         "threat-intel-enrichment",
			Title:            "Threat Intelligence Match",
			Summary:          fmt.Sprintf("Telemetry matched known malicious IP %s.", payload.RemoteIP),
			Severity:         highestThreatSeverity(threatMatches),
			Status:           "open",
			Confidence:       0.97,
			MitreTactic:      "Command and Control",
			MitreTechnique:   "Application Layer Protocol",
			MitreTechniqueID: "T1071",
			IP:               payload.RemoteIP,
			Enrichment: map[string]any{
				"threat_matches": matchSummaries,
			},
		})
	}

	return detections
}

func ensureIncident(ctx context.Context, runner dbRunner, payload TelemetryPayload, detection detectionSpec) (string, error) {
	var existingID string
	var existingSeverity string

	err := runner.QueryRowContext(ctx, `
		SELECT id, severity
		FROM incidents
		WHERE endpoint_id = $1
			AND status IN ('open', 'investigating')
			AND mitre_technique_id = $2
		ORDER BY updated_at DESC
		LIMIT 1
	`, payload.EndpointID, detection.MitreTechniqueID).Scan(&existingID, &existingSeverity)

	switch {
	case err == nil:
		_, updateErr := runner.ExecContext(ctx, `
			UPDATE incidents
			SET
				updated_at = $2,
				severity = $3,
				alert_count = alert_count + 1,
				summary = $4
			WHERE id = $1
		`,
			existingID,
			payload.OccurredAt,
			maxSeverity(existingSeverity, detection.Severity),
			detection.Summary,
		)
		return existingID, updateErr
	case errors.Is(err, sql.ErrNoRows):
		incidentID := incidentID(payload.Hostname, payload.OccurredAt, payload.ID+detection.Detector)
		title := fmt.Sprintf("%s on %s", detection.Title, payload.Hostname)

		_, insertErr := runner.ExecContext(ctx, `
			INSERT INTO incidents (
				id,
				title,
				status,
				severity,
				created_at,
				updated_at,
				endpoint_id,
				hostname,
				mitre_tactic,
				mitre_technique,
				mitre_technique_id,
				alert_count,
				analyst_owner,
				summary,
				tags
			) VALUES (
				$1,
				$2,
				$3,
				$4,
				$5,
				$5,
				$6,
				$7,
				$8,
				$9,
				$10,
				1,
				'unassigned',
				$11,
				'[]'::jsonb
			)
		`,
			incidentID,
			title,
			detection.Status,
			detection.Severity,
			payload.OccurredAt,
			payload.EndpointID,
			payload.Hostname,
			detection.MitreTactic,
			detection.MitreTechnique,
			detection.MitreTechniqueID,
			detection.Summary,
		)
		return incidentID, insertErr
	default:
		return "", err
	}
}

func insertAlert(ctx context.Context, runner dbRunner, payload TelemetryPayload, detection detectionSpec, incidentID string) error {
	processTreeRaw, err := json.Marshal(payload.ProcessTree)
	if err != nil {
		return err
	}

	evidence := map[string]any{
		"event_id":   payload.ID,
		"event_type": firstNonEmpty(payload.EventType, "process_create"),
	}
	if detection.IP != "" {
		evidence["remote_ip"] = detection.IP
	}
	if payload.CommandLine != "" {
		evidence["command_line"] = payload.CommandLine
	}

	evidenceRaw, err := json.Marshal(evidence)
	if err != nil {
		return err
	}

	enrichment := detection.Enrichment
	if enrichment == nil {
		enrichment = map[string]any{}
	}

	enrichmentRaw, err := json.Marshal(enrichment)
	if err != nil {
		return err
	}

	alertID := hashID("alert-", payload.ID+"|"+detection.Detector)
	dedupeKey := strings.Join([]string{
		payload.EndpointID,
		payload.ID,
		detection.Detector,
		payload.ProcessName,
		firstNonEmpty(detection.IP, "no-ip"),
	}, "|")

	_, err = runner.ExecContext(ctx, `
		INSERT INTO alerts (
			id,
			incident_id,
			dedupe_key,
			endpoint_id,
			occurred_at,
			hostname,
			title,
			summary,
			detector,
			process_name,
			parent_process_name,
			command_line,
			ip,
			mitre_tactic,
			mitre_technique,
			mitre_technique_id,
			severity,
			status,
			confidence,
			process_tree,
			evidence,
			enrichment
		) VALUES (
			$1,
			$2,
			$3,
			$4,
			$5,
			$6,
			$7,
			$8,
			$9,
			$10,
			NULL,
			$11,
			$12,
			$13,
			$14,
			$15,
			$16,
			$17,
			$18,
			$19::jsonb,
			$20::jsonb,
			$21::jsonb
		)
		ON CONFLICT (dedupe_key) DO UPDATE SET
			incident_id = EXCLUDED.incident_id,
			status = EXCLUDED.status,
			severity = EXCLUDED.severity,
			ip = EXCLUDED.ip,
			updated_at = NOW()
	`,
		alertID,
		incidentID,
		dedupeKey,
		payload.EndpointID,
		payload.OccurredAt,
		payload.Hostname,
		detection.Title,
		detection.Summary,
		detection.Detector,
		payload.ProcessName,
		nullIfEmpty(payload.CommandLine),
		detection.IP,
		detection.MitreTactic,
		detection.MitreTechnique,
		detection.MitreTechniqueID,
		detection.Severity,
		detection.Status,
		detection.Confidence,
		string(processTreeRaw),
		string(evidenceRaw),
		string(enrichmentRaw),
	)

	return err
}

func hashID(prefix string, seed string) string {
	digest := sha1.Sum([]byte(seed))
	return prefix + hex.EncodeToString(digest[:8])
}

func slugify(value string) string {
	lower := strings.ToLower(strings.TrimSpace(value))
	if lower == "" {
		return "unknown"
	}

	builder := strings.Builder{}
	lastDash := false
	for _, char := range lower {
		switch {
		case char >= 'a' && char <= 'z':
			builder.WriteRune(char)
			lastDash = false
		case char >= '0' && char <= '9':
			builder.WriteRune(char)
			lastDash = false
		default:
			if !lastDash {
				builder.WriteRune('-')
				lastDash = true
			}
		}
	}

	result := strings.Trim(builder.String(), "-")
	if result == "" {
		return "unknown"
	}

	return result
}
