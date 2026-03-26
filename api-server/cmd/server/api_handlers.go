package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

func registerRoutes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/healthz", healthz)
	mux.HandleFunc("/stats/overview", getOverviewStats)
	mux.HandleFunc("/alerts", getAlerts)
	mux.HandleFunc("/alerts/", getAlertByID)
	mux.HandleFunc("/incidents", getIncidents)
	mux.HandleFunc("/incidents/", getIncidentByID)
	mux.HandleFunc("/endpoints", getEndpoints)
	mux.HandleFunc("/endpoints/", getEndpointByID)
	mux.HandleFunc("/threat-intel", getThreatIntel)
	mux.HandleFunc("/mitre/coverage", getMitreCoverage)
	mux.HandleFunc("/ingest", ingestTelemetry)

	return mux
}

func healthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func getOverviewStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var stats OverviewStats
	err := db.QueryRowContext(r.Context(), `
		SELECT
			(SELECT COUNT(*) FROM alerts) AS alerts,
			(SELECT COUNT(*) FROM incidents) AS incidents,
			(SELECT COUNT(*) FROM endpoints) AS endpoints
	`).Scan(&stats.Alerts, &stats.Incidents, &stats.Endpoints)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, stats)
}

func getAlerts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	endpointID := strings.TrimSpace(r.URL.Query().Get("endpoint_id"))
	incidentID := strings.TrimSpace(r.URL.Query().Get("incident_id"))

	alerts, err := listAlerts(r.Context(), db, endpointID, incidentID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, alerts)
}

func getAlertByID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	id := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/alerts/"))
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing alert id")
		return
	}

	alert, err := getAlertRecordByID(r.Context(), db, id)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "alert not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, alert)
}

func getIncidents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	incidents, err := listIncidents(r.Context(), db)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, incidents)
}

func getIncidentByID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	id := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/incidents/"))
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing incident id")
		return
	}

	incident, err := getIncidentRecordByID(r.Context(), db, id)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "incident not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, incident)
}

func getEndpoints(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	query := strings.TrimSpace(r.URL.Query().Get("q"))
	owner := strings.TrimSpace(r.URL.Query().Get("owner"))

	endpoints, err := listEndpoints(r.Context(), db, query, owner)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, endpoints)
}

func getEndpointByID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	id := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/endpoints/"))
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing endpoint id")
		return
	}

	endpoint, err := getEndpointRecordByID(r.Context(), db, id)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "endpoint not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, endpoint)
}

func getThreatIntel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	indicators, err := listThreatIntel(r.Context(), db)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, indicators)
}

func getMitreCoverage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	coverage, err := listMitreCoverage(r.Context(), db)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, coverage)
}

func listAlerts(ctx context.Context, runner dbRunner, endpointID string, incidentID string) ([]AlertResponse, error) {
	query := `
		SELECT
			a.id,
			a.incident_id,
			a.endpoint_id,
			a.hostname,
			a.title,
			a.summary,
			a.detector,
			a.process_name,
			a.parent_process_name,
			a.command_line,
			COALESCE(NULLIF(a.ip, ''), NULLIF(a.evidence->>'remote_ip', ''), e.last_seen_ip, '') AS ip,
			a.mitre_tactic,
			a.mitre_technique,
			a.mitre_technique_id,
			a.severity,
			a.status,
			a.confidence,
			a.occurred_at,
			a.process_tree,
			a.evidence,
			a.enrichment,
			EXISTS (
				SELECT 1
				FROM threat_intel ti
				WHERE ti.indicator = COALESCE(NULLIF(a.ip, ''), NULLIF(a.evidence->>'remote_ip', ''), e.last_seen_ip, '')
			) AS threat_match
		FROM alerts a
		LEFT JOIN endpoints e ON e.id = a.endpoint_id
		WHERE 1=1
	`

	args := make([]any, 0, 2)
	if endpointID != "" {
		args = append(args, endpointID)
		query += fmt.Sprintf(" AND a.endpoint_id = $%d", len(args))
	}
	if incidentID != "" {
		args = append(args, incidentID)
		query += fmt.Sprintf(" AND a.incident_id = $%d", len(args))
	}

	query += " ORDER BY a.occurred_at DESC LIMIT 200"

	rows, err := runner.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	alerts := make([]AlertResponse, 0)
	for rows.Next() {
		alert, scanErr := scanAlertRecord(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		alerts = append(alerts, alert)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return alerts, nil
}

func getAlertRecordByID(ctx context.Context, runner dbRunner, id string) (AlertResponse, error) {
	row := runner.QueryRowContext(ctx, `
		SELECT
			a.id,
			a.incident_id,
			a.endpoint_id,
			a.hostname,
			a.title,
			a.summary,
			a.detector,
			a.process_name,
			a.parent_process_name,
			a.command_line,
			COALESCE(NULLIF(a.ip, ''), NULLIF(a.evidence->>'remote_ip', ''), e.last_seen_ip, '') AS ip,
			a.mitre_tactic,
			a.mitre_technique,
			a.mitre_technique_id,
			a.severity,
			a.status,
			a.confidence,
			a.occurred_at,
			a.process_tree,
			a.evidence,
			a.enrichment,
			EXISTS (
				SELECT 1
				FROM threat_intel ti
				WHERE ti.indicator = COALESCE(NULLIF(a.ip, ''), NULLIF(a.evidence->>'remote_ip', ''), e.last_seen_ip, '')
			) AS threat_match
		FROM alerts a
		LEFT JOIN endpoints e ON e.id = a.endpoint_id
		WHERE a.id = $1
	`, id)

	return scanAlertRecord(row)
}

func listIncidents(ctx context.Context, runner dbRunner) ([]IncidentResponse, error) {
	rows, err := runner.QueryContext(ctx, `
		SELECT
			i.id,
			i.title,
			i.status,
			i.severity,
			i.created_at,
			i.updated_at,
			i.endpoint_id,
			i.hostname,
			i.summary,
			i.analyst_owner,
			GREATEST(i.alert_count, COUNT(a.id)::int) AS alert_count
		FROM incidents i
		LEFT JOIN alerts a ON a.incident_id = i.id
		GROUP BY
			i.id,
			i.title,
			i.status,
			i.severity,
			i.created_at,
			i.updated_at,
			i.endpoint_id,
			i.hostname,
			i.summary,
			i.analyst_owner,
			i.alert_count
		ORDER BY i.updated_at DESC
		LIMIT 100
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	incidents := make([]IncidentResponse, 0)
	for rows.Next() {
		var incident IncidentResponse
		if err := rows.Scan(
			&incident.ID,
			&incident.Title,
			&incident.Status,
			&incident.Severity,
			&incident.CreatedAt,
			&incident.UpdatedAt,
			&incident.EndpointID,
			&incident.Hostname,
			&incident.Summary,
			&incident.AnalystOwner,
			&incident.AlertCount,
		); err != nil {
			return nil, err
		}

		incidents = append(incidents, incident)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return incidents, nil
}

func getIncidentRecordByID(ctx context.Context, runner dbRunner, id string) (IncidentResponse, error) {
	var incident IncidentResponse

	err := runner.QueryRowContext(ctx, `
		SELECT
			i.id,
			i.title,
			i.status,
			i.severity,
			i.created_at,
			i.updated_at,
			i.endpoint_id,
			i.hostname,
			i.summary,
			i.analyst_owner,
			GREATEST(i.alert_count, COUNT(a.id)::int) AS alert_count
		FROM incidents i
		LEFT JOIN alerts a ON a.incident_id = i.id
		WHERE i.id = $1
		GROUP BY
			i.id,
			i.title,
			i.status,
			i.severity,
			i.created_at,
			i.updated_at,
			i.endpoint_id,
			i.hostname,
			i.summary,
			i.analyst_owner,
			i.alert_count
	`, id).Scan(
		&incident.ID,
		&incident.Title,
		&incident.Status,
		&incident.Severity,
		&incident.CreatedAt,
		&incident.UpdatedAt,
		&incident.EndpointID,
		&incident.Hostname,
		&incident.Summary,
		&incident.AnalystOwner,
		&incident.AlertCount,
	)

	return incident, err
}

func listEndpoints(ctx context.Context, runner dbRunner, query string, owner string) ([]EndpointResponse, error) {
	baseQuery := `
		SELECT
			e.id,
			e.organization_id,
			e.hostname,
			COALESCE(e.last_seen_ip, '') AS ip,
			e.os_version,
			COALESCE(e.owner, 'unassigned') AS owner,
			e.agent_version,
			CASE
				WHEN e.last_telemetry_at < NOW() - INTERVAL '15 minutes' THEN 'offline'
				WHEN e.status = 'offline' THEN 'offline'
				ELSE e.status
			END AS status,
			e.risk_score,
			e.last_telemetry_at,
			e.health,
			e.tags,
			COUNT(a.id)::int AS alert_count
		FROM endpoints e
		LEFT JOIN alerts a
			ON a.endpoint_id = e.id
			AND a.status IN ('open', 'investigating')
		WHERE 1=1
	`

	args := make([]any, 0, 2)
	if query != "" {
		args = append(args, "%"+query+"%")
		baseQuery += fmt.Sprintf(" AND (e.hostname ILIKE $%d OR COALESCE(e.owner, '') ILIKE $%d)", len(args), len(args))
	}
	if owner != "" {
		args = append(args, "%"+owner+"%")
		baseQuery += fmt.Sprintf(" AND COALESCE(e.owner, '') ILIKE $%d", len(args))
	}

	baseQuery += `
		GROUP BY
			e.id,
			e.organization_id,
			e.hostname,
			e.last_seen_ip,
			e.os_version,
			e.owner,
			e.agent_version,
			e.status,
			e.risk_score,
			e.last_telemetry_at,
			e.health,
			e.tags
		ORDER BY e.last_telemetry_at DESC
		LIMIT 200
	`

	rows, err := runner.QueryContext(ctx, baseQuery, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	endpoints := make([]EndpointResponse, 0)
	for rows.Next() {
		endpoint, scanErr := scanEndpointRecord(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		endpoints = append(endpoints, endpoint)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return endpoints, nil
}

func getEndpointRecordByID(ctx context.Context, runner dbRunner, id string) (EndpointResponse, error) {
	row := runner.QueryRowContext(ctx, `
		SELECT
			e.id,
			e.organization_id,
			e.hostname,
			COALESCE(e.last_seen_ip, '') AS ip,
			e.os_version,
			COALESCE(e.owner, 'unassigned') AS owner,
			e.agent_version,
			CASE
				WHEN e.last_telemetry_at < NOW() - INTERVAL '15 minutes' THEN 'offline'
				WHEN e.status = 'offline' THEN 'offline'
				ELSE e.status
			END AS status,
			e.risk_score,
			e.last_telemetry_at,
			e.health,
			e.tags,
			COUNT(a.id)::int AS alert_count
		FROM endpoints e
		LEFT JOIN alerts a
			ON a.endpoint_id = e.id
			AND a.status IN ('open', 'investigating')
		WHERE e.id = $1
		GROUP BY
			e.id,
			e.organization_id,
			e.hostname,
			e.last_seen_ip,
			e.os_version,
			e.owner,
			e.agent_version,
			e.status,
			e.risk_score,
			e.last_telemetry_at,
			e.health,
			e.tags
	`, id)

	return scanEndpointRecord(row)
}

func listThreatIntel(ctx context.Context, runner dbRunner) ([]ThreatIntelResponse, error) {
	rows, err := runner.QueryContext(ctx, `
		SELECT
			t.id,
			t.indicator,
			t.indicator_type,
			t.provider,
			t.severity,
			t.confidence,
			t.category,
			t.first_seen_at,
			t.last_seen_at,
			t.expires_at,
			t.context,
			COUNT(a.id)::int AS related_alerts
		FROM threat_intel t
		LEFT JOIN alerts a
			ON COALESCE(NULLIF(a.ip, ''), NULLIF(a.evidence->>'remote_ip', '')) = t.indicator
		GROUP BY
			t.id,
			t.indicator,
			t.indicator_type,
			t.provider,
			t.severity,
			t.confidence,
			t.category,
			t.first_seen_at,
			t.last_seen_at,
			t.expires_at,
			t.context
		ORDER BY
			CASE t.severity
				WHEN 'critical' THEN 4
				WHEN 'high' THEN 3
				WHEN 'medium' THEN 2
				WHEN 'low' THEN 1
				ELSE 0
			END DESC,
			t.last_seen_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	indicators := make([]ThreatIntelResponse, 0)
	for rows.Next() {
		var indicator ThreatIntelResponse
		var expiresAt sql.NullTime
		var contextRaw []byte

		if err := rows.Scan(
			&indicator.ID,
			&indicator.Indicator,
			&indicator.IndicatorType,
			&indicator.Provider,
			&indicator.Severity,
			&indicator.Confidence,
			&indicator.Category,
			&indicator.FirstSeenAt,
			&indicator.LastSeenAt,
			&expiresAt,
			&contextRaw,
			&indicator.RelatedAlerts,
		); err != nil {
			return nil, err
		}

		if expiresAt.Valid {
			value := expiresAt.Time
			indicator.ExpiresAt = &value
		}
		indicator.Context = normalizeRawJSON(contextRaw, "{}")
		indicators = append(indicators, indicator)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return indicators, nil
}

func listMitreCoverage(ctx context.Context, runner dbRunner) ([]MitreCoverageResponse, error) {
	rows, err := runner.QueryContext(ctx, `
		WITH counts AS (
			SELECT
				mitre_technique_id,
				mitre_technique,
				mitre_tactic,
				COUNT(*)::int AS count
			FROM alerts
			GROUP BY
				mitre_technique_id,
				mitre_technique,
				mitre_tactic
		),
		max_counts AS (
			SELECT COALESCE(MAX(count), 1) AS max_count FROM counts
		)
		SELECT
			c.mitre_technique_id,
			c.mitre_technique,
			c.mitre_tactic,
			c.count,
			GREATEST(1, CEIL((c.count::numeric / m.max_count::numeric) * 5))::int AS coverage
		FROM counts c
		CROSS JOIN max_counts m
		ORDER BY c.count DESC, c.mitre_technique_id ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	coverage := make([]MitreCoverageResponse, 0)
	for rows.Next() {
		var item MitreCoverageResponse
		if err := rows.Scan(
			&item.TechniqueID,
			&item.Technique,
			&item.Tactic,
			&item.Count,
			&item.Coverage,
		); err != nil {
			return nil, err
		}

		item.Alerts = item.Count
		coverage = append(coverage, item)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return coverage, nil
}

func scanAlertRecord(row interface{ Scan(dest ...any) error }) (AlertResponse, error) {
	var alert AlertResponse
	var incidentID sql.NullString
	var parentProcess sql.NullString
	var commandLine sql.NullString
	var ip sql.NullString
	var processTreeRaw []byte
	var evidenceRaw []byte
	var enrichmentRaw []byte

	if err := row.Scan(
		&alert.ID,
		&incidentID,
		&alert.EndpointID,
		&alert.Hostname,
		&alert.Title,
		&alert.Summary,
		&alert.Detector,
		&alert.ProcessName,
		&parentProcess,
		&commandLine,
		&ip,
		&alert.MitreTactic,
		&alert.MitreTechnique,
		&alert.MitreTechniqueID,
		&alert.Severity,
		&alert.Status,
		&alert.Confidence,
		&alert.OccurredAt,
		&processTreeRaw,
		&evidenceRaw,
		&enrichmentRaw,
		&alert.ThreatMatch,
	); err != nil {
		return AlertResponse{}, err
	}

	alert.Process = alert.ProcessName
	if incidentID.Valid {
		value := incidentID.String
		alert.IncidentID = &value
	}
	if parentProcess.Valid {
		value := parentProcess.String
		alert.ParentProcess = &value
		alert.ParentProcessName = &value
	}
	if commandLine.Valid {
		value := commandLine.String
		alert.CommandLine = &value
	}
	if ip.Valid {
		alert.IP = ip.String
	}
	if len(processTreeRaw) > 0 {
		if err := json.Unmarshal(processTreeRaw, &alert.ProcessTree); err != nil {
			return AlertResponse{}, err
		}
	} else {
		alert.ProcessTree = []ProcessNode{}
	}
	alert.Evidence = normalizeRawJSON(evidenceRaw, "{}")
	alert.Enrichment = normalizeRawJSON(enrichmentRaw, "{}")

	return alert, nil
}

func scanEndpointRecord(row interface{ Scan(dest ...any) error }) (EndpointResponse, error) {
	var endpoint EndpointResponse
	var healthRaw []byte
	var tagsRaw []byte

	if err := row.Scan(
		&endpoint.ID,
		&endpoint.OrganizationID,
		&endpoint.Hostname,
		&endpoint.IP,
		&endpoint.OSVersion,
		&endpoint.Owner,
		&endpoint.AgentVersion,
		&endpoint.Status,
		&endpoint.RiskScore,
		&endpoint.LastTelemetryAt,
		&healthRaw,
		&tagsRaw,
		&endpoint.AlertCount,
	); err != nil {
		return EndpointResponse{}, err
	}

	endpoint.OS = endpoint.OSVersion
	endpoint.LastSeenIP = endpoint.IP
	endpoint.LastSeen = endpoint.LastTelemetryAt
	endpoint.Health = normalizeRawJSON(healthRaw, "{}")
	endpoint.Tags = decodeStringArray(tagsRaw)

	return endpoint, nil
}
