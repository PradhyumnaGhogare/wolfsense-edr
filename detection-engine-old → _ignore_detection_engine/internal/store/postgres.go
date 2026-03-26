package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"edr-platform/detection-engine/internal/model"
)

type Store struct {
	db *sql.DB
}

func New(db *sql.DB) *Store {
	return &Store{db: db}
}

func (s *Store) Ping(ctx context.Context) error {
	return s.db.PingContext(ctx)
}

func (s *Store) LoadThreatIntel(ctx context.Context) (map[string]model.ThreatIndicator, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, indicator, indicator_type, provider, severity, confidence, category, first_seen_at, last_seen_at, context
		FROM threat_intel
		WHERE expires_at IS NULL OR expires_at > NOW()
	`)
	if err != nil {
		return nil, fmt.Errorf("query threat intel: %w", err)
	}
	defer rows.Close()

	feed := map[string]model.ThreatIndicator{}
	for rows.Next() {
		var item model.ThreatIndicator
		var contextRaw []byte
		if err := rows.Scan(
			&item.ID, &item.Indicator, &item.IndicatorType, &item.Provider, &item.Severity,
			&item.Confidence, &item.Category, &item.FirstSeenAt, &item.LastSeenAt, &contextRaw,
		); err != nil {
			return nil, fmt.Errorf("scan threat intel row: %w", err)
		}
		_ = json.Unmarshal(contextRaw, &item.Context)
		feed[strings.ToLower(item.Indicator)] = item
	}

	return feed, rows.Err()
}

func (s *Store) SaveAlerts(ctx context.Context, alerts []model.Alert) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin alert transaction: %w", err)
	}
	defer tx.Rollback()

	for _, alert := range alerts {
		incidentID, err := s.ensureIncident(ctx, tx, alert)
		if err != nil {
			return err
		}

		processTree, _ := json.Marshal(alert.ProcessTree)
		evidence, _ := json.Marshal(alert.Evidence)
		enrichment, _ := json.Marshal(alert.Enrichment)

		if _, err := tx.ExecContext(ctx, `
			INSERT INTO alerts (
				id, incident_id, dedupe_key, endpoint_id, occurred_at, hostname, title, summary, detector,
				process_name, parent_process_name, command_line, mitre_tactic, mitre_technique, mitre_technique_id,
				severity, status, confidence, process_tree, evidence, enrichment
			) VALUES (
				$1, $2, $3, $4, $5, $6, $7, $8, $9,
				$10, $11, $12, $13, $14, $15,
				$16, $17, $18, $19, $20, $21
			)
			ON CONFLICT (dedupe_key) DO UPDATE SET
				occurred_at = EXCLUDED.occurred_at,
				status = 'open',
				enrichment = EXCLUDED.enrichment,
				updated_at = NOW()
		`,
			alert.ID, incidentID, alert.DedupeKey, alert.EndpointID, alert.OccurredAt, alert.Hostname, alert.Title, alert.Summary, alert.Detector,
			alert.Process, alert.ParentProcess, alert.CommandLine, alert.MITRETactic, alert.MITRETechnique, alert.MITRETechniqueID,
			alert.Severity, alert.Status, alert.Confidence, processTree, evidence, enrichment,
		); err != nil {
			return fmt.Errorf("insert alert %s: %w", alert.ID, err)
		}

		if _, err := tx.ExecContext(ctx, `
			UPDATE incidents
			SET
				alert_count = (SELECT COUNT(*) FROM alerts WHERE incident_id = $1),
				updated_at = NOW(),
				severity = CASE
					WHEN severity = 'critical' OR $2 = 'critical' THEN 'critical'
					WHEN severity = 'high' OR $2 = 'high' THEN 'high'
					WHEN severity = 'medium' OR $2 = 'medium' THEN 'medium'
					ELSE 'low'
				END
			WHERE id = $1
		`, incidentID, alert.Severity); err != nil {
			return fmt.Errorf("update incident %s: %w", incidentID, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit alert transaction: %w", err)
	}

	return nil
}

func (s *Store) ensureIncident(ctx context.Context, tx *sql.Tx, alert model.Alert) (string, error) {
	var incidentID string
	err := tx.QueryRowContext(ctx, `
		SELECT id
		FROM incidents
		WHERE endpoint_id = $1 AND mitre_technique_id = $2 AND status <> 'resolved'
		ORDER BY updated_at DESC
		LIMIT 1
	`, alert.EndpointID, alert.MITRETechniqueID).Scan(&incidentID)
	if err == nil {
		return incidentID, nil
	}
	if err != sql.ErrNoRows {
		return "", fmt.Errorf("lookup incident: %w", err)
	}

	incidentID = fmt.Sprintf("inc-%d", time.Now().UTC().UnixNano())
	tags, _ := json.Marshal([]string{"automated", "mitre:" + strings.ToLower(alert.MITRETechniqueID)})

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO incidents (
			id, title, status, severity, created_at, updated_at, endpoint_id, hostname,
			mitre_tactic, mitre_technique, mitre_technique_id, alert_count, analyst_owner, summary, tags
		) VALUES (
			$1, $2, 'open', $3, NOW(), NOW(), $4, $5,
			$6, $7, $8, 0, 'unassigned', $9, $10
		)
	`, incidentID, alert.Title, alert.Severity, alert.EndpointID, alert.Hostname, alert.MITRETactic, alert.MITRETechnique, alert.MITRETechniqueID, alert.Summary, tags); err != nil {
		return "", fmt.Errorf("create incident: %w", err)
	}

	return incidentID, nil
}
