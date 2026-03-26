package alerts

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

var ErrNotFound = errors.New("alert not found")

type Alert struct {
	ID               string          `json:"id"`
	IncidentID       *string         `json:"incident_id"`
	Title            string          `json:"title"`
	Summary          string          `json:"summary"`
	EndpointID       string          `json:"endpoint_id"`
	Hostname         string          `json:"hostname"`
	Process          string          `json:"process"`
	ParentProcess    *string         `json:"parent_process"`
	CommandLine      *string         `json:"command_line"`
	MitreTactic      string          `json:"mitre_tactic"`
	MitreTechnique   string          `json:"mitre_technique"`
	MitreTechniqueID string          `json:"mitre_technique_id"`
	Severity         string          `json:"severity"`
	Status           string          `json:"status"`
	OccurredAt       time.Time       `json:"occurred_at"`
	ProcessTree      []ProcessNode   `json:"process_tree"`
	Evidence         json.RawMessage `json:"evidence"`
	Enrichment       json.RawMessage `json:"enrichment"`
}

type ProcessNode struct {
	Name        string `json:"name"`
	Path        string `json:"path,omitempty"`
	PID         int    `json:"pid"`
	PPID        int    `json:"ppid"`
	CommandLine string `json:"command_line"`
}

type Repository interface {
	List(ctx context.Context, filters ListFilters) ([]Alert, error)
	GetByID(ctx context.Context, id string) (Alert, error)
}

type ListFilters struct {
	Limit      int
	EndpointID string
}

type PostgresRepository struct {
	db *sql.DB
}

func NewRepository(db *sql.DB) *PostgresRepository {
	return &PostgresRepository{db: db}
}

func (r *PostgresRepository) List(ctx context.Context, filters ListFilters) ([]Alert, error) {
	query := `
		SELECT
			id,
			incident_id,
			title,
			summary,
			endpoint_id,
			hostname,
			process_name,
			parent_process_name,
			command_line,
			mitre_tactic,
			mitre_technique,
			mitre_technique_id,
			severity,
			status,
			occurred_at,
			process_tree,
			evidence,
			enrichment
		FROM alerts
		WHERE 1=1
	`

	args := make([]any, 0, 2)
	if filters.EndpointID != "" {
		args = append(args, filters.EndpointID)
		query += fmt.Sprintf(" AND endpoint_id = $%d", len(args))
	}
	args = append(args, filters.Limit)
	query += fmt.Sprintf(" ORDER BY occurred_at DESC LIMIT $%d", len(args))

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query alerts list: %w", err)
	}
	defer rows.Close()

	alerts := make([]Alert, 0, filters.Limit)
	for rows.Next() {
		alert, scanErr := scanAlert(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		alerts = append(alerts, alert)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate alerts list: %w", err)
	}

	return alerts, nil
}

func (r *PostgresRepository) GetByID(ctx context.Context, id string) (Alert, error) {
	safeID := strings.TrimSpace(id)
	if safeID == "" {
		return Alert{}, ErrNotFound
	}

	row := r.db.QueryRowContext(ctx, `
		SELECT
			id,
			incident_id,
			title,
			summary,
			endpoint_id,
			hostname,
			process_name,
			parent_process_name,
			command_line,
			mitre_tactic,
			mitre_technique,
			mitre_technique_id,
			severity,
			status,
			occurred_at,
			process_tree,
			evidence,
			enrichment
		FROM alerts
		WHERE id = $1
	`, safeID)

	alert, err := scanAlert(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Alert{}, ErrNotFound
	}
	if err != nil {
		return Alert{}, err
	}

	return alert, nil
}

type scanner interface {
	Scan(dest ...any) error
}

func scanAlert(row scanner) (Alert, error) {
	var alert Alert
	var incidentID sql.NullString
	var parentProcess sql.NullString
	var commandLine sql.NullString
	var processTreeRaw []byte
	var evidenceRaw []byte
	var enrichmentRaw []byte

	if err := row.Scan(
		&alert.ID,
		&incidentID,
		&alert.Title,
		&alert.Summary,
		&alert.EndpointID,
		&alert.Hostname,
		&alert.Process,
		&parentProcess,
		&commandLine,
		&alert.MitreTactic,
		&alert.MitreTechnique,
		&alert.MitreTechniqueID,
		&alert.Severity,
		&alert.Status,
		&alert.OccurredAt,
		&processTreeRaw,
		&evidenceRaw,
		&enrichmentRaw,
	); err != nil {
		if err == sql.ErrNoRows {
			return Alert{}, err
		}
		return Alert{}, fmt.Errorf("scan alert: %w", err)
	}

	if incidentID.Valid {
		value := incidentID.String
		alert.IncidentID = &value
	}
	if parentProcess.Valid {
		value := parentProcess.String
		alert.ParentProcess = &value
	}
	if commandLine.Valid {
		value := commandLine.String
		alert.CommandLine = &value
	}
	if len(processTreeRaw) > 0 {
		if err := json.Unmarshal(processTreeRaw, &alert.ProcessTree); err != nil {
			return Alert{}, fmt.Errorf("decode alert process tree: %w", err)
		}
	} else {
		alert.ProcessTree = make([]ProcessNode, 0)
	}
	alert.Evidence = normalizeRawJSON(evidenceRaw, "{}")
	alert.Enrichment = normalizeRawJSON(enrichmentRaw, "{}")

	return alert, nil
}

func normalizeRawJSON(raw []byte, fallback string) json.RawMessage {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return json.RawMessage(fallback)
	}

	return json.RawMessage(raw)
}
