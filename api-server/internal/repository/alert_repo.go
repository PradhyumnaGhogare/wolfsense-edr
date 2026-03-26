package repository

import (
	"context"
	"database/sql"
	"fmt"

	"edr-platform/api-server/internal/model"
)

type AlertRepository struct {
	db *sql.DB
}

func (r *AlertRepository) DB() {
	panic("unimplemented")
}

func NewAlertRepository(db *sql.DB) *AlertRepository {
	return &AlertRepository{db: db}
}

func (r *AlertRepository) ListAlerts(ctx context.Context, filters model.AlertFilters) ([]model.Alert, error) {
	query := `
		SELECT id, title, severity, status, occurred_at
		FROM alerts
		WHERE 1=1
	`

	args := []any{}

	if filters.Severity != "" {
		args = append(args, filters.Severity)
		query += fmt.Sprintf(" AND severity = $%d", len(args))
	}

	if filters.Status != "" {
		args = append(args, filters.Status)
		query += fmt.Sprintf(" AND status = $%d", len(args))
	}

	if filters.Hostname != "" {
		args = append(args, filters.Hostname)
		query += fmt.Sprintf(" AND hostname = $%d", len(args))
	}

	query += " ORDER BY occurred_at DESC LIMIT 100"

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var alerts []model.Alert

	for rows.Next() {
		var a model.Alert
		err := rows.Scan(
			&a.ID,
			&a.Title,
			&a.Severity,
			&a.Status,
			&a.OccurredAt,
		)
		if err != nil {
			return nil, err
		}
		alerts = append(alerts, a)
	}

	return alerts, nil
}
