package repository

import (
	"context"
	"database/sql"

	"edr-platform/api-server/internal/model"
)

type Store struct {
	db *sql.DB
}

func NewStore(db *sql.DB) *Store {
	return &Store{db: db}
}

func (s *Store) ListAlerts(ctx context.Context) ([]model.Alert, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, title, severity, status, occurred_at 
		FROM alerts
	`)
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

func (s *Store) GetAlert(ctx context.Context, id string) (model.Alert, error) {
	var a model.Alert

	err := s.db.QueryRowContext(ctx, `
		SELECT id, title, severity, status, occurred_at 
		FROM alerts WHERE id = $1
	`, id).Scan(
		&a.ID,
		&a.Title,
		&a.Severity,
		&a.Status,
		&a.OccurredAt,
	)

	return a, err
}
