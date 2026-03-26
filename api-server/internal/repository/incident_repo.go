package repository

import (
	"context"

	"edr-platform/api-server/internal/model"
)

func (s *Store) ListIncidents(ctx context.Context) ([]model.Incident, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, title, status, severity, created_at, updated_at, endpoint_id, hostname
		FROM incidents
		ORDER BY created_at DESC
		LIMIT 50
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var incidents []model.Incident

	for rows.Next() {
		var i model.Incident
		err := rows.Scan(
			&i.ID,
			&i.Title,
			&i.Status,
			&i.Severity,
			&i.CreatedAt,
			&i.UpdatedAt,
			&i.EndpointID,
			&i.Hostname,
		)
		if err != nil {
			return nil, err
		}
		incidents = append(incidents, i)
	}

	return incidents, nil
}
