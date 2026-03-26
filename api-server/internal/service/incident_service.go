package service

import (
	"context"

	"edr-platform/api-server/internal/model"
	"edr-platform/api-server/internal/repository"
)

type IncidentService struct {
	store *repository.Store
}

func NewIncidentService(store *repository.Store) *IncidentService {
	return &IncidentService{store: store}
}

func (s *IncidentService) ListIncidents(ctx context.Context) ([]model.Incident, error) {
	return []model.Incident{}, nil // TODO: Implement ListIncidents in repository.Store
}
