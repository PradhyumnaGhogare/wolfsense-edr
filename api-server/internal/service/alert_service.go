package service

import (
	"context"

	"edr-platform/api-server/internal/model"
	"edr-platform/api-server/internal/repository"
)

type AlertService struct {
	store *repository.Store
}

func NewAlertService(store *repository.Store) *AlertService {
	return &AlertService{store: store}
}

func (s *AlertService) ListAlerts(ctx context.Context, filters model.AlertFilters) ([]model.Alert, error) {
	return s.store.ListAlerts(ctx) // ✅ FIX HERE
}

func (s *AlertService) GetAlert(ctx context.Context, id string) (model.Alert, error) {
	return s.store.GetAlert(ctx, id)
}
