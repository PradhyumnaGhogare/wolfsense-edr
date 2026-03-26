package alerts

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

const (
	DefaultLimit = 50
	MaxLimit     = 200
)

var ErrInvalidID = errors.New("invalid alert id")

type Service struct {
	repo Repository
}

func NewService(repo Repository) *Service {
	return &Service{repo: repo}
}

func (s *Service) ListAlerts(ctx context.Context, limit int, endpointID string) ([]Alert, error) {
	safeLimit := limit
	if safeLimit <= 0 {
		safeLimit = DefaultLimit
	}
	if safeLimit > MaxLimit {
		safeLimit = MaxLimit
	}

	alerts, err := s.repo.List(ctx, ListFilters{
		Limit:      safeLimit,
		EndpointID: strings.TrimSpace(endpointID),
	})
	if err != nil {
		return nil, fmt.Errorf("list alerts: %w", err)
	}
	return alerts, nil
}

func (s *Service) GetAlertByID(ctx context.Context, id string) (Alert, error) {
	safeID := strings.TrimSpace(id)
	if safeID == "" {
		return Alert{}, ErrInvalidID
	}

	alert, err := s.repo.GetByID(ctx, safeID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return Alert{}, ErrNotFound
		}
		return Alert{}, fmt.Errorf("get alert by id %q: %w", safeID, err)
	}

	return alert, nil
}
