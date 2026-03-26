package collector

import (
	"context"

	"edr-platform/agent/internal/model"
)

type Provider interface {
	Collect(ctx context.Context, out chan<- model.TelemetryEvent) error
}
