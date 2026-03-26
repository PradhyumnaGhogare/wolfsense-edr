package collector

import (
	"context"
	"fmt"
	"time"

	"edr-platform/agent/internal/model"
)

type SimulatedWindowsProvider struct {
	endpointID string
	hostname   string
}

func NewSimulatedWindowsProvider(endpointID, hostname string) *SimulatedWindowsProvider {
	return &SimulatedWindowsProvider{
		endpointID: endpointID,
		hostname:   hostname,
	}
}

func (p *SimulatedWindowsProvider) Collect(ctx context.Context, out chan<- model.TelemetryEvent) error {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil

		case now := <-ticker.C:
			event := model.TelemetryEvent{
				ID:          fmt.Sprintf("%s-%d", p.endpointID, now.UnixNano()),
				EventType:   "process_create",
				OccurredAt:  now,
				ProcessName: "powershell.exe",
				CommandLine: "powershell.exe -EncodedCommand TEST",
				EndpointID:  p.endpointID,
				Hostname:    p.hostname,
			}

			out <- event
		}
	}
}
