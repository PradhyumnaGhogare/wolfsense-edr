package main

import (
	"context"
	"fmt"
	"time"

	"edr-platform/agent/internal/collector"
	"edr-platform/agent/internal/model"
	"edr-platform/agent/internal/transport"
)

func main() {
	ctx := context.Background()

	endpointID := "endpoint-001"
	hostname := "test-host"

	provider := collector.NewSimulatedWindowsProvider(endpointID, hostname)
	client := transport.NewClient("http://localhost:8080/ingest")

	events := make(chan model.TelemetryEvent)

	go func() {
		for e := range events {
			fmt.Println("Sending event...")
			client.Send(ctx, e)
		}
	}()

	go provider.Collect(ctx, events)

	for {
		time.Sleep(10 * time.Second)
	}
}
