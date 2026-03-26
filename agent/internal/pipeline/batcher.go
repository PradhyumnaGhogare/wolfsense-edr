package pipeline

import (
	"context"
	"sync"

	"edr-platform/agent/internal/model"
)

type Sender func(context.Context, []model.TelemetryEvent) error

type Batcher struct {
	mu      sync.Mutex
	maxSize int
	buffer  []model.TelemetryEvent
	sender  Sender
}

func NewBatcher(maxSize int, sender Sender) *Batcher {
	return &Batcher{
		maxSize: maxSize,
		buffer:  make([]model.TelemetryEvent, 0, maxSize),
		sender:  sender,
	}
}

func (b *Batcher) Add(ctx context.Context, event model.TelemetryEvent) error {
	b.mu.Lock()
	b.buffer = append(b.buffer, event)
	shouldFlush := len(b.buffer) >= b.maxSize
	b.mu.Unlock()

	if shouldFlush {
		return b.Flush(ctx)
	}

	return nil
}

func (b *Batcher) Flush(ctx context.Context) error {
	b.mu.Lock()
	if len(b.buffer) == 0 {
		b.mu.Unlock()
		return nil
	}

	events := make([]model.TelemetryEvent, len(b.buffer))
	copy(events, b.buffer)
	b.buffer = b.buffer[:0]
	b.mu.Unlock()

	return b.sender(ctx, events)
}
