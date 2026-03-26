package stream

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"edr-platform/detection-engine/internal/config"
	"edr-platform/detection-engine/internal/model"
	"github.com/redis/go-redis/v9"
)

type RedisStream struct {
	client          *redis.Client
	telemetryStream string
	alertStream     string
	consumerGroup   string
	consumerName    string
}

func New(cfg config.Config) *RedisStream {
	return &RedisStream{
		client: redis.NewClient(&redis.Options{
			Addr:     cfg.RedisAddr,
			Password: cfg.RedisPassword,
			DB:       cfg.RedisDB,
		}),
		telemetryStream: cfg.TelemetryStream,
		alertStream:     cfg.AlertStream,
		consumerGroup:   cfg.ConsumerGroup,
		consumerName:    cfg.ConsumerName,
	}
}

func (r *RedisStream) Ping(ctx context.Context) error {
	return r.client.Ping(ctx).Err()
}

func (r *RedisStream) Close() error {
	return r.client.Close()
}

func (r *RedisStream) ConsumeTelemetry(ctx context.Context, handler func(context.Context, model.TelemetryEvent) error) error {
	if err := r.ensureConsumerGroup(ctx); err != nil {
		return err
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		streams, err := r.client.XReadGroup(ctx, &redis.XReadGroupArgs{
			Group:    r.consumerGroup,
			Consumer: r.consumerName,
			Streams:  []string{r.telemetryStream, ">"},
			Count:    20,
			Block:    5 * time.Second,
		}).Result()
		if err != nil {
			if err == redis.Nil {
				continue
			}
			return fmt.Errorf("read telemetry stream: %w", err)
		}

		for _, result := range streams {
			for _, message := range result.Messages {
				var event model.TelemetryEvent
				rawPayload := fmt.Sprint(message.Values["payload"])
				if err := json.Unmarshal([]byte(rawPayload), &event); err != nil {
					_ = r.client.XAck(ctx, r.telemetryStream, r.consumerGroup, message.ID).Err()
					continue
				}

				if err := handler(ctx, event); err != nil {
					return fmt.Errorf("handle telemetry event %s: %w", event.ID, err)
				}

				if err := r.client.XAck(ctx, r.telemetryStream, r.consumerGroup, message.ID).Err(); err != nil {
					return fmt.Errorf("ack telemetry event %s: %w", message.ID, err)
				}
			}
		}
	}
}

func (r *RedisStream) PublishAlert(ctx context.Context, alert model.Alert) error {
	payload, err := json.Marshal(alert)
	if err != nil {
		return fmt.Errorf("marshal alert: %w", err)
	}

	return r.client.XAdd(ctx, &redis.XAddArgs{
		Stream: r.alertStream,
		Values: map[string]any{
			"payload": string(payload),
		},
		MaxLen: 10000,
		Approx: true,
	}).Err()
}

func (r *RedisStream) ensureConsumerGroup(ctx context.Context) error {
	err := r.client.XGroupCreateMkStream(ctx, r.telemetryStream, r.consumerGroup, "$").Err()
	if err != nil && !strings.Contains(err.Error(), "BUSYGROUP") {
		return fmt.Errorf("create telemetry consumer group: %w", err)
	}
	return nil
}
