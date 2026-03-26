package config

import (
	"os"
	"strconv"
	"time"
)

type Config struct {
	BindAddr             string
	DatabaseURL          string
	RedisAddr            string
	RedisPassword        string
	RedisDB              int
	TelemetryStream      string
	AlertStream          string
	ConsumerGroup        string
	ConsumerName         string
	RulesPath            string
	IntelRefreshInterval time.Duration
}

func LoadFromEnv() Config {
	return Config{
		BindAddr:             getEnv("ENGINE_BIND_ADDR", ":8081"),
		DatabaseURL:          getEnv("DATABASE_URL", "postgres://postgres:Jaan@localhost:5432/edr?sslmode=disable"),
		RedisAddr:            getEnv("REDIS_ADDR", "localhost:6379"),
		RedisPassword:        getEnv("REDIS_PASSWORD", ""),
		RedisDB:              getEnvInt("REDIS_DB", 0),
		TelemetryStream:      getEnv("REDIS_STREAM_TELEMETRY", "edr.telemetry.normalized"),
		AlertStream:          getEnv("REDIS_STREAM_ALERTS", "edr.alerts"),
		ConsumerGroup:        getEnv("REDIS_CONSUMER_GROUP", "edr-detection"),
		ConsumerName:         getEnv("REDIS_CONSUMER_NAME", "engine-1"),
		RulesPath:            getEnv("ENGINE_RULES_PATH", "internal/rules/default-rules.json"),
		IntelRefreshInterval: getEnvDuration("ENGINE_INTEL_REFRESH_INTERVAL", 2*time.Minute),
	}
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok && value != "" {
		return value
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	if raw, ok := os.LookupEnv(key); ok && raw != "" {
		if value, err := strconv.Atoi(raw); err == nil {
			return value
		}
	}
	return fallback
}

func getEnvDuration(key string, fallback time.Duration) time.Duration {
	if raw, ok := os.LookupEnv(key); ok && raw != "" {
		if value, err := time.ParseDuration(raw); err == nil {
			return value
		}
	}
	return fallback
}
