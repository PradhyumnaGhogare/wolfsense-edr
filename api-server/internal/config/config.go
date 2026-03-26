package config

import (
	"os"
	"strings"
	"time"
)

type Config struct {
	BindAddr            string
	DatabaseURL         string
	RedisAddr           string
	RedisPassword       string
	RedisDB             int
	TelemetryStream     string
	AlertStream         string
	IngestAuthToken     string
	AllowedOrigins      []string
	ShutdownGracePeriod time.Duration
}

func LoadFromEnv() Config {
	return Config{
		BindAddr:            getEnv("API_BIND_ADDR", ":8080"),
		DatabaseURL:         getEnv("DATABASE_URL", "postgres://postgres:Jaan@localhost:5432/edr?sslmode=disable"),
		RedisAddr:           getEnv("REDIS_ADDR", "localhost:6379"),
		RedisPassword:       getEnv("REDIS_PASSWORD", ""),
		TelemetryStream:     getEnv("REDIS_STREAM_TELEMETRY", "edr.telemetry.normalized"),
		AlertStream:         getEnv("REDIS_STREAM_ALERTS", "edr.alerts"),
		IngestAuthToken:     getEnv("INGEST_AUTH_TOKEN", "local-dev-agent-token"),
		AllowedOrigins:      splitCSV(getEnv("ALLOWED_ORIGINS", "http://localhost:3000")),
		ShutdownGracePeriod: getEnvDuration("API_SHUTDOWN_GRACE_PERIOD", 10*time.Second),
	}
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok && value != "" {
		return value
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

func splitCSV(raw string) []string {
	parts := strings.Split(raw, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}
