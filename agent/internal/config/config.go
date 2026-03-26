package config

import (
	"os"
	"strconv"
	"time"
)

type Config struct {
	OrganizationID        string
	EndpointID            string
	Hostname              string
	Username              string
	AgentVersion          string
	OSVersion             string
	IngestURL             string
	EnrollmentToken       string
	BatchSize             int
	FlushInterval         time.Duration
	ChannelBuffer         int
	TLSInsecureSkipVerify bool
}

func LoadFromEnv() Config {
	hostname, _ := os.Hostname()

	return Config{
		OrganizationID:        getEnv("EDR_ORGANIZATION_ID", "acme-corp"),
		EndpointID:            getEnv("EDR_ENDPOINT_ID", "endpoint-finance-042"),
		Hostname:              getEnv("EDR_HOSTNAME", hostname),
		Username:              getEnv("EDR_USERNAME", "CORP\\analyst.svc"),
		AgentVersion:          getEnv("EDR_AGENT_VERSION", "1.7.2"),
		OSVersion:             getEnv("EDR_OS_VERSION", "Windows 11 Enterprise 23H2"),
		IngestURL:             getEnv("EDR_INGEST_URL", "http://localhost:8080/api/v1/telemetry/batch"),
		EnrollmentToken:       getEnv("EDR_ENROLLMENT_TOKEN", "local-dev-agent-token"),
		BatchSize:             getEnvInt("EDR_BATCH_SIZE", 8),
		FlushInterval:         getEnvDuration("EDR_FLUSH_INTERVAL", 5*time.Second),
		ChannelBuffer:         getEnvInt("EDR_CHANNEL_BUFFER", 64),
		TLSInsecureSkipVerify: getEnvBool("EDR_TLS_INSECURE_SKIP_VERIFY", false),
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
		value, err := strconv.Atoi(raw)
		if err == nil {
			return value
		}
	}
	return fallback
}

func getEnvBool(key string, fallback bool) bool {
	if raw, ok := os.LookupEnv(key); ok && raw != "" {
		value, err := strconv.ParseBool(raw)
		if err == nil {
			return value
		}
	}
	return fallback
}

func getEnvDuration(key string, fallback time.Duration) time.Duration {
	if raw, ok := os.LookupEnv(key); ok && raw != "" {
		value, err := time.ParseDuration(raw)
		if err == nil {
			return value
		}
	}
	return fallback
}
