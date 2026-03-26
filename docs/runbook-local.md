# Local Runbook

## Start the stack

```bash
docker compose -f infrastructure/docker-compose.yml up --build
```

## Run the agent on Windows

```bash
cd agent
go run ./cmd/agent
```

The agent sends simulated endpoint telemetry to `http://localhost:8080/api/v1/telemetry/batch` using the token in `INGEST_AUTH_TOKEN`.

## Services

- dashboard: `http://localhost:3000`
- api server: `http://localhost:8080`
- detection engine health: `http://localhost:8081/healthz`
- postgres: `localhost:5432`
- redis: `localhost:6379`
