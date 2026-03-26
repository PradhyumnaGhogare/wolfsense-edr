# EDR + SOC Platform

This repository contains a production-style Endpoint Detection and Response platform with a SOC dashboard designed around the workflow of enterprise analysts.

## Architecture

1. Windows endpoint telemetry is produced by the Go `agent` service and posted to the ingestion API.
2. The Go `api-server` validates, normalizes, stores telemetry in PostgreSQL, and publishes events to Redis Streams.
3. The Go `detection-engine` consumes normalized telemetry, applies MITRE-aligned and behavioral rules, enriches with threat intelligence, persists alerts and incidents, and republishes alerts for realtime consumption.
4. The Next.js `dashboard` renders fleet health, alerts, incidents, threat intel, and MITRE ATT&CK coverage, using the API when available and seeded SOC data as a local fallback.

## Repository layout

```text
agent/              Windows endpoint telemetry agent in Go
api-server/         REST API, ingestion layer, websocket fan-out in Go
dashboard/          Next.js SOC analyst dashboard
database/           PostgreSQL schema and seed data
detection-engine/   MITRE rule engine, TI enrichment, incident aggregation
docs/               Architecture, API, and local runbook
infrastructure/     Docker Compose for local development
```

## Local run

1. Copy `.env.example` to `.env` and adjust values if needed.
2. Start infrastructure from [`infrastructure/docker-compose.yml`](/e:/EDR-SOC/infrastructure/docker-compose.yml).
3. Run the Windows agent on the host or build [`agent/Dockerfile`](/e:/EDR-SOC/agent/Dockerfile) to produce `agent.exe`.
4. Open the dashboard at `http://localhost:3000`.

## Core capabilities

- endpoint telemetry for process, network, and file behaviors
- MITRE ATT&CK mapping on every detection
- behavioral correlation and process chain analysis
- threat intelligence enrichment for IPs and hashes
- incident and alert persistence in PostgreSQL
- realtime SOC dashboard with alerts, incidents, endpoints, TI, and MITRE views

## Scaling recommendations

- move telemetry retention to hot/warm tiers and offload search-heavy workloads to Elasticsearch or OpenSearch
- shard detection consumers by tenant or endpoint cohort with multiple Redis or Kafka consumer groups
- add mTLS enrollment, device identity, and signed agent manifests for production deployment
- separate alerting, incident management, and enrichment into independently scalable workers
- add object storage for forensic artifacts and long-lived process graph snapshots
