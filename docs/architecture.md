# Architecture Overview

## Data flow

1. `agent` simulates Windows telemetry with enterprise-style process and network scenarios.
2. `api-server` acts as the ingestion layer:
   - validates the enrollment token
   - normalizes process names and event fields
   - stores telemetry and endpoint heartbeat data
   - forwards normalized events to Redis Streams
3. `detection-engine` reads from the telemetry stream using a Redis consumer group and applies:
   - PowerShell abuse rules
   - encoded command detection
   - process chain analysis
   - credential dumping logic
   - living-off-the-land binary detection
   - threat intelligence enrichment
4. Alerts are written to PostgreSQL, correlated into incidents, and republished to an alert stream.
5. `dashboard` consumes API endpoints and presents analyst-facing workflows.

## Storage model

- PostgreSQL stores durable entities: endpoints, telemetry, alerts, incidents, and threat intel.
- JSONB preserves rich evidence such as process trees and raw events while relational columns support filtering and joins.
- Redis Streams decouples ingestion from detection and enables horizontal consumers.
- Elasticsearch is defined as an optional local profile for telemetry search expansion.

## Security posture

- bearer-token enrollment flow for the simulated agent path
- TLS-ready agent transport client
- websocket origin validation for realtime alerts
- bounded Redis streams to limit unbounded local growth
