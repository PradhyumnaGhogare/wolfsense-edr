## ⚠️ Usage Notice

Wolfsense EDR is a personal research and development project.

The architecture, detection logic, and implementation are original work.

Unauthorized copying, reuse, or redistribution is not permitted without explicit permission.

This project is intended to demonstrate detection engineering concepts and endpoint telemetry analysis.

# EDR + SOC Platform

This repository contains a production-style Endpoint Detection and Response platform with a SOC dashboard designed around the workflow of enterprise analysts.

## 🧠 Architecture
Agent → Backend → Detection Engine → Alert → Dashboard

1. Windows endpoint telemetry is produced by the Go `agent` service and posted to the ingestion API.
2. The Go `api-server` validates, normalizes, stores telemetry in PostgreSQL, and publishes events to Redis Streams.
3. The Go `detection-engine` consumes normalized telemetry, applies MITRE-aligned and behavioral rules, enriches with threat intelligence, persists alerts and incidents, and republishes alerts for realtime consumption.
4. The Next.js `dashboard` renders fleet health, alerts, incidents, threat intel, and MITRE ATT&CK coverage.

## 🚀 Features

- Endpoint telemetry collection
- Behavioral detection logic
- MITRE ATT&CK mapping
- Threat intelligence enrichment
- Real-time SOC dashboard
- Alert and incident correlation

## 🔍 Detection Use Cases

- Credential abuse detection
- Suspicious process execution
- Brute force patterns
- Lateral movement indicators

## 📦 Repository Layout

agent/ — Windows endpoint telemetry agent  
api-server/ — ingestion + API  
dashboard/ — SOC UI  
database/ — PostgreSQL schema  
detection-engine/ — detection logic  
docs/ — architecture docs  
infrastructure/ — docker setup  

## ⚙️ Local Setup

1. Copy `.env.example` to `.env`
2. Run Docker Compose
3. Start agent
4. Open dashboard at `http://localhost:3000`

## 📈 Scaling Ideas

- Elasticsearch/OpenSearch for search
- Kafka/Redis scaling
- mTLS + device identity
- artifact storage
