CREATE TABLE IF NOT EXISTS endpoints (
    id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL,
    hostname TEXT NOT NULL UNIQUE,
    owner TEXT NOT NULL DEFAULT 'unassigned',
    os_version TEXT NOT NULL,
    agent_version TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('online', 'degraded', 'offline')),
    risk_score INTEGER NOT NULL DEFAULT 0,
    health JSONB NOT NULL DEFAULT '{}'::jsonb,
    tags JSONB NOT NULL DEFAULT '[]'::jsonb,
    last_telemetry_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_ip TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS telemetry (
    id TEXT PRIMARY KEY,
    endpoint_id TEXT NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,
    organization_id TEXT NOT NULL,
    hostname TEXT NOT NULL,
    username TEXT NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    event_type TEXT NOT NULL CHECK (event_type IN ('process_create', 'network_connect', 'file_write', 'file_delete', 'process_terminate')),
    process_name TEXT NOT NULL,
    process_path TEXT,
    process_id BIGINT NOT NULL,
    parent_process_name TEXT,
    parent_process_id BIGINT,
    command_line TEXT,
    integrity_level TEXT,
    process_tree JSONB NOT NULL DEFAULT '[]'::jsonb,
    network_context JSONB,
    file_context JSONB,
    labels JSONB NOT NULL DEFAULT '{}'::jsonb,
    raw_event JSONB NOT NULL,
    normalized_event JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('open', 'investigating', 'contained', 'resolved')),
    severity TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    endpoint_id TEXT NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,
    hostname TEXT NOT NULL,
    mitre_tactic TEXT NOT NULL,
    mitre_technique TEXT NOT NULL,
    mitre_technique_id TEXT NOT NULL,
    alert_count INTEGER NOT NULL DEFAULT 0,
    analyst_owner TEXT NOT NULL DEFAULT 'unassigned',
    summary TEXT NOT NULL,
    tags JSONB NOT NULL DEFAULT '[]'::jsonb
);

CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY,
    incident_id TEXT REFERENCES incidents(id) ON DELETE SET NULL,
    dedupe_key TEXT NOT NULL UNIQUE,
    endpoint_id TEXT NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,
    occurred_at TIMESTAMPTZ NOT NULL,
    hostname TEXT NOT NULL,
    title TEXT NOT NULL,
    summary TEXT NOT NULL,
    detector TEXT NOT NULL,
    process_name TEXT NOT NULL,
    parent_process_name TEXT,
    command_line TEXT,
    ip TEXT,
    mitre_tactic TEXT NOT NULL,
    mitre_technique TEXT NOT NULL,
    mitre_technique_id TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    status TEXT NOT NULL CHECK (status IN ('open', 'investigating', 'resolved')),
    confidence NUMERIC(4,2) NOT NULL,
    process_tree JSONB NOT NULL DEFAULT '[]'::jsonb,
    evidence JSONB NOT NULL DEFAULT '{}'::jsonb,
    enrichment JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS threat_intel (
    id TEXT PRIMARY KEY,
    indicator TEXT NOT NULL UNIQUE,
    indicator_type TEXT NOT NULL CHECK (indicator_type IN ('ipv4', 'domain', 'sha256')),
    provider TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    confidence INTEGER NOT NULL CHECK (confidence BETWEEN 1 AND 100),
    category TEXT NOT NULL,
    first_seen_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ,
    context JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_endpoints_status ON endpoints (status);
CREATE INDEX IF NOT EXISTS idx_endpoints_last_telemetry_at ON endpoints (last_telemetry_at DESC);

CREATE INDEX IF NOT EXISTS idx_telemetry_endpoint_occurred_at ON telemetry (endpoint_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_telemetry_event_type_occurred_at ON telemetry (event_type, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_telemetry_process_name ON telemetry (process_name);
CREATE INDEX IF NOT EXISTS idx_telemetry_hostname_occurred_at ON telemetry (hostname, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_telemetry_process_tree_gin ON telemetry USING GIN (process_tree jsonb_path_ops);
CREATE INDEX IF NOT EXISTS idx_telemetry_normalized_event_gin ON telemetry USING GIN (normalized_event jsonb_path_ops);

CREATE INDEX IF NOT EXISTS idx_incidents_status_updated_at ON incidents (status, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_incidents_endpoint_id ON incidents (endpoint_id);
CREATE INDEX IF NOT EXISTS idx_incidents_mitre_technique ON incidents (mitre_technique_id);

CREATE INDEX IF NOT EXISTS idx_alerts_occurred_at ON alerts (occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_status_severity ON alerts (status, severity);
CREATE INDEX IF NOT EXISTS idx_alerts_endpoint_id ON alerts (endpoint_id);
CREATE INDEX IF NOT EXISTS idx_alerts_incident_id ON alerts (incident_id);
CREATE INDEX IF NOT EXISTS idx_alerts_hostname ON alerts (hostname);
CREATE INDEX IF NOT EXISTS idx_alerts_mitre_technique ON alerts (mitre_technique_id);
CREATE INDEX IF NOT EXISTS idx_alerts_process_tree_gin ON alerts USING GIN (process_tree jsonb_path_ops);
CREATE INDEX IF NOT EXISTS idx_alerts_evidence_gin ON alerts USING GIN (evidence jsonb_path_ops);

CREATE INDEX IF NOT EXISTS idx_threat_intel_indicator_type ON threat_intel (indicator_type, indicator);
CREATE INDEX IF NOT EXISTS idx_threat_intel_last_seen_at ON threat_intel (last_seen_at DESC);
