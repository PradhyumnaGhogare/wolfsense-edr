export type Severity = "critical" | "high" | "medium" | "low";

export type AlertStatus =
  | "open"
  | "investigating"
  | "resolved"
  | "closed";

export type IncidentStatus = AlertStatus | "contained";

export type EndpointStatus = "online" | "degraded" | "offline";

export type ProcessNode = {
  name: string;
  path?: string;
  pid: number;
  ppid?: number;
  parent_id?: number;
  command_line: string;
};

export type ProcessTreeNode = ProcessNode;

export type Alert = {
  id: string;
  incident_id?: string | null;
  endpoint_id?: string;
  title: string;
  summary?: string;
  detector?: string;
  hostname?: string;
  process?: string;
  process_name?: string;
  parent_process?: string | null;
  parent_process_name?: string | null;
  command_line?: string | null;
  ip?: string;
  mitre_tactic?: string;
  mitre_technique?: string;
  mitre_technique_id?: string;
  severity: Severity;
  status: AlertStatus;
  confidence?: number;
  occurred_at?: string;
  process_tree?: ProcessNode[];
  evidence?: Record<string, unknown>;
  enrichment?: Record<string, unknown>;
  threat_match?: boolean;
};

export type Incident = {
  id: string;
  title?: string;
  hostname?: string;
  severity: Severity;
  status: IncidentStatus;
  created_at?: string;
  updated_at?: string;
  endpoint_id?: string;
  summary?: string;
  analyst_owner?: string;
  alert_count?: number;
  alerts?: Alert[];
};

export type Endpoint = {
  id: string;
  organization_id?: string;
  hostname?: string;
  ip?: string;
  last_seen_ip?: string;
  os?: string;
  os_version?: string;
  owner?: string;
  agent_version?: string;
  status?: EndpointStatus | AlertStatus;
  risk_score?: number;
  last_seen?: string;
  last_telemetry_at?: string;
  health?: Record<string, unknown>;
  tags?: string[];
  alert_count?: number;
};

export type ThreatIntelIndicator = {
  id: string;
  indicator: string;
  indicator_type: string;
  provider: string;
  severity: Severity;
  confidence: number;
  category: string;
  first_seen_at: string;
  last_seen_at: string;
  expires_at?: string | null;
  context?: Record<string, unknown>;
  related_alerts: number;
};

export type MitreCoverage = {
  technique: string;
  technique_id: string;
  tactic?: string;
  count: number;
  coverage: number;
  alerts: number;
};

export type OverviewStats = {
  alerts: number;
  incidents: number;
  endpoints: number;
};
