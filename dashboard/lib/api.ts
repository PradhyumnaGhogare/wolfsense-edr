import {
  Alert,
  Endpoint,
  Incident,
  MitreCoverage,
  OverviewStats,
  ThreatIntelIndicator,
} from "./types";

const API = process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://127.0.0.1:8080";

async function fetchJson<T>(path: string): Promise<T | null> {
  try {
    const res = await fetch(`${API}${path}`, {
      cache: "no-store",
    });

    if (!res.ok) {
      console.error("API error:", res.status, path);
      return null;
    }

    return (await res.json()) as T;
  } catch (err) {
    console.error("Fetch failed:", err);
    return null;
  }
}

function withQuery(path: string, query: Record<string, string | undefined>) {
  const params = new URLSearchParams();

  Object.entries(query).forEach(([key, value]) => {
    if (value?.trim()) {
      params.set(key, value.trim());
    }
  });

  const encoded = params.toString();
  return encoded ? `${path}?${encoded}` : path;
}

export async function getOverviewStats(): Promise<OverviewStats> {
  return (
    (await fetchJson<OverviewStats>("/stats/overview")) ?? {
      alerts: 0,
      incidents: 0,
      endpoints: 0,
    }
  );
}

export async function getAlerts(filters?: {
  endpointId?: string;
  incidentId?: string;
}): Promise<Alert[]> {
  const path = withQuery("/alerts", {
    endpoint_id: filters?.endpointId,
    incident_id: filters?.incidentId,
  });

  return (await fetchJson<Alert[]>(path)) ?? [];
}

export async function getAlertById(id: string): Promise<Alert | null> {
  const safeId = id.trim();
  if (!safeId) {
    return null;
  }

  const alert = await fetchJson<Alert>(`/alerts/${safeId}`);
  if (alert) {
    return alert;
  }

  const alerts = await getAlerts();
  return alerts.find((item) => item.id === safeId) ?? null;
}

export async function getAlertsForEndpoint(endpointId: string): Promise<Alert[]> {
  const safeEndpointId = endpointId.trim();
  if (!safeEndpointId) {
    return [];
  }

  return getAlerts({ endpointId: safeEndpointId });
}

export async function getIncidents(): Promise<Incident[]> {
  return (await fetchJson<Incident[]>("/incidents")) ?? [];
}

export async function getIncidentById(id: string): Promise<Incident | null> {
  const safeId = id.trim();
  if (!safeId) {
    return null;
  }

  const incident = await fetchJson<Incident>(`/incidents/${safeId}`);
  if (incident) {
    return incident;
  }

  const incidents = await getIncidents();
  return incidents.find((item) => item.id === safeId) ?? null;
}

export async function getEndpoints(query?: string, owner?: string): Promise<Endpoint[]> {
  const path = withQuery("/endpoints", {
    q: query,
    owner,
  });

  return (await fetchJson<Endpoint[]>(path)) ?? [];
}

export async function getEndpoint(id: string): Promise<Endpoint | null> {
  const safeId = id.trim();
  if (!safeId) {
    return null;
  }

  return fetchJson<Endpoint>(`/endpoints/${safeId}`);
}

export async function getThreatIntel(): Promise<ThreatIntelIndicator[]> {
  return (await fetchJson<ThreatIntelIndicator[]>("/threat-intel")) ?? [];
}

export async function getMitreCoverage(): Promise<MitreCoverage[]> {
  return (await fetchJson<MitreCoverage[]>("/mitre/coverage")) ?? [];
}
