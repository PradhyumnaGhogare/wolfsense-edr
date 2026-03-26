import Link from "next/link";
import { notFound } from "next/navigation";

import { StatusPill } from "../../../components/status-pill";
import { Timeline } from "../../../components/timeline";
import { getAlertsForEndpoint, getEndpoint } from "../../../lib/api";
import { Alert } from "../../../lib/types";

export const dynamic = "force-dynamic";

export default async function EndpointDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  const [endpoint, alerts] = await Promise.all([
    getEndpoint(id),
    getAlertsForEndpoint(id),
  ]);

  if (!endpoint) {
    notFound();
  }

  const indicators = getIndicators(alerts);

  return (
    <section className="space-y-6">
      <div className="rounded-[2rem] border border-white/10 bg-slate-950/70 p-6">
        <div className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
          <div>
            <p className="text-xs uppercase tracking-[0.32em] text-cyan-100/65">
              Endpoint Detail
            </p>
            <h1 className="mt-4 text-4xl font-semibold text-white">
              {endpoint.hostname?.trim() || endpoint.id}
            </h1>
            <p className="mt-3 max-w-3xl text-sm leading-7 text-slate-300">
              Review endpoint posture, live status, and alert activity without
              leaving the investigation flow.
            </p>
          </div>

          <div className="flex flex-wrap gap-3">
            <StatusPill value={endpoint.status} />
          </div>
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-6">
        <InfoCard label="Endpoint ID" value={endpoint.id} />
        <InfoCard label="IP" value={endpoint.ip?.trim() || endpoint.last_seen_ip?.trim() || "-"} />
        <InfoCard label="Owner" value={endpoint.owner?.trim() || "unassigned"} />
        <InfoCard label="Operating System" value={endpoint.os?.trim() || endpoint.os_version?.trim() || "-"} />
        <InfoCard label="Last Seen" value={formatDateTime(endpoint.last_seen ?? endpoint.last_telemetry_at)} />
        <InfoCard label="Open Alerts" value={String(endpoint.alert_count ?? alerts.length)} />
      </div>

      <div className="grid gap-6 xl:grid-cols-[1fr_0.85fr]">
        <Timeline alerts={alerts} />

        <div className="space-y-6">
          <section className="rounded-3xl border border-white/10 bg-slate-950/60 p-6">
            <p className="text-xs uppercase tracking-[0.24em] text-cyan-100/70">
              Endpoint Posture
            </p>
            <h2 className="mt-3 text-2xl font-semibold text-white">
              Asset context
            </h2>

            <div className="mt-5 grid gap-4">
              <InfoBlock
                label="Status"
                value={endpoint.status?.trim() || "unknown"}
              />
              <InfoBlock
                label="Agent Version"
                value={endpoint.agent_version?.trim() || "-"}
              />
              <InfoBlock
                label="Risk Score"
                value={String(endpoint.risk_score ?? 0)}
              />
              <InfoBlock
                label="Tags"
                value={endpoint.tags?.length ? endpoint.tags.join(", ") : "No tags"}
              />
            </div>
          </section>

          <section className="rounded-3xl border border-white/10 bg-slate-950/60 p-6">
            <p className="text-xs uppercase tracking-[0.24em] text-cyan-100/70">
              Indicators
            </p>
            <h2 className="mt-3 text-2xl font-semibold text-white">
              Observed activity
            </h2>

            <div className="mt-5 grid gap-4">
              <IndicatorBlock
                label="Observed IPs"
                values={indicators.ips}
                emptyLabel="No IP indicators captured."
              />
              <IndicatorBlock
                label="Processes"
                values={indicators.processes}
                emptyLabel="No processes captured."
              />
            </div>
          </section>
        </div>
      </div>

      <section className="rounded-3xl border border-white/10 bg-slate-950/60 p-6">
        <div className="flex items-center justify-between gap-3">
          <div>
            <p className="text-xs uppercase tracking-[0.24em] text-cyan-100/70">
              Related Alerts
            </p>
            <h2 className="mt-3 text-2xl font-semibold text-white">
              Detection history
            </h2>
          </div>
          <Link
            href="/alerts"
            className="text-sm font-medium text-cyan-300 transition hover:text-cyan-200"
          >
            View alert queue
          </Link>
        </div>

        <div className="mt-5 grid gap-4">
          {alerts.length === 0 ? (
            <div className="rounded-2xl border border-dashed border-white/10 bg-white/5 p-5 text-sm text-slate-300">
              No alerts are currently associated with this endpoint.
            </div>
          ) : null}

          {alerts.map((alert) => (
            <Link
              key={alert.id}
              href={`/alerts/${alert.id}`}
              className={`rounded-2xl border p-4 transition ${
                alert.threat_match
                  ? "border-red-400/20 bg-red-950/10 hover:bg-red-950/20"
                  : "border-white/10 bg-white/5 hover:border-cyan-300/35 hover:bg-cyan-300/8"
              }`}
            >
              <div className="flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
                <div>
                  <div className="flex flex-wrap items-center gap-3">
                    <h3 className="text-lg font-semibold text-white">
                      {alert.title}
                    </h3>
                    <StatusPill value={alert.severity} />
                    {alert.threat_match ? (
                      <span className="inline-flex rounded-full border border-red-400/40 bg-red-500/10 px-2.5 py-1 text-[10px] font-semibold uppercase tracking-[0.22em] text-red-200">
                        malicious ip
                      </span>
                    ) : null}
                  </div>

                  <p className="mt-3 text-sm text-slate-300">
                    {alert.summary?.trim() || "No alert summary available."}
                  </p>

                  <div className="mt-4 grid gap-3 text-sm text-slate-300 md:grid-cols-3">
                    <MetaCell label="Process" value={getProcessName(alert)} />
                    <MetaCell label="IP" value={alert.ip?.trim() || "-"} />
                    <MetaCell
                      label="Occurred"
                      value={formatDateTime(alert.occurred_at)}
                    />
                  </div>
                </div>

                <div className="flex gap-3">
                  <StatusPill value={alert.status} />
                </div>
              </div>
            </Link>
          ))}
        </div>
      </section>
    </section>
  );
}

function InfoCard({
  label,
  value,
}: {
  label: string;
  value: string;
}) {
  return (
    <div className="rounded-xl border border-white/10 bg-slate-950/60 p-4">
      <p className="text-xs uppercase tracking-[0.22em] text-slate-500">
        {label}
      </p>
      <p className="mt-2 break-words text-base font-semibold text-white">
        {value}
      </p>
    </div>
  );
}

function InfoBlock({
  label,
  value,
}: {
  label: string;
  value: string;
}) {
  return (
    <div className="rounded-2xl border border-white/10 bg-white/5 p-4">
      <p className="text-xs uppercase tracking-[0.22em] text-slate-500">
        {label}
      </p>
      <p className="mt-2 break-words text-sm leading-6 text-slate-200">
        {value}
      </p>
    </div>
  );
}

function IndicatorBlock({
  label,
  values,
  emptyLabel,
}: {
  label: string;
  values: string[];
  emptyLabel: string;
}) {
  return (
    <div className="rounded-2xl border border-white/10 bg-white/5 p-4">
      <p className="text-xs uppercase tracking-[0.22em] text-slate-500">
        {label}
      </p>
      <div className="mt-3 flex flex-wrap gap-2">
        {values.length === 0 ? (
          <span className="text-sm text-slate-300">{emptyLabel}</span>
        ) : (
          values.map((value) => (
            <span
              key={value}
              className="inline-flex rounded-full border border-white/10 bg-slate-950 px-3 py-1 text-xs font-medium text-slate-200"
            >
              {value}
            </span>
          ))
        )}
      </div>
    </div>
  );
}

function MetaCell({
  label,
  value,
}: {
  label: string;
  value: string;
}) {
  return (
    <div>
      <p className="text-xs uppercase tracking-[0.22em] text-slate-500">
        {label}
      </p>
      <p className="mt-1 break-words">{value}</p>
    </div>
  );
}

function getIndicators(alerts: Alert[]) {
  return {
    ips: uniqueValues(alerts.map((alert) => alert.ip?.trim() || "")),
    processes: uniqueValues(alerts.map((alert) => getProcessName(alert))),
  };
}

function uniqueValues(values: string[]) {
  return [...new Set(values.filter((value) => value.trim()))].slice(0, 8);
}

function getProcessName(alert: Alert) {
  return (
    alert.process?.trim() ||
    alert.process_name?.trim() ||
    "Process unavailable"
  );
}

function formatDateTime(value?: string | null) {
  if (!value) {
    return "-";
  }

  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return "-";
  }

  return date.toLocaleString();
}
