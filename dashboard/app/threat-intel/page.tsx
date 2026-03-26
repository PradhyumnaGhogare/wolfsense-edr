import Link from "next/link";

import { AlertsTable } from "../../components/alerts-table";
import { StatusPill } from "../../components/status-pill";
import { getAlerts, getThreatIntel } from "../../lib/api";

export const dynamic = "force-dynamic";

export default async function ThreatIntelPage() {
  const [indicators, alerts] = await Promise.all([getThreatIntel(), getAlerts()]);
  const matchedAlerts = alerts.filter((alert) => alert.threat_match);

  return (
    <section className="space-y-6">
      <div className="rounded-[2rem] border border-white/10 bg-slate-950/70 p-6">
        <p className="text-xs uppercase tracking-[0.32em] text-cyan-100/65">
          Threat Intelligence
        </p>
        <h1 className="mt-4 text-4xl font-semibold text-white">
          Malicious indicator watchlist
        </h1>
        <p className="mt-3 max-w-3xl text-sm leading-7 text-slate-300">
          Review active intelligence matches, validate malicious IPs, and pivot
          directly into alerts that intersect with known hostile infrastructure.
        </p>
      </div>

      <div className="grid gap-4 md:grid-cols-3">
        <SummaryCard
          label="Indicators"
          value={String(indicators.length)}
          detail="Tracked indicators available to enrich detections."
        />
        <SummaryCard
          label="Matched Alerts"
          value={String(matchedAlerts.length)}
          detail="Alerts currently intersecting with threat intelligence."
        />
        <SummaryCard
          label="Critical IOCs"
          value={String(indicators.filter((item) => item.severity === "critical").length)}
          detail="Indicators requiring immediate analyst attention."
        />
      </div>

      <div className="grid gap-4">
        {indicators.length === 0 ? (
          <div className="rounded-3xl border border-white/10 bg-slate-950/60 p-5 text-sm text-slate-300">
            No threat intelligence indicators are available.
          </div>
        ) : null}

        {indicators.map((indicator) => (
          <article
            key={indicator.id}
            className="rounded-3xl border border-white/10 bg-slate-950/60 p-5"
          >
            <div className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
              <div>
                <div className="flex flex-wrap items-center gap-3">
                  <h2 className="text-xl font-semibold text-white">
                    {indicator.indicator}
                  </h2>
                  <StatusPill value={indicator.severity} />
                </div>

                <div className="mt-3 flex flex-wrap gap-3 text-xs uppercase tracking-[0.22em] text-slate-500">
                  <span>{indicator.provider}</span>
                  <span>{indicator.indicator_type}</span>
                  <span>{indicator.category}</span>
                </div>

                <p className="mt-4 text-sm text-slate-300">
                  Confidence {indicator.confidence}% with{" "}
                  {indicator.related_alerts} related alert
                  {indicator.related_alerts === 1 ? "" : "s"}.
                </p>

                <div className="mt-4 rounded-2xl border border-red-400/20 bg-red-500/10 p-4">
                  <p className="text-xs uppercase tracking-[0.22em] text-red-200/80">
                    Warning
                  </p>
                  <p className="mt-2 text-sm leading-6 text-red-100">
                    Malicious IP activity is flagged across the platform for
                    this indicator. Investigate any associated alert stream
                    immediately.
                  </p>
                </div>
              </div>

              <div className="grid gap-3 text-sm text-slate-300 xl:min-w-72">
                <MetaRow
                  label="First Seen"
                  value={formatDateTime(indicator.first_seen_at)}
                />
                <MetaRow
                  label="Last Seen"
                  value={formatDateTime(indicator.last_seen_at)}
                />
                <MetaRow
                  label="Expires"
                  value={formatDateTime(indicator.expires_at)}
                />
              </div>
            </div>
          </article>
        ))}
      </div>

      <div className="rounded-3xl border border-white/10 bg-slate-950/60 p-5">
        <div className="mb-5 flex items-center justify-between gap-3">
          <div>
            <p className="text-xs uppercase tracking-[0.24em] text-cyan-100/70">
              Matched Alerts
            </p>
            <h2 className="mt-3 text-2xl font-semibold text-white">
              Alert intersections
            </h2>
          </div>
          <Link
            href="/alerts"
            className="text-sm font-medium text-cyan-300 transition hover:text-cyan-200"
          >
            View alert queue
          </Link>
        </div>

        {matchedAlerts.length === 0 ? (
          <div className="rounded-2xl border border-dashed border-white/10 bg-white/5 p-4 text-sm text-slate-300">
            No alerts are currently mapped to malicious IP intelligence.
          </div>
        ) : (
          <AlertsTable alerts={matchedAlerts} />
        )}
      </div>
    </section>
  );
}

function SummaryCard({
  label,
  value,
  detail,
}: {
  label: string;
  value: string;
  detail: string;
}) {
  return (
    <div className="rounded-3xl border border-white/10 bg-slate-950/60 p-5">
      <p className="text-xs uppercase tracking-[0.24em] text-cyan-100/70">
        {label}
      </p>
      <p className="mt-4 text-4xl font-semibold text-white">{value}</p>
      <p className="mt-3 text-sm leading-6 text-slate-300">{detail}</p>
    </div>
  );
}

function MetaRow({
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
      <p className="mt-2 break-words text-sm font-medium text-white">{value}</p>
    </div>
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
