import Link from "next/link";

import { AlertsTable } from "../components/alerts-table";
import { LiveAlertFeed } from "../components/live-alert-feed";
import { StatusPill } from "../components/status-pill";
import { SummaryCard } from "../components/summary-card";
import { getAlerts, getIncidents, getOverviewStats } from "../lib/api";

export const dynamic = "force-dynamic";

export default async function OverviewPage() {
  const [stats, alerts, incidents] = await Promise.all([
    getOverviewStats(),
    getAlerts(),
    getIncidents(),
  ]);

  const recentAlerts = alerts.slice(0, 10);
  const recentIncidents = incidents.slice(0, 4);

  return (
    <section className="space-y-6">
      <div className="rounded-[2rem] border border-white/10 bg-slate-950/70 p-6">
        <p className="text-xs uppercase tracking-[0.32em] text-cyan-100/65">
          Overview
        </p>
        <h1 className="mt-4 text-4xl font-semibold text-white">
          SOC operations command
        </h1>
        <p className="mt-3 max-w-3xl text-sm leading-7 text-slate-300">
          Monitor enterprise detections, triage active incidents, and pivot from
          telemetry to investigation without leaving the dashboard.
        </p>
      </div>

      <div className="grid gap-4 md:grid-cols-3">
        <SummaryCard
          label="Alerts"
          value={stats.alerts}
          detail="Detections currently indexed by the platform."
        />
        <SummaryCard
          label="Incidents"
          value={stats.incidents}
          detail="Correlated investigations requiring analyst attention."
        />
        <SummaryCard
          label="Endpoints"
          value={stats.endpoints}
          detail="Managed systems currently reporting into the SOC."
        />
      </div>

      <div className="grid gap-6 xl:grid-cols-[1.2fr_0.8fr]">
        <LiveAlertFeed alerts={recentAlerts} />

        <div className="rounded-3xl border border-white/10 bg-slate-950/60 p-5">
          <div className="flex items-center justify-between gap-3">
            <div>
              <p className="text-xs uppercase tracking-[0.24em] text-cyan-100/70">
                Active Incidents
              </p>
              <h2 className="mt-3 text-2xl font-semibold text-white">
                Investigation queue
              </h2>
            </div>
            <Link
              href="/incidents"
              className="text-sm font-medium text-cyan-300 transition hover:text-cyan-200"
            >
              View all
            </Link>
          </div>

          <div className="mt-5 grid gap-4">
            {recentIncidents.length === 0 ? (
              <div className="rounded-2xl border border-dashed border-white/10 bg-white/5 p-4 text-sm text-slate-300">
                No incidents are currently open.
              </div>
            ) : null}

            {recentIncidents.map((incident) => (
              <Link
                key={incident.id}
                href={`/incidents/${incident.id}`}
                className="rounded-2xl border border-white/10 bg-white/5 p-4 transition hover:border-cyan-300/35 hover:bg-cyan-300/8"
              >
                <div className="flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
                  <div>
                    <h3 className="text-lg font-semibold text-white">
                      {incident.title || `Incident ${incident.id}`}
                    </h3>
                    <p className="mt-2 text-sm text-slate-300">
                      {incident.summary?.trim() ||
                        incident.hostname?.trim() ||
                        "No incident summary available."}
                    </p>
                    <p className="mt-3 text-xs uppercase tracking-[0.22em] text-slate-500">
                      {incident.alert_count ?? 0} alert
                      {(incident.alert_count ?? 0) === 1 ? "" : "s"} linked
                    </p>
                  </div>

                  <div className="flex gap-2">
                    <StatusPill value={incident.severity} />
                    <StatusPill value={incident.status} />
                  </div>
                </div>
              </Link>
            ))}
          </div>
        </div>
      </div>

      <AlertsTable alerts={recentAlerts} />
    </section>
  );
}
