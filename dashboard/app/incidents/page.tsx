import Link from "next/link";

import { StatusPill } from "../../components/status-pill";
import { getIncidents } from "../../lib/api";
import { Incident } from "../../lib/types";

export const dynamic = "force-dynamic";

export default async function IncidentsPage() {
  const incidents = await getIncidents();

  return (
    <section className="space-y-6">
      <div className="rounded-[2rem] border border-white/10 bg-slate-950/70 p-6">
        <p className="text-xs uppercase tracking-[0.32em] text-cyan-100/65">
          Incidents
        </p>
        <h1 className="mt-4 text-4xl font-semibold text-white">
          Investigation queue
        </h1>
        <p className="mt-3 max-w-3xl text-sm leading-7 text-slate-300">
          Review active cases, prioritize severity, and pivot from correlated
          incidents into the full alert and endpoint investigation workflow.
        </p>
      </div>

      <div className="grid gap-5">
        {incidents.length === 0 ? (
          <div className="rounded-3xl border border-white/10 bg-slate-950/60 p-5 text-sm text-slate-300">
            No incidents are currently available.
          </div>
        ) : null}

        {incidents.map((incident) => (
          <Link
            key={incident.id}
            href={`/incidents/${incident.id}`}
            className="group rounded-3xl border border-white/10 bg-slate-950/60 p-5 transition hover:border-cyan-300/40 hover:bg-cyan-300/8"
          >
            <div className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
              <div>
                <div className="flex flex-wrap items-center gap-3">
                  <p className="text-xs uppercase tracking-[0.24em] text-slate-500">
                    {formatDateTime(incident.updated_at || incident.created_at)}
                  </p>
                  <span className="text-slate-700">|</span>
                  <p className="text-xs uppercase tracking-[0.24em] text-slate-500">
                    {incident.id}
                  </p>
                </div>

                <div className="mt-3 flex flex-wrap items-center gap-3">
                  <h2 className="text-xl font-semibold text-white">
                    {getIncidentTitle(incident)}
                  </h2>
                  <StatusPill value={incident.severity} />
                </div>

                <p className="mt-3 max-w-3xl text-sm leading-7 text-slate-300">
                  {incident.summary?.trim() ||
                    incident.hostname?.trim() ||
                    "No incident summary available."}
                </p>

                <div className="mt-4 flex flex-wrap gap-4 text-sm text-slate-400">
                  <span>
                    Host:{" "}
                    <span className="font-medium text-slate-200">
                      {incident.hostname?.trim() || "-"}
                    </span>
                  </span>
                  <span>
                    Analyst:{" "}
                    <span className="font-medium text-slate-200">
                      {incident.analyst_owner?.trim() || "unassigned"}
                    </span>
                  </span>
                  <span>
                    Alerts:{" "}
                    <span className="font-medium text-slate-200">
                      {incident.alert_count ?? 0}
                    </span>
                  </span>
                </div>
              </div>

              <div className="flex items-center gap-3 self-start">
                <StatusPill value={incident.status} />
                <span className="text-sm font-medium text-cyan-100 transition group-hover:text-cyan-50">
                  Open case
                </span>
              </div>
            </div>
          </Link>
        ))}
      </div>
    </section>
  );
}

function getIncidentTitle(incident: Incident) {
  return (
    incident.title?.trim() ||
    (incident.hostname?.trim()
      ? `Investigation on ${incident.hostname}`
      : `Incident ${incident.id}`)
  );
}

function formatDateTime(value?: string) {
  if (!value) {
    return "Time unavailable";
  }

  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return "Time unavailable";
  }

  return date.toLocaleString();
}
