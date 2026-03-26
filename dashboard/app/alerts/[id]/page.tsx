import Link from "next/link";
import { notFound } from "next/navigation";

import { ProcessTree } from "@/components/process-tree";
import { StatusPill } from "@/components/status-pill";
import { getAlertById } from "@/lib/api";

export const dynamic = "force-dynamic";

export default async function AlertDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  const alert = await getAlertById(id);

  if (!alert) {
    notFound();
  }

  const timelineEvents = buildTimeline(alert);
  const processTree = alert.process_tree ?? [];

  return (
    <section className="space-y-6">
      <div className="rounded-[2rem] border border-white/10 bg-slate-950/70 p-6">
        <div className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
          <div>
            <p className="text-xs uppercase tracking-[0.32em] text-cyan-100/65">
              Alert Detail
            </p>
            <h1 className="mt-4 text-4xl font-semibold text-white">
              {alert.title}
            </h1>
            <p className="mt-3 max-w-3xl text-sm leading-7 text-slate-300">
              {alert.summary?.trim() || "No alert summary available."}
            </p>
          </div>

          <div className="flex flex-wrap gap-3">
            <StatusPill value={alert.severity} />
            <StatusPill value={alert.status} />
            {alert.threat_match ? (
              <span className="inline-flex rounded-full border border-red-400/40 bg-red-500/10 px-2.5 py-1 text-[10px] font-semibold uppercase tracking-[0.22em] text-red-200">
                malicious ip
              </span>
            ) : null}
          </div>
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-6">
        <InfoCard label="Hostname" value={alert.hostname?.trim() || "-"} />
        <InfoCard label="Process" value={getProcessName(alert)} />
        <InfoCard label="IP" value={alert.ip?.trim() || "-"} />
        <InfoCard
          label="MITRE Technique"
          value={formatMitre(alert.mitre_technique_id, alert.mitre_technique)}
        />
        <InfoCard label="Occurred At" value={formatDateTime(alert.occurred_at)} />
        <InfoCard label="Alert ID" value={alert.id} />
      </div>

      <div className="grid gap-6 xl:grid-cols-[1.1fr_0.9fr]">
        <div className="space-y-6">
          <section className="rounded-3xl border border-white/10 bg-slate-950/60 p-6">
            <p className="text-xs uppercase tracking-[0.24em] text-cyan-100/70">
              Command Line
            </p>
            <h2 className="mt-3 text-2xl font-semibold text-white">
              Execution detail
            </h2>

            <div className="mt-5 rounded-2xl border border-white/10 bg-slate-950/80 p-4 font-mono text-sm text-slate-200">
              <pre className="whitespace-pre-wrap break-words">
                {alert.command_line?.trim() || "No command line captured."}
              </pre>
            </div>
          </section>

          {processTree.length > 0 ? (
            <ProcessTree nodes={processTree} />
          ) : (
            <section className="rounded-3xl border border-white/10 bg-slate-950/60 p-6">
              <p className="text-xs uppercase tracking-[0.24em] text-cyan-100/70">
                Process Lineage
              </p>
              <div className="mt-5 rounded-2xl border border-dashed border-white/10 bg-white/5 p-4 text-sm text-slate-300">
                No process tree was captured for this alert.
              </div>
            </section>
          )}

          <JsonBlock title="Process Tree JSON" value={processTree} />
        </div>

        <div className="space-y-6">
          <section className="rounded-3xl border border-white/10 bg-slate-950/60 p-6">
            <p className="text-xs uppercase tracking-[0.24em] text-cyan-100/70">
              Investigation Context
            </p>
            <h2 className="mt-3 text-2xl font-semibold text-white">
              Alert metadata
            </h2>

            <div className="mt-5 grid gap-4">
              <InfoBlock
                label="Summary"
                value={alert.summary?.trim() || "No summary available."}
              />
              <InfoBlock label="Detector" value={alert.detector?.trim() || "-"} />
              <InfoBlock label="Hostname" value={alert.hostname?.trim() || "-"} />
              <InfoBlock label="Process" value={getProcessName(alert)} />
              <InfoBlock
                label="MITRE"
                value={formatMitre(alert.mitre_technique_id, alert.mitre_technique)}
              />

              {alert.incident_id ? (
                <div className="rounded-2xl border border-white/10 bg-white/5 p-4">
                  <p className="text-xs uppercase tracking-[0.22em] text-slate-500">
                    Incident
                  </p>
                  <Link
                    href={`/incidents/${alert.incident_id}`}
                    className="mt-2 inline-flex text-sm font-medium text-cyan-300 transition hover:text-cyan-200"
                  >
                    Open incident {alert.incident_id}
                  </Link>
                </div>
              ) : null}
            </div>
          </section>

          <section className="rounded-3xl border border-white/10 bg-slate-950/60 p-6">
            <p className="text-xs uppercase tracking-[0.24em] text-cyan-100/70">
              Event Timeline
            </p>
            <h2 className="mt-3 text-2xl font-semibold text-white">
              Detection sequence
            </h2>

            <div className="relative mt-6 space-y-5 pl-8 before:absolute before:left-[11px] before:top-1 before:h-[calc(100%-8px)] before:w-px before:bg-gradient-to-b before:from-cyan-300/50 before:via-cyan-200/20 before:to-transparent">
              {timelineEvents.map((event, index) => (
                <article key={`${event.title}-${index}`} className="relative">
                  <span className="absolute -left-8 top-5 flex h-6 w-6 items-center justify-center rounded-full border border-cyan-300/40 bg-slate-950">
                    <span className="h-2 w-2 rounded-full bg-cyan-200" />
                  </span>

                  <div className="rounded-2xl border border-white/10 bg-white/[0.03] p-4">
                    <p className="text-xs uppercase tracking-[0.22em] text-slate-500">
                      {event.time}
                    </p>
                    <h3 className="mt-2 text-lg font-semibold text-white">
                      {event.title}
                    </h3>
                    <p className="mt-2 text-sm leading-6 text-slate-300">
                      {event.detail}
                    </p>
                  </div>
                </article>
              ))}
            </div>
          </section>

          <JsonBlock title="Evidence JSON" value={alert.evidence ?? {}} />
          <JsonBlock title="Enrichment JSON" value={alert.enrichment ?? {}} />
        </div>
      </div>
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

function JsonBlock({
  title,
  value,
}: {
  title: string;
  value: unknown;
}) {
  return (
    <section className="rounded-3xl border border-white/10 bg-slate-950/60 p-6">
      <p className="text-xs uppercase tracking-[0.24em] text-cyan-100/70">
        {title}
      </p>
      <div className="mt-5 rounded-2xl border border-white/10 bg-slate-950/80 p-4 font-mono text-sm text-slate-200">
        <pre className="whitespace-pre-wrap break-words">
          {JSON.stringify(value ?? {}, null, 2)}
        </pre>
      </div>
    </section>
  );
}

function buildTimeline(alert: {
  occurred_at?: string;
  hostname?: string;
  process?: string;
  process_name?: string;
  mitre_technique_id?: string;
  mitre_technique?: string;
  threat_match?: boolean;
  incident_id?: string | null;
}) {
  const events = [
    {
      title: "Alert observed",
      detail: `${getProcessName(alert)} executed on ${alert.hostname?.trim() || "an unknown host"}.`,
      time: formatDateTime(alert.occurred_at),
    },
  ];

  if (alert.mitre_technique_id || alert.mitre_technique) {
    events.push({
      title: "MITRE technique mapped",
      detail: formatMitre(alert.mitre_technique_id, alert.mitre_technique),
      time: formatDateTime(alert.occurred_at),
    });
  }

  if (alert.threat_match) {
    events.push({
      title: "Threat intelligence correlation",
      detail: "The alert IP matched a known malicious indicator.",
      time: formatDateTime(alert.occurred_at),
    });
  }

  if (alert.incident_id) {
    events.push({
      title: "Incident association",
      detail: `The alert was correlated into incident ${alert.incident_id}.`,
      time: formatDateTime(alert.occurred_at),
    });
  }

  return events;
}

function getProcessName(alert: {
  process?: string;
  process_name?: string;
}) {
  return (
    alert.process?.trim() ||
    alert.process_name?.trim() ||
    "Process unavailable"
  );
}

function formatMitre(techniqueId?: string, technique?: string) {
  if (techniqueId && technique) {
    return `${techniqueId} - ${technique}`;
  }

  return techniqueId || technique || "-";
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
