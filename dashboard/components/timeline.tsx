import { Alert } from "../lib/types";
import { StatusPill } from "./status-pill";

export function Timeline({ alerts }: { alerts: Alert[] }) {
  const sortedAlerts = [...alerts].sort(sortAlertsAscending);

  return (
    <div className="rounded-3xl border border-white/10 bg-slate-950/60 p-6">
      <div className="flex items-center justify-between gap-3">
        <div>
          <p className="text-xs uppercase tracking-[0.24em] text-cyan-100/70">
            Timeline
          </p>
          <h2 className="mt-3 text-2xl font-semibold text-white">
            Investigation sequence
          </h2>
        </div>
        <span className="text-xs uppercase tracking-[0.24em] text-slate-500">
          {sortedAlerts.length} event{sortedAlerts.length === 1 ? "" : "s"}
        </span>
      </div>

      {sortedAlerts.length === 0 ? (
        <div className="mt-6 rounded-2xl border border-dashed border-white/10 bg-white/5 p-5 text-sm text-slate-300">
          No events are available for this timeline yet.
        </div>
      ) : (
        <div className="relative mt-8 space-y-5 pl-8 before:absolute before:left-[11px] before:top-1 before:h-[calc(100%-8px)] before:w-px before:bg-gradient-to-b before:from-cyan-300/50 before:via-cyan-200/20 before:to-transparent">
          {sortedAlerts.map((alert) => (
            <article key={alert.id} className="relative">
              <span className="absolute -left-8 top-5 flex h-6 w-6 items-center justify-center rounded-full border border-cyan-300/40 bg-slate-950 shadow-[0_0_24px_rgba(34,211,238,0.18)]">
                <span className="h-2 w-2 rounded-full bg-cyan-200" />
              </span>

              <div className="rounded-2xl border border-white/10 bg-white/[0.03] p-4">
                <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
                  <div>
                    <p className="text-xs uppercase tracking-[0.24em] text-slate-500">
                      {formatDateTime(alert.occurred_at)}
                    </p>
                    <h3 className="mt-2 text-lg font-semibold text-white">
                      {alert.title}
                    </h3>
                  </div>
                  <StatusPill value={alert.severity} />
                </div>

                <div className="mt-4 grid gap-3 text-sm text-slate-300 md:grid-cols-2">
                  <div>
                    <p className="text-xs uppercase tracking-[0.22em] text-slate-500">
                      Process
                    </p>
                    <p className="mt-1 break-words">{getProcessName(alert)}</p>
                  </div>
                  <div>
                    <p className="text-xs uppercase tracking-[0.22em] text-slate-500">
                      Host
                    </p>
                    <p className="mt-1 break-words">
                      {alert.hostname?.trim() || "Unknown host"}
                    </p>
                  </div>
                </div>
              </div>
            </article>
          ))}
        </div>
      )}
    </div>
  );
}

function getProcessName(alert: Alert) {
  return (
    alert.process?.trim() ||
    alert.process_name?.trim() ||
    "Process unavailable"
  );
}

function sortAlertsAscending(left: Alert, right: Alert) {
  return getTimestamp(left.occurred_at) - getTimestamp(right.occurred_at);
}

function getTimestamp(value?: string | null) {
  if (!value) {
    return 0;
  }

  const timestamp = new Date(value).getTime();
  return Number.isNaN(timestamp) ? 0 : timestamp;
}

function formatDateTime(value?: string | null) {
  if (!value) {
    return "Time unavailable";
  }

  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return "Time unavailable";
  }

  return date.toLocaleString();
}
