"use client";

import Link from "next/link";
import { startTransition, useDeferredValue, useState } from "react";

import { Alert } from "../lib/types";
import { StatusPill } from "./status-pill";

export function AlertsTable({ alerts }: { alerts: Alert[] }) {
  const [filter, setFilter] = useState("all");
  const deferredFilter = useDeferredValue(filter);

  const safeAlerts = Array.isArray(alerts) ? alerts : [];

  const filtered = safeAlerts.filter((alert) => {
    if (deferredFilter === "all") {
      return true;
    }

    if (deferredFilter === "threat") {
      return Boolean(alert.threat_match);
    }

    return alert.severity === deferredFilter || alert.status === deferredFilter;
  });

  return (
    <div className="rounded-3xl border border-white/10 bg-slate-950/60 p-5">
      <div className="mb-5 flex flex-wrap items-center justify-between gap-3">
        <h3 className="text-sm font-semibold uppercase tracking-[0.24em] text-cyan-100/70">
          Alert Queue
        </h3>

        <div className="flex flex-wrap gap-2">
          {["all", "critical", "high", "open", "threat"].map((value) => (
            <button
              key={value}
              type="button"
              onClick={() => startTransition(() => setFilter(value))}
              className={`rounded-full border px-3 py-1 text-xs uppercase tracking-[0.24em] ${
                filter === value
                  ? "border-cyan-300/50 bg-cyan-300/10 text-cyan-100"
                  : "border-white/10 text-slate-400"
              }`}
            >
              {value}
            </button>
          ))}
        </div>
      </div>

      <div className="overflow-x-auto">
        <table className="min-w-full text-left text-sm text-slate-200">
          <thead className="text-xs uppercase tracking-[0.24em] text-slate-500">
            <tr>
              <th className="pb-3 pr-4">Alert</th>
              <th className="pb-3 pr-4">Host</th>
              <th className="pb-3 pr-4">IP</th>
              <th className="pb-3 pr-4">Severity</th>
              <th className="pb-3">Status</th>
            </tr>
          </thead>

          <tbody>
            {filtered.map((alert) => (
              <tr
                key={alert.id}
                className={`border-t border-white/5 ${
                  alert.threat_match
                    ? "bg-red-950/15 hover:bg-red-950/25"
                    : "hover:bg-slate-800/60"
                }`}
              >
                <td className="py-4 pr-4 align-top">
                  <Link
                    href={`/alerts/${alert.id}`}
                    className="font-medium text-cyan-400 hover:underline"
                  >
                    {alert.title}
                  </Link>

                  <p className="mt-2 max-w-md text-xs text-slate-400">
                    {alert.summary?.trim() || "No summary available."}
                  </p>

                  {alert.threat_match ? (
                    <span className="mt-3 inline-flex rounded-full border border-red-400/40 bg-red-500/10 px-2.5 py-1 text-[10px] font-semibold uppercase tracking-[0.22em] text-red-200">
                      malicious ip
                    </span>
                  ) : null}
                </td>

                <td className="py-4 pr-4 align-top text-slate-300">
                  {alert.hostname?.trim() || "-"}
                </td>

                <td className="py-4 pr-4 align-top">
                  <span
                    className={
                      alert.threat_match ? "font-medium text-red-200" : "text-slate-300"
                    }
                  >
                    {alert.ip?.trim() || "-"}
                  </span>
                </td>

                <td className="py-4 pr-4 align-top">
                  <StatusPill value={alert.severity} />
                </td>

                <td className="py-4 align-top">
                  <StatusPill value={alert.status} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
