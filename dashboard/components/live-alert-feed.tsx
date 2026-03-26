"use client";

import { useEffect, useEffectEvent, useState } from "react";

import { Alert } from "../lib/types";
import { StatusPill } from "./status-pill";

export function LiveAlertFeed({ alerts }: { alerts: Alert[] }) {
  const [index, setIndex] = useState(0);

  const rotate = useEffectEvent(() => {
    setIndex((current) => (alerts.length === 0 ? 0 : (current + 1) % alerts.length));
  });

  useEffect(() => {
    const timer = window.setInterval(() => rotate(), 2500);
    return () => window.clearInterval(timer);
  }, []);

  const active = alerts[index];
  if (!active) {
    return null;
  }

  return (
    <div className="rounded-3xl border border-white/10 bg-slate-950/60 p-5">
      <div className="flex items-center justify-between gap-3">
        <h3 className="text-sm font-semibold uppercase tracking-[0.24em] text-cyan-100/70">
          Live Alert Stream
        </h3>
        <div className="flex gap-2">
          <StatusPill value={active.severity} />
          {active.threat_match ? (
            <span className="inline-flex rounded-full border border-red-400/40 bg-red-500/10 px-2.5 py-1 text-[10px] font-semibold uppercase tracking-[0.22em] text-red-200">
              threat intel
            </span>
          ) : null}
        </div>
      </div>

      <p className="mt-4 text-xl font-semibold text-white">{active.title}</p>
      <p className="mt-2 text-sm text-slate-300">
        {active.summary?.trim() || "No summary available."}
      </p>

      <div className="mt-4 grid gap-3 text-sm text-slate-300 md:grid-cols-4">
        <div>
          <p className="text-xs uppercase tracking-[0.24em] text-slate-500">Host</p>
          <p className="mt-1">{active.hostname?.trim() || "-"}</p>
        </div>
        <div>
          <p className="text-xs uppercase tracking-[0.24em] text-slate-500">Process</p>
          <p className="mt-1">{active.process_name?.trim() || active.process?.trim() || "-"}</p>
        </div>
        <div>
          <p className="text-xs uppercase tracking-[0.24em] text-slate-500">IP</p>
          <p className="mt-1">{active.ip?.trim() || "-"}</p>
        </div>
        <div>
          <p className="text-xs uppercase tracking-[0.24em] text-slate-500">MITRE</p>
          <p className="mt-1">{active.mitre_technique_id || "-"}</p>
        </div>
      </div>
    </div>
  );
}
