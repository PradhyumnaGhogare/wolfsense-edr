import {
  AlertStatus,
  EndpointStatus,
  IncidentStatus,
  Severity,
} from "../lib/types";

type StatusValue = Severity | AlertStatus | IncidentStatus | EndpointStatus;

const toneMap: Record<StatusValue, string> = {
  critical: "border-red-500/50 bg-red-500/10 text-red-200",
  high: "border-red-500/50 bg-red-500/10 text-red-200",
  medium: "border-yellow-400/50 bg-yellow-400/10 text-yellow-100",
  low: "border-blue-400/50 bg-blue-400/10 text-blue-100",
  open: "border-red-500/50 bg-red-500/10 text-red-200",
  investigating: "border-cyan-400/50 bg-cyan-400/10 text-cyan-100",
  resolved: "border-emerald-400/50 bg-emerald-400/10 text-emerald-100",
  closed: "border-zinc-500/50 bg-zinc-500/10 text-zinc-100",
  contained: "border-lime-400/50 bg-lime-400/10 text-lime-100",
  online: "border-emerald-400/50 bg-emerald-400/10 text-emerald-100",
  degraded: "border-amber-300/50 bg-amber-300/10 text-amber-100",
  offline: "border-zinc-500/50 bg-zinc-500/10 text-zinc-100",
};

export function StatusPill({ value }: { value?: StatusValue | string | null }) {
  const normalizedValue = value?.toLowerCase() ?? "unknown";
  const tone =
    toneMap[normalizedValue as StatusValue] ??
    "border-white/10 bg-white/5 text-slate-200";

  return (
    <span
      className={`inline-flex rounded-full border px-2.5 py-1 text-[10px] font-semibold uppercase tracking-[0.24em] ${tone}`}
    >
      {normalizedValue}
    </span>
  );
}
