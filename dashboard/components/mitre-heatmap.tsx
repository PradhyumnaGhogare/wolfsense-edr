import { MitreCoverage } from "../lib/types";

export function MitreHeatmap({ coverage }: { coverage: MitreCoverage[] }) {
  const safeCoverage = Array.isArray(coverage) ? coverage : [];

  if (safeCoverage.length === 0) {
    return (
      <div className="rounded-3xl border border-white/10 bg-white/5 p-5 text-sm text-slate-300">
        No MITRE coverage data available.
      </div>
    );
  }

  return (
    <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
      {safeCoverage.map((item) => (
        <article
          key={`${item.technique_id}-${item.technique}`}
          className="rounded-3xl border border-white/10 bg-white/5 p-5"
        >
          <p className="text-xs uppercase tracking-[0.24em] text-cyan-100/60">
            {item.tactic || "MITRE ATT&CK"}
          </p>
          <h3 className="mt-3 text-lg font-semibold text-white">
            {item.technique}
          </h3>
          <p className="mt-1 text-sm text-slate-400">
            {item.technique_id || "Technique ID unavailable"}
          </p>
          <div className="mt-4 h-3 rounded-full bg-slate-900">
            <div
              className="h-full rounded-full bg-gradient-to-r from-cyan-400 to-lime-300"
              style={{ width: `${Math.max(12, item.coverage * 20)}%` }}
            />
          </div>
          <p className="mt-3 text-sm text-slate-300">
            {item.count} mapped detection{item.count === 1 ? "" : "s"}
          </p>
        </article>
      ))}
    </div>
  );
}
