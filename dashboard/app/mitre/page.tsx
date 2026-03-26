import { MitreHeatmap } from "../../components/mitre-heatmap";
import { getMitreCoverage } from "../../lib/api";

export const dynamic = "force-dynamic";

export default async function MitrePage() {
  const coverage = await getMitreCoverage();

  return (
    <section className="space-y-6">
      <div className="rounded-[2rem] border border-white/10 bg-slate-950/70 p-6">
        <p className="text-xs uppercase tracking-[0.32em] text-cyan-100/65">MITRE ATT&CK</p>
        <h2 className="mt-4 text-4xl font-semibold text-white">Technique coverage heatmap</h2>
      </div>
      <MitreHeatmap coverage={coverage} />
    </section>
  );
}
