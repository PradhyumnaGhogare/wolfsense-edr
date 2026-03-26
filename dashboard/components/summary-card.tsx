export function SummaryCard({
  label,
  value,
  detail,
}: {
  label: string;
  value: string | number;
  detail: string;
}) {
  return (
    <article className="rounded-3xl border border-white/10 bg-white/5 p-5 shadow-[0_20px_60px_rgba(0,0,0,0.25)] backdrop-blur">
      <p className="text-xs uppercase tracking-[0.28em] text-cyan-100/60">{label}</p>
      <p className="mt-4 text-4xl font-semibold text-white">{value}</p>
      <p className="mt-3 text-sm text-slate-300">{detail}</p>
    </article>
  );
}
