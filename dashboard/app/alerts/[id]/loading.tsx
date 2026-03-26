export default function AlertDetailLoading() {
  return (
    <section className="space-y-6 animate-pulse">
      <div className="rounded-2xl border border-white/10 bg-slate-950/70 p-6">
        <div className="h-3 w-28 rounded bg-slate-700" />
        <div className="mt-4 h-8 w-3/5 rounded bg-slate-700" />
        <div className="mt-3 h-4 w-4/5 rounded bg-slate-800" />
      </div>
      <div className="grid gap-4 md:grid-cols-2">
        {Array.from({ length: 8 }).map((_, index) => (
          <div
            key={index}
            className="rounded-xl border border-white/5 bg-slate-900/70 p-4"
          >
            <div className="h-3 w-24 rounded bg-slate-700" />
            <div className="mt-3 h-5 w-4/5 rounded bg-slate-800" />
          </div>
        ))}
      </div>
    </section>
  );
}
