export function TimelineChart({ buckets }: { buckets: any[] | null }) {
  const safeBuckets = Array.isArray(buckets) ? buckets : [];

  const peak = safeBuckets.length
    ? Math.max(...safeBuckets.map((b) => b.count ?? 0), 1)
    : 1;

  return (
    <div className="rounded-3xl border border-white/10 bg-slate-950/60 p-5">
      <h3 className="text-sm font-semibold text-cyan-100/70 mb-4">
        Alerts Timeline
      </h3>

      {safeBuckets.length === 0 ? (
        <p className="text-slate-400 text-sm">No timeline data available</p>
      ) : (
        <div className="flex items-end gap-2 h-32">
          {safeBuckets.map((bucket, i) => (
            <div key={i} className="flex flex-col items-center">
              <div
                className="bg-cyan-400/70 w-6 rounded"
                style={{
                  height: `${(bucket.count / peak) * 100}%`,
                }}
              />
              <span className="text-xs text-slate-400 mt-1">
                {bucket.hour}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}