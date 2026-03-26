import Link from "next/link";

import { StatusPill } from "../../components/status-pill";
import { getEndpoints } from "../../lib/api";

export const dynamic = "force-dynamic";

type SearchParams = {
  q?: string | string[] | undefined;
  owner?: string | string[] | undefined;
};

export default async function EndpointsPage({
  searchParams,
}: {
  searchParams?: SearchParams | Promise<SearchParams>;
}) {
  const resolvedSearchParams = (await Promise.resolve(searchParams)) ?? {};
  const query = getFirstValue(resolvedSearchParams.q);
  const owner = getFirstValue(resolvedSearchParams.owner);
  const endpoints = await getEndpoints(query, owner);

  return (
    <section className="space-y-6">
      <div className="rounded-[2rem] border border-white/10 bg-slate-950/70 p-6">
        <p className="text-xs uppercase tracking-[0.32em] text-cyan-100/65">
          Endpoints
        </p>
        <h1 className="mt-4 text-4xl font-semibold text-white">
          Managed endpoint estate
        </h1>
        <p className="mt-3 max-w-3xl text-sm leading-7 text-slate-300">
          Search monitored systems by hostname or owner, review live health, and
          pivot into endpoint-specific detection history.
        </p>
      </div>

      <form
        action="/endpoints"
        method="get"
        className="grid gap-4 rounded-3xl border border-white/10 bg-slate-950/60 p-5 lg:grid-cols-[1fr_1fr_auto]"
      >
        <label className="space-y-2">
          <span className="text-xs uppercase tracking-[0.22em] text-slate-500">
            Hostname Search
          </span>
          <input
            type="text"
            name="q"
            defaultValue={query}
            placeholder="Search hostname"
            className="w-full rounded-2xl border border-white/10 bg-slate-950 px-4 py-3 text-sm text-white outline-none transition focus:border-cyan-300/40"
          />
        </label>

        <label className="space-y-2">
          <span className="text-xs uppercase tracking-[0.22em] text-slate-500">
            Owner Search
          </span>
          <input
            type="text"
            name="owner"
            defaultValue={owner}
            placeholder="Filter by owner"
            className="w-full rounded-2xl border border-white/10 bg-slate-950 px-4 py-3 text-sm text-white outline-none transition focus:border-cyan-300/40"
          />
        </label>

        <div className="flex items-end gap-3">
          <button
            type="submit"
            className="rounded-2xl border border-cyan-300/40 bg-cyan-300/10 px-5 py-3 text-sm font-medium text-cyan-100 transition hover:bg-cyan-300/20"
          >
            Search
          </button>
          <Link
            href="/endpoints"
            className="rounded-2xl border border-white/10 px-5 py-3 text-sm text-slate-300 transition hover:border-cyan-300/30 hover:text-white"
          >
            Clear
          </Link>
        </div>
      </form>

      <div className="grid gap-5">
        {endpoints.length === 0 ? (
          <div className="rounded-3xl border border-white/10 bg-slate-950/60 p-5 text-sm text-slate-300">
            No endpoints matched the current filters.
          </div>
        ) : null}

        {endpoints.map((endpoint) => (
          <Link
            key={endpoint.id}
            href={`/endpoints/${endpoint.id}`}
            className="group rounded-3xl border border-white/10 bg-slate-950/60 p-5 transition hover:border-cyan-300/40 hover:bg-cyan-300/8"
          >
            <div className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
              <div>
                <div className="flex flex-wrap items-center gap-3">
                  <h2 className="text-xl font-semibold text-white">
                    {endpoint.hostname?.trim() || endpoint.id}
                  </h2>
                  <StatusPill value={endpoint.status} />
                </div>

                <div className="mt-4 grid gap-3 text-sm text-slate-300 md:grid-cols-2 xl:grid-cols-4">
                  <MetaCell label="IP" value={endpoint.ip?.trim() || "-"} />
                  <MetaCell label="Owner" value={endpoint.owner?.trim() || "unassigned"} />
                  <MetaCell
                    label="Last Seen"
                    value={formatDateTime(endpoint.last_seen ?? endpoint.last_telemetry_at)}
                  />
                  <MetaCell label="Operating System" value={endpoint.os?.trim() || endpoint.os_version?.trim() || "-"} />
                </div>
              </div>

              <div className="grid gap-3 text-sm text-slate-300 xl:min-w-56">
                <MetaCell label="Open Alerts" value={String(endpoint.alert_count ?? 0)} />
                <MetaCell label="Risk Score" value={String(endpoint.risk_score ?? 0)} />
                <p className="text-sm font-medium text-cyan-100 transition group-hover:text-cyan-50">
                  Open endpoint
                </p>
              </div>
            </div>
          </Link>
        ))}
      </div>
    </section>
  );
}

function MetaCell({
  label,
  value,
}: {
  label: string;
  value: string;
}) {
  return (
    <div>
      <p className="text-xs uppercase tracking-[0.22em] text-slate-500">
        {label}
      </p>
      <p className="mt-1 break-words">{value}</p>
    </div>
  );
}

function getFirstValue(value?: string | string[]) {
  if (Array.isArray(value)) {
    return value[0] ?? "";
  }

  return value ?? "";
}

function formatDateTime(value?: string) {
  if (!value) {
    return "-";
  }

  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return "-";
  }

  return date.toLocaleString();
}
