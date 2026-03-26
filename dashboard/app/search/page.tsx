import { getAlerts } from "../../lib/api";
import { Alert } from "../../lib/types";
import { AlertsTable } from "../../components/alerts-table";

export const dynamic = "force-dynamic";

export default async function SearchPage({
  searchParams,
}: {
  searchParams?: { [key: string]: string | string[] | undefined };
}) {
  const query = searchParams?.q ?? "";
  const alerts: Alert[] = await getAlerts();

  const filteredAlerts = alerts.filter((alert) => {
    if (!query) return true;
    const lowerCaseQuery = String(query).toLowerCase();
    return JSON.stringify(alert).toLowerCase().includes(lowerCaseQuery);
  });

  return (
    <section className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl text-white font-semibold">Search</h1>
          <p className="text-slate-400 max-w-2xl">
            Searching for alerts containing:{" "}
            <span className="text-cyan-400 font-mono">{query}</span>
          </p>
        </div>
      </div>

      <AlertsTable alerts={filteredAlerts} />
    </section>
  );
}