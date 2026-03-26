import { AlertsTable } from "../../components/alerts-table";
import { getAlerts } from "../../lib/api";
import { Alert } from "../../lib/types";

export const dynamic = "force-dynamic";

export default async function AlertsPage() {
  let alerts: Alert[] = [];
  let errorMessage: string | null = null;

  try {
    alerts = await getAlerts();
  } catch {
    errorMessage = "Unable to load alerts right now.";
  }

  return (
    <section className="space-y-6">
      <div className="rounded-2xl border border-white/10 bg-slate-950/70 p-6">
        <p className="text-xs uppercase tracking-[0.32em] text-cyan-100/65">
          Alerts
        </p>
        <h2 className="mt-4 text-4xl font-semibold text-white">
          Triage & Investigation Queue
        </h2>
        <p className="mt-3 max-w-3xl text-sm leading-7 text-slate-300">
          Review and investigate alerts from across the enterprise.
        </p>
      </div>

      {errorMessage ? (
        <div className="rounded-xl border border-red-400/30 bg-red-900/10 p-4 text-sm text-red-200">
          {errorMessage}
        </div>
      ) : null}

      <AlertsTable alerts={alerts} />
    </section>
  );
}
