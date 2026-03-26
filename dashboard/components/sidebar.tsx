import Link from "next/link";

const items = [
  { href: "/", label: "Overview" },
  { href: "/alerts", label: "Alerts" },
  { href: "/incidents", label: "Incidents" },
  { href: "/endpoints", label: "Endpoints" },
  { href: "/threat-intel", label: "Threat Intel" },
  { href: "/mitre", label: "MITRE" },
];

export function Sidebar() {
  return (
    <aside className="rounded-[2rem] border border-white/10 bg-slate-950/70 p-5 backdrop-blur">
      <div className="rounded-3xl border border-cyan-300/30 bg-cyan-300/10 p-4">
        <p className="text-xs uppercase tracking-[0.3em] text-cyan-100/70">EDR Platform</p>
        <h1 className="mt-3 text-2xl font-semibold text-white">WolfSense</h1>
        <p className="mt-2 text-sm text-slate-300">
          SOC dashboard for endpoint telemetry, detections, and investigation.
        </p>
      </div>
      <nav className="mt-6 space-y-2">
        {items.map((item) => (
          <Link
            key={item.href}
            href={item.href}
            className="flex items-center justify-between rounded-2xl border border-white/5 px-4 py-3 text-sm text-slate-200 transition hover:border-cyan-300/40 hover:bg-cyan-300/8"
          >
            {item.label}
            <span className="text-cyan-200/40">/</span>
          </Link>
        ))}
      </nav>
    </aside>
  );
}
