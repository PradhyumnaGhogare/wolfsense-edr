
import Link from 'next/link';
import { StatusPill } from '../status-pill';

function CommandLine({ command }: { command: string }) {
    return (
        <div className="bg-slate-800 p-4 rounded-lg text-sm text-slate-300 font-mono">
            <pre><code>{command}</code></pre>
        </div>
    );
}

function MitreAttack({ tactic, technique }: { tactic: string; technique: string }) {
    return (
        <div>
            <p className="text-sm text-slate-400">Tactic: <span className="text-white">{tactic}</span></p>
            <p className="text-sm text-slate-400">Technique: <span className="text-white">{technique}</span></p>
        </div>
    );
}

function Timeline({ timestamp }: { timestamp: string }) {
    const formattedTime = new Date(timestamp).toLocaleString();
    return (
        <div>
            <p className="text-sm text-slate-400">Alert Time: <span className="text-white">{formattedTime}</span></p>
        </div>
    );
}

export function CenterPanel({ alert }: any) {
  return (
    <div className="space-y-6">
        <div className="bg-slate-900/70 rounded-xl p-6 border border-slate-800">
            <div className="flex items-center justify-between mb-4">
                <div>
                    <h1 className="text-2xl text-white font-semibold">{alert?.title ?? 'No Title'}</h1>
                    <p className="text-slate-400">{alert?.summary ?? 'No Summary'}</p>
                </div>
                {alert?.severity && <StatusPill value={alert.severity} />}
            </div>

            <div className="grid grid-cols-2 gap-4 text-sm">
                <div>
                    <p className="text-slate-400">Hostname</p>
                    {alert?.hostname ? (
                        <Link
                            href={`/endpoints/${alert.endpoint_id}`}
                            className="text-cyan-400 hover:underline"
                        >
                            {alert.hostname}
                        </Link>
                    ) : (
                        <p>N/A</p>
                    )}
                </div>

                <div>
                    <p className="text-slate-400">Process</p>
                    <p>{alert?.process ?? 'N/A'}</p>
                </div>
            </div>
        </div>

        <div className="bg-slate-900/70 rounded-xl p-6 border border-slate-800">
            <h2 className="text-white font-semibold mb-2">Command Line</h2>
            <CommandLine command={alert?.command_line ?? 'No command line available.'} />
        </div>

        <div className="bg-slate-900/70 rounded-xl p-6 border border-slate-800">
            <h2 className="text-white font-semibold mb-2">MITRE ATT&CK</h2>
            <MitreAttack tactic={alert?.mitre_tactic ?? 'N/A'} technique={alert?.mitre_technique ?? 'N/A'} />
        </div>
        
        <div className="bg-slate-900/70 rounded-xl p-6 border border-slate-800">
            <h2 className="text-white font-semibold mb-2">Timeline</h2>
            <Timeline timestamp={alert?.timestamp ?? new Date().toISOString()} />
        </div>
    </div>
  );
}
