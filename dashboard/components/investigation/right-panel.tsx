
import { EvidenceViewer } from '../evidence-viewer';
import Link from 'next/link';

function IOC({ type, value }: { type: string; value: string }) {
    return (
        <div className="flex justify-between items-center">
            <p className="text-sm text-slate-400">{type}</p>
            <Link href={`/alerts?search=${value}`} className="text-cyan-400 hover:underline text-sm font-mono">
                {value}
            </Link>
        </div>
    );
}

export function RightPanel({ alert }: any) {
    const network = alert.network || {};
    const file = alert.file || {};

  return (
    <div className="space-y-6">
        <div className="bg-slate-900/70 rounded-xl p-6 border border-slate-800">
          <h2 className="text-white font-semibold mb-4">Evidence</h2>
          {alert.evidence ? <EvidenceViewer evidence={alert.evidence} /> : <p className="text-slate-400">No evidence available.</p>}
        </div>

        <div className="bg-slate-900/70 rounded-xl p-6 border border-slate-800">
            <h2 className="text-white font-semibold mb-4">Network IOCs</h2>
            <div className="space-y-2">
                {network.remote_ip && <IOC type="Remote IP" value={network.remote_ip} />}
                {network.remote_port && <IOC type="Remote Port" value={network.remote_port} />}
            </div>
        </div>

        <div className="bg-slate-900/70 rounded-xl p-6 border border-slate-800">
            <h2 className="text-white font-semibold mb-4">File IOCs</h2>
            <div className="space-y-2">
                {file.hash_sha256 && <IOC type="SHA256" value={file.hash_sha256} />}
                {file.path && <p className="text-sm text-slate-400">{file.path}</p>}
            </div>
        </div>
    </div>
  );
}
