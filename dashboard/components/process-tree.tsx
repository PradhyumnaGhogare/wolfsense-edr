import { ProcessTreeNode } from "../lib/types";

export function ProcessTree({ nodes }: { nodes: ProcessTreeNode[] }) {
  return (
    <div className="rounded-3xl border border-white/10 bg-slate-950/60 p-5">
      <h3 className="mb-4 text-sm font-semibold uppercase tracking-[0.24em] text-cyan-100/70">
        Process Lineage
      </h3>
      <div className="space-y-3">
        {nodes.map((node, index) => (
          <div key={`${node.name}-${node.pid}-${index}`} className="flex gap-3">
            <div className="flex w-10 flex-col items-center">
              <div className="h-3 w-3 rounded-full bg-cyan-300" />
              {index < nodes.length - 1 ? <div className="h-full w-px bg-cyan-300/30" /> : null}
            </div>
            <div className="flex-1 rounded-2xl border border-white/10 bg-white/5 p-3">
              <div className="flex items-center justify-between gap-3">
                <p className="font-medium text-white">{node.name}</p>
                <span className="text-xs text-slate-400">PID {node.pid}</span>
              </div>
              <p className="mt-2 text-xs text-slate-300">{node.command_line}</p>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
