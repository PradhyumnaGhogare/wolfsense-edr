
'use client';

import { useState } from 'react';

function ProcessTreeNode({ node, selected, onSelect, level }: any) {
  const isSelected = selected && selected.pid === node.pid;
  return (
    <div style={{ marginLeft: `${level * 20}px` }}>
        <div 
            className={`p-2 rounded-md cursor-pointer ${isSelected ? 'bg-sky-900' : 'hover:bg-slate-800'}`}
            onClick={() => onSelect(node)}
        >
            <p className="text-sm text-slate-300">{node.name} (PID: {node.pid})</p>
        </div>
    </div>
  );
}

export function ProcessTreePanel({ alert }: any) {
    const [selectedProcess, setSelectedProcess] = useState<any>(null);

    const handleSelectProcess = (process: any) => {
        setSelectedProcess(process);
    };

    const processTree = alert.process_tree || [];

  return (
    <div className="bg-slate-900/70 rounded-xl p-6 border border-slate-800 h-full">
      <h2 className="text-white font-semibold mb-4">Process Tree</h2>
      <div className="space-y-1">
        {processTree.length > 0 ? (
          processTree.map((node: any, index: number) => (
            <ProcessTreeNode 
              key={index} 
              node={node} 
              selected={selectedProcess} 
              onSelect={handleSelectProcess}
              level={node.level || 0}
            />
          ))
        ) : (
          <p className="text-slate-400">No process tree data available.</p>
        )}
      </div>
      {selectedProcess && (
          <div className="mt-4 pt-4 border-t border-slate-700">
              <h3 className="text-white font-semibold mb-2">Process Details</h3>
              <p className="text-sm text-slate-400">PID: {selectedProcess.pid}</p>
              <p className="text-sm text-slate-400 font-mono bg-slate-800 p-2 rounded">
                {selectedProcess.command_line}
              </p>
          </div>
      )}
    </div>
  );
}
