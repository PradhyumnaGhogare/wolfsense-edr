"use client";

import Link from "next/link";
import React from "react";

interface EvidenceViewerProps {
  evidence: Record<string, any>;
}

const isIOC = (key: string, value: any): boolean => {
  if (typeof value !== "string") return false;
  const lowerKey = key.toLowerCase();
  return (
    lowerKey.includes("ip") ||
    lowerKey.includes("domain") ||
    lowerKey.includes("hash")
  );
};

const IOCLink = ({ value }: { value: string }): React.ReactElement => (
  <Link href={`/search?q=${value}`} className="text-cyan-400 hover:underline">
    {value}
  </Link>
);

const renderValue = (key: string, value: any): React.ReactElement => {
  if (isIOC(key, value)) {
    return <IOCLink value={value} />;
  }
  if (typeof value === "string") {
    return <span className="text-slate-300">"{value}"</span>;
  }
  if (typeof value === "number" || typeof value === "boolean") {
    return <span className="text-green-400">{String(value)}</span>;
  }
  if (value === null) {
    return <span className="text-slate-500">null</span>;
  }
  if (Array.isArray(value)) {
    return (
      <>
        [
        <div className="pl-4">
          {value.map((item, index) => (
            <div key={index}>{renderValue(String(index), item)},</div>
          ))}
        </div>
        ]
      </>
    );
  }
  if (typeof value === "object") {
    return <EvidenceObject obj={value} />;
  }
  return <span className="text-slate-300">{String(value)}</span>;
};

const EvidenceObject = ({
  obj,
}: {
  obj: Record<string, any>;
}): React.ReactElement => {
  return (
    <>
      {"{"}
      <div className="pl-4">
        {Object.entries(obj).map(([key, value]) => (
          <div key={key}>
            <span className="text-purple-400">"{key}"</span>:{" "}
            {renderValue(key, value)},
          </div>
        ))}
      </div>
      {"}"}
    </>
  );
};

export const EvidenceViewer = ({
  evidence,
}: EvidenceViewerProps): React.ReactElement => {
  return (
    <pre className="text-xs bg-slate-800 rounded-md p-4 mt-2 overflow-auto font-mono">
      <EvidenceObject obj={evidence} />
    </pre>
  );
};
