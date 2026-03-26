
import React from 'react';

export function InvestigationLayout({ left, center, right }: { left: React.ReactNode; center: React.ReactNode; right: React.ReactNode }) {
  return (
    <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
      <div className="lg:col-span-3">{left}</div>
      <div className="lg:col-span-5">{center}</div>
      <div className="lg:col-span-4">{right}</div>
    </div>
  );
}
