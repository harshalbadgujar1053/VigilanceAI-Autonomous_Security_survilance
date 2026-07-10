import React from 'react';

interface SeverityBadgeProps {
  severity: string;
}

export default function SeverityBadge({ severity }: SeverityBadgeProps) {
  const upperSev = severity ? severity.toUpperCase() : 'LOW';
  
  let cls = 'low';
  if (upperSev === 'CRITICAL') cls = 'critical';
  else if (upperSev === 'HIGH') cls = 'high';
  else if (upperSev === 'MEDIUM') cls = 'medium';
  else if (upperSev === 'INFO') cls = 'info';

  return (
    <span id={`sev-badge-${upperSev.toLowerCase()}`} className={`severity-badge ${cls}`}>
      <span className="sev-dot" />
      {upperSev}
    </span>
  );
}
