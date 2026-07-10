import React from 'react';
import { Alert } from '../types';
import { 
  ResponsiveContainer, 
  PieChart, 
  Pie, 
  Cell, 
  BarChart, 
  Bar, 
  XAxis, 
  YAxis, 
  Tooltip, 
  Legend, 
  CartesianGrid,
  Label
} from 'recharts';
import { 
  Shield, 
  AlertOctagon, 
  BarChart3, 
  Sparkles, 
  Fingerprint,
  Server,
  Laptop,
  HelpCircle,
  Database,
  Smartphone,
  Printer,
  Video,
  Phone,
  Globe,
  HardDrive,
  Terminal,
  Grid,
  Apple,
  History,
  ShieldAlert
} from 'lucide-react';

interface SOCChartsProps {
  alerts: Alert[];
}



const ROTATING_COLORS = [
  '#0F766E', // Teal
  '#0ea5e9', // Sky Blue
  '#10B981', // Emerald
  '#F59E0B', // Amber
  '#F97316', // Orange
  '#EF4444', // Red
  '#8B5CF6', // Purple
  '#EC4899'  // Pink
];

export default function SOCCharts({ alerts }: SOCChartsProps) {
  // track which log row is expanded
  const [expandedId, setExpandedId] = React.useState<string | null>(null);

  if (!alerts || alerts.length === 0) {
    return (
      <div className="dashboard-empty-state">
        <ShieldAlert size={48} style={{ color: 'var(--color-text-muted)', marginBottom: '12px' }} />
        <h4>No Matching Metrics</h4>
        <p>Try clearing or modifying your dashboard search query.</p>
      </div>
    );
  }

  // Compute stats
  const total = alerts.length;
  const critical = alerts.filter(a => a.rule.level >= 12).length;
  const high = alerts.filter(a => a.rule.level >= 8 && a.rule.level < 12).length;
  const medium = alerts.filter(a => a.rule.level >= 4 && a.rule.level < 8).length;
  const low = alerts.filter(a => a.rule.level < 4).length;

  const avgLevel = Number(
    (alerts.reduce((acc, a) => acc + a.rule.level, 0) / total).toFixed(1)
  );

  // 1. Severity Pie Data (Donut style)
  const pieData = [
    { name: 'Critical', value: critical, color: '#EF4444' },
    { name: 'High', value: high, color: '#F97316' },
    { name: 'Medium', value: medium, color: '#F59E0B' },
    { name: 'Low', value: low, color: '#10B981' }
  ].filter(d => d.value > 0);

  // 2. Alert Levels Bar Data (Top 12 sorted by level)
  const topAlertsData = [...alerts]
    .sort((a, b) => b.rule.level - a.rule.level)
    .slice(0, 12)
    .map(a => {
      const desc = a.rule.description;
      const truncatedLabel = desc.length > 18 ? desc.substring(0, 15) + '...' : desc;
      
      let barColor = '#10B981';
      if (a.rule.level >= 12) barColor = '#EF4444';
      else if (a.rule.level >= 8) barColor = '#F97316';
      else if (a.rule.level >= 4) barColor = '#F59E0B';

      return {
        id: a.id,
        name: truncatedLabel,
        fullName: desc,
        level: a.rule.level,
        color: barColor
      };
    });

  // 3. MITRE Tactic Data (from groups, top 8)
  const tacticCounts: Record<string, number> = {};
  alerts.forEach(a => {
    if (a.rule && a.rule.groups) {
      a.rule.groups.forEach(g => {
        const label = g.replace(/_/g, ' ').toUpperCase();
        tacticCounts[label] = (tacticCounts[label] || 0) + 1;
      });
    }
  });

  const mapTacticName = (rawName: string): string => {
    const clean = rawName.replace(/_/g, ' ').toUpperCase().trim();
    switch (clean) {
      case 'INITIAL ACCESS': return 'Initial Access';
      case 'EXECUTION': return 'Execution';
      case 'PERSISTENCE': return 'Persistence';
      case 'PRIVILEGE ESCALATION': return 'Privilege Esc.';
      case 'DEFENSE EVASION': return 'Defense Evasion';
      case 'CREDENTIAL ACCESS': return 'Credential Acc.';
      case 'DISCOVERY': return 'Discovery';
      case 'LATERAL MOVEMENT': return 'Lateral Mvmt';
      case 'COLLECTION': return 'Collection';
      case 'COMMAND AND CONTROL': return 'Command & Ctrl';
      case 'EXFILTRATION': return 'Exfiltration';
      case 'IMPACT': return 'Impact';
      default: {
        return clean
          .toLowerCase()
          .split(' ')
          .map(w => w.charAt(0).toUpperCase() + w.slice(1))
          .join(' ');
      }
    }
  };

  const tacticData = Object.entries(tacticCounts)
    .map(([rawName, count]) => {
      const displayName = mapTacticName(rawName);
      return {
        name: displayName,
        fullName: rawName.replace(/_/g, ' ').toUpperCase(),
        count
      };
    })
    .sort((a, b) => b.count - a.count)
    .slice(0, 8);

  // helpers for redesigned overview row
  const maxTacticCount = Math.max(...tacticData.map(t => t.count), 1);
  const riskScore = Math.round(((critical + high) / total) * 100);
  const riskLabel = riskScore >= 60 ? 'High Risk' : riskScore >= 30 ? 'Elevated' : 'Stable';
  const riskColor = riskScore >= 60 ? '#EF4444' : riskScore >= 30 ? '#F59E0B' : '#10B981';
  const gaugeAngle = (riskScore / 100) * 180;

  // Custom Tooltip component for Recharts
  const CustomTooltip = ({ active, payload, label }: any) => {
    if (active && payload && payload.length) {
      const data = payload[0].payload;
      return (
        <div className="custom-chart-tooltip">
          <p className="tooltip-title">{data.fullName || label || data.name}</p>
          <p className="tooltip-value">
            <span className="bullet-indicator" style={{ backgroundColor: payload[0].color || '#0F766E' }} />
            {payload[0].name}: <span className="tooltip-number">{payload[0].value}</span>
          </p>
        </div>
      );
    }
    return null;
  };

  // Custom active labels for pie charts
  const renderPieLabel = ({ cx, cy, midAngle, innerRadius, outerRadius, value, name }: any) => {
    const RADIAN = Math.PI / 180;
    const radius = innerRadius + (outerRadius - innerRadius) * 0.5;
    const x = cx + radius * Math.cos(-midAngle * RADIAN);
    const y = cy + radius * Math.sin(-midAngle * RADIAN);

    return (
      <text x={x} y={y} fill="white" textAnchor="middle" dominantBaseline="central" className="pie-label-text">
        {value}
      </text>
    );
  };

  return (
    <div className="soc-charts-wrapper">
      {/* Overview row: icon progress list, gradient donut, risk gauge */}
      <div id="dashboard-overview-grid" className="charts-grid">

        {/* 1. Detection Categories -> icon + progress bar rows */}
        <div className="chart-container-card">
          <div className="chart-card-header">
            <h4>Detection Categories</h4>
            <p>Breakdown by MITRE technique class</p>
          </div>
          <div className="icon-progress-list">
            {tacticData.map((t, i) => {
              const pct = Math.round((t.count / maxTacticCount) * 100);
              const color = ROTATING_COLORS[i % ROTATING_COLORS.length];
              return (
                <div key={t.name} className="icon-progress-row">
                  <div className="icon-progress-top">
                    <span className="icon-progress-label">{t.name}</span>
                    <span className="icon-progress-count" style={{ color }}>{t.count}</span>
                  </div>
                  <div className="icon-progress-track">
                    <div
                      className="icon-progress-fill"
                      style={{ width: `${pct}%`, background: color }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* 2. Severity Distribution donut - gradient fill + pill legend */}
        <div className="chart-container-card">
          <div className="chart-card-header">
            <h4>Severity Distribution</h4>
            <p>Active alert category break-down</p>
          </div>
          <div className="donut-chart-section-layout">
            <div className="chart-body-wrapper">
              <ResponsiveContainer width="100%" height={110}>
                <PieChart>
                  <defs>
                    {pieData.map((entry, index) => (
                      <linearGradient key={`grad-${index}`} id={`sevGrad-${index}`} x1="0" y1="0" x2="1" y2="1">
                        <stop offset="0%" stopColor={entry.color} stopOpacity={1} />
                        <stop offset="100%" stopColor={entry.color} stopOpacity={0.7} />
                      </linearGradient>
                    ))}
                  </defs>
                  <Pie
                    data={pieData}
                    cx="50%"
                    cy="50%"
                    innerRadius={32}
                    outerRadius={48}
                    paddingAngle={4}
                    dataKey="value"
                  >
                    <Label value={total} position="center" className="donut-center-value" />
                    {pieData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={`url(#sevGrad-${index})`} stroke="var(--color-surface)" strokeWidth={2} />
                    ))}
                  </Pie>
                  <Tooltip content={<CustomTooltip />} />
                </PieChart>
              </ResponsiveContainer>
            </div>
            <div className="pill-legend vertical-legend">
              {pieData.map(d => (
                <span key={d.name} className="pill-legend-item">
                  <span className="pill-legend-dot" style={{ background: d.color }} />
                  {d.name} · {d.value}
                </span>
              ))}
            </div>
          </div>
        </div>

        {/* 3. Overall Risk Score -> semi-circle gauge */}
        <div className="chart-container-card">
          <div className="chart-card-header">
            <h4>Overall Risk Score</h4>
            <p>Weighted by critical &amp; high severity share</p>
          </div>
          <div className="risk-gauge-wrapper">
            <svg viewBox="0 0 200 120" className="risk-gauge-svg">
              <path d="M 20 110 A 80 80 0 0 1 180 110" fill="none" stroke="#E2E8F0" strokeWidth="16" strokeLinecap="round" />
              <path
                d="M 20 110 A 80 80 0 0 1 180 110"
                fill="none"
                stroke={riskColor}
                strokeWidth="16"
                strokeLinecap="round"
                strokeDasharray={`${(gaugeAngle / 180) * 251.2} 251.2`}
              />
              <text x="100" y="95" textAnchor="middle" className="risk-gauge-value">{riskScore}%</text>
            </svg>
            <div className="risk-gauge-label" style={{ color: riskColor }}>
              <ShieldAlert size={16} />
              {riskLabel}
            </div>
            <p className="risk-gauge-subtext">{critical + high} of {total} alerts are Critical/High</p>
          </div>
        </div>

      </div>

      {/* Charts Grid */}
      <div id="dashboard-charts-grid" className="charts-grid">
        {/* Alert Rule Levels Bar Chart */}
        <div className="chart-container-card">
          <div className="chart-card-header">
            <h4>Alert Rule Levels</h4>
            <p>Sizing of top 12 active event triggers</p>
          </div>
          <div className="chart-body-wrapper">
            <ResponsiveContainer width="100%" height={160}>
              <BarChart data={topAlertsData} margin={{ top: 10, right: 10, left: -15, bottom: 5 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255, 63, 129, 0.08)" vertical={false} />
                <XAxis 
                  dataKey="name" 
                  tick={{ fill: 'var(--color-text-secondary)', fontSize: 10 }}
                  axisLine={{ stroke: 'var(--color-border)' }}
                  tickLine={false}
                />
                <YAxis 
                  domain={[0, 15]} 
                  tick={{ fill: 'var(--color-text-secondary)', fontSize: 10 }}
                  axisLine={{ stroke: 'var(--color-border)' }}
                  tickLine={false}
                />
                <Tooltip content={<CustomTooltip />} />
                <Bar dataKey="level" radius={[4, 4, 0, 0]}>
                  {topAlertsData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* MITRE Tactics Bar Chart */}
        <div className="chart-container-card">
          <div className="chart-card-header">
            <h4>MITRE ATT&CK Indicators</h4>
            <p>Top technique classes detected on disk</p>
          </div>
          <div className="chart-body-wrapper">
            <ResponsiveContainer width="100%" height={160}>
              <BarChart data={tacticData} margin={{ top: 10, right: 10, left: -15, bottom: 25 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255, 63, 129, 0.08)" vertical={false} />
                <XAxis 
                  dataKey="name" 
                  tick={{ fill: 'var(--color-text-secondary)', fontSize: 9, dy: 4, dx: -2 }}
                  interval={0}
                  axisLine={{ stroke: 'var(--color-border)' }}
                  tickLine={false}
                  angle={-30}
                  textAnchor="end"
                  height={45}
                />
                <YAxis 
                  allowDecimals={false}
                  tick={{ fill: 'var(--color-text-secondary)', fontSize: 10 }}
                  axisLine={{ stroke: 'var(--color-border)' }}
                  tickLine={false}
                />
                <Tooltip content={<CustomTooltip />} />
                <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                  {tacticData.map((entry, index) => (
                    <Cell 
                      key={`cell-${index}`} 
                      fill={ROTATING_COLORS[index % ROTATING_COLORS.length]} 
                    />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Security Logs Section below Diagrams */}
      <div className="chart-container-card" id="dashboard-logs-section" style={{ width: '100%' }}>
        <div className="chart-card-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px' }}>
          <div>
            <h4>Security Event Logs</h4>
            <p>Active security log feeds captured across all monitoring host agents</p>
          </div>
          <div style={{ fontSize: '11px', backgroundColor: '#F1F5F9', color: '#475569', padding: '4px 10px', borderRadius: '6px', fontFamily: 'monospace', fontWeight: '600' }}>
            {alerts.length} Total Events
          </div>
        </div>
        
        <div style={{ overflowX: 'auto', marginTop: '16px' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px', textAlign: 'left' }}>
            <thead>
              <tr style={{ borderBottom: '2px solid #E2E8F0', paddingBottom: '8px' }}>
                <th style={{ padding: '10px 12px', fontWeight: '600', color: '#64748B' }}>Severity</th>
                <th style={{ padding: '10px 12px', fontWeight: '600', color: '#64748B' }}>Trigger Rule / Description</th>
                <th style={{ padding: '10px 12px', fontWeight: '600', color: '#64748B' }}>Host Agent</th>
                <th style={{ padding: '10px 12px', fontWeight: '600', color: '#64748B' }}>Log File Location</th>
                <th style={{ padding: '10px 12px', fontWeight: '600', color: '#64748B', textAlign: 'right' }}>Timestamp</th>
              </tr>
            </thead>
            <tbody>
              {[...alerts].sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()).map((alert) => {
                let severityLabel = "Low";
                let badgeStyle = { backgroundColor: '#DEF7EC', color: '#03543F' }; // Low Green
                if (alert.rule.level >= 12) {
                  severityLabel = "Critical";
                  badgeStyle = { backgroundColor: '#FDE8E8', color: '#9B1C1C' }; // Critical Red
                } else if (alert.rule.level >= 8) {
                  severityLabel = "High";
                  badgeStyle = { backgroundColor: '#FDF2E9', color: '#8A3F15' }; // High Orange
                } else if (alert.rule.level >= 4) {
                  severityLabel = "Medium";
                  badgeStyle = { backgroundColor: '#FEF9C3', color: '#713F12' }; // Medium Yellow
                }

                const isExpanded = expandedId === alert.id;

                return (
                  <React.Fragment key={alert.id}>
                    <tr
                      className="hover-row-effect"
                      onClick={() => setExpandedId(isExpanded ? null : alert.id)}
                      style={{
                        borderBottom: '1px solid #F1F5F9',
                        transition: 'background-color 0.15s ease',
                        cursor: 'pointer',
                        backgroundColor: isExpanded ? '#F8FAFC' : 'transparent'
                      }}
                    >
                      <td style={{ padding: '12px', whiteSpace: 'nowrap' }}>
                        <span style={{ 
                          display: 'inline-flex', 
                          alignItems: 'center', 
                          padding: '3px 8px', 
                          borderRadius: '9999px', 
                          fontWeight: '600', 
                          fontSize: '10px',
                          textTransform: 'uppercase',
                          ...badgeStyle 
                        }}>
                          {severityLabel} ({alert.rule.level})
                        </span>
                      </td>
                      <td style={{ padding: '12px' }}>
                        <div style={{ fontWeight: '600', color: '#1E293B', marginBottom: '4px' }}>{alert.rule.description}</div>
                        <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap' }}>
                          {alert.rule.groups.map(group => (
                            <span key={group} style={{ 
                              fontSize: '9px', 
                              backgroundColor: '#F8FAFC', 
                              color: '#64748B', 
                              border: '1px solid #E2E8F0', 
                              padding: '1px 6px', 
                              borderRadius: '4px',
                              fontFamily: 'monospace' 
                            }}>
                              {group}
                            </span>
                          ))}
                        </div>
                      </td>
                      <td style={{ padding: '12px', whiteSpace: 'nowrap' }}>
                        <div style={{ fontWeight: '500', color: '#334155' }}>{alert.agent.name}</div>
                        <div style={{ fontSize: '10px', color: '#94A3B8', fontFamily: 'monospace' }}>{alert.agent.ip}</div>
                      </td>
                      <td style={{ padding: '12px', color: '#475569', fontFamily: 'monospace', fontSize: '11px' }}>
                        {alert.location}
                      </td>
                      <td style={{ padding: '12px', textAlign: 'right', color: '#64748B', whiteSpace: 'nowrap' }}>
                        {new Date(alert.timestamp).toLocaleString(undefined, {
                          month: 'short',
                          day: 'numeric',
                          hour: '2-digit',
                          minute: '2-digit',
                          second: '2-digit'
                        })}
                      </td>
                    </tr>

                    {/* Expandable detail panel row */}
                    {isExpanded && (
                      <tr>
                        <td colSpan={5} style={{ padding: 0 }}>
                          <div className="row-detail-panel">
                            <div>
                              <strong>Rule ID:</strong> {alert.rule.id}
                              <br />
                              <strong>Rule Level:</strong> {alert.rule.level}
                              <br />
                              <strong>Full Description:</strong> {alert.rule.description}
                            </div>
                            <div>
                              <strong>Host Agent:</strong> {alert.agent.name}
                              <br />
                              <strong>Agent IP:</strong> {alert.agent.ip}
                            </div>
                            <div>
                              <strong>Log Path:</strong> {alert.location}
                              <br />
                              <strong>Timestamp:</strong>{' '}
                              {new Date(alert.timestamp).toLocaleString()}
                            </div>
                          </div>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
