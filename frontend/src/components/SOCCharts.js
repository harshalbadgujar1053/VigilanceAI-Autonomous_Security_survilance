import {
  PieChart, Pie, Cell, Tooltip, Legend, ResponsiveContainer,
  BarChart, Bar, XAxis, YAxis, CartesianGrid
} from 'recharts';

const SEVERITY_COLORS = {
  CRITICAL: '#e53e3e',
  HIGH:     '#ed8936',
  MEDIUM:   '#ecc94b',
  LOW:      '#38a169',
};

const TACTIC_COLORS = ['#3182ce','#805ad5','#e53e3e','#ed8936','#38a169','#00b5d8','#d53f8c'];

function CustomPieLabel({ cx, cy, midAngle, innerRadius, outerRadius, percent, name, value }) {
  if (percent < 0.05) return null;
  const RADIAN = Math.PI / 180;
  const radius = innerRadius + (outerRadius - innerRadius) * 0.5;
  const x = cx + radius * Math.cos(-midAngle * RADIAN);
  const y = cy + radius * Math.sin(-midAngle * RADIAN);
  return (
    <text x={x} y={y} fill="white" textAnchor="middle" dominantBaseline="central" fontSize={11} fontWeight={700}>
      {value > 0 ? value : ''}
    </text>
  );
}

function Card({ title, subtitle, children }) {
  return (
    <div style={{ background: '#fff', borderRadius: '12px', border: '1px solid #e2e8f0', padding: '20px 20px 12px', boxShadow: '0 1px 4px rgba(0,0,0,0.06)', flex: 1, minWidth: '280px' }}>
      <div style={{ marginBottom: '4px', fontSize: '13px', fontWeight: 700, color: '#1a202c' }}>{title}</div>
      {subtitle && <div style={{ fontSize: '11px', color: '#a0aec0', marginBottom: '14px' }}>{subtitle}</div>}
      {children}
    </div>
  );
}

export default function SOCCharts({ alerts }) {
  // ── Severity pie data ──
  const sevCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  alerts.forEach(a => {
    const lvl = parseInt(a?.rule?.level ?? 0, 10);
    if (lvl >= 12) sevCounts.CRITICAL++;
    else if (lvl >= 8) sevCounts.HIGH++;
    else if (lvl >= 4) sevCounts.MEDIUM++;
    else sevCounts.LOW++;
  });
  const pieData = Object.entries(sevCounts)
    .map(([name, value]) => ({ name, value }))
    .filter(d => d.value > 0);

  // ── Rule level bar data ──
  const barData = alerts.map(a => ({
    name: (a?.rule?.description || 'Unknown').length > 18
      ? (a?.rule?.description || '').slice(0, 18) + '…'
      : (a?.rule?.description || 'Unknown'),
    level: parseInt(a?.rule?.level ?? 0, 10),
    fill: parseInt(a?.rule?.level ?? 0, 10) >= 12 ? '#e53e3e'
        : parseInt(a?.rule?.level ?? 0, 10) >= 8  ? '#ed8936'
        : parseInt(a?.rule?.level ?? 0, 10) >= 4  ? '#ecc94b'
        : '#38a169',
  }));

  // ── MITRE tactic bar ──
  const tacticCounts = {};
  alerts.forEach(a => {
    (a?.rule?.groups || []).forEach(g => {
      const label = g.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
      tacticCounts[label] = (tacticCounts[label] || 0) + 1;
    });
  });
  const tacticData = Object.entries(tacticCounts)
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 8);

  // ── KPI metrics ──
  const total = alerts.length;
  const critical = sevCounts.CRITICAL;
  const avgLevel = total > 0
    ? (alerts.reduce((s, a) => s + parseInt(a?.rule?.level ?? 0, 10), 0) / total).toFixed(1)
    : 0;

  if (alerts.length === 0) return null;

  return (
    <div style={{ marginBottom: '24px' }}>

      {/* ── KPI STRIP ── */}
      <div style={{ display: 'flex', gap: '12px', marginBottom: '16px', flexWrap: 'wrap' }}>
        {[
          { label: 'Total Alerts',     value: total,    color: '#2b6cb0', bg: '#ebf8ff', border: '#90cdf4' },
          { label: 'Critical Threats', value: critical, color: '#c53030', bg: '#fff5f5', border: '#fc8181' },
          { label: 'Avg Rule Level',   value: avgLevel, color: '#b7791f', bg: '#fffff0', border: '#f6e05e', suffix: '/15' },
          { label: 'AI Engine',        value: 'Mistral 7B', color: '#553c9a', bg: '#faf5ff', border: '#d6bcfa', isText: true },
          { label: 'MITRE Indexed',    value: '697',    color: '#2c7a7b', bg: '#e6fffa', border: '#81e6d9', suffix: ' techniques' },
        ].map(({ label, value, color, bg, border, suffix, isText }) => (
          <div key={label} style={{ flex: 1, minWidth: '120px', background: bg, border: `1px solid ${border}`, borderRadius: '10px', padding: '14px 16px' }}>
            <div style={{ fontSize: '10px', color: '#718096', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: '5px' }}>{label}</div>
            <div style={{ fontSize: isText ? '15px' : '26px', fontWeight: 800, color, lineHeight: 1 }}>
              {value}{suffix && <span style={{ fontSize: '11px', fontWeight: 400, color: '#a0aec0' }}>{suffix}</span>}
            </div>
          </div>
        ))}
      </div>

      {/* ── CHARTS ROW ── */}
      <div style={{ display: 'flex', gap: '16px', flexWrap: 'wrap' }}>

        {/* PIE — Severity Distribution */}
        <Card title="Alert Distribution by Severity" subtitle="Breakdown of current alert queue">
          <ResponsiveContainer width="100%" height={220}>
            <PieChart>
              <Pie
                data={pieData}
                cx="50%" cy="50%"
                innerRadius={55} outerRadius={90}
                paddingAngle={3}
                dataKey="value"
                labelLine={false}
                label={CustomPieLabel}
              >
                {pieData.map((entry) => (
                  <Cell key={entry.name} fill={SEVERITY_COLORS[entry.name]} />
                ))}
              </Pie>
              <Tooltip
                formatter={(value, name) => [`${value} alert${value !== 1 ? 's' : ''}`, name]}
                contentStyle={{ fontSize: '12px', borderRadius: '6px', border: '1px solid #e2e8f0' }}
              />
              <Legend
                iconType="circle"
                iconSize={8}
                formatter={(value) => <span style={{ fontSize: '11px', color: '#4a5568', fontWeight: 600 }}>{value}</span>}
              />
            </PieChart>
          </ResponsiveContainer>
        </Card>

        {/* BAR — Rule Level per Alert */}
        <Card title="Alert Severity by Rule Level" subtitle="Wazuh rule level (0–15) per detected alert">
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={barData} margin={{ top: 4, right: 8, left: -10, bottom: 40 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#f0f4f8" />
              <XAxis
                dataKey="name"
                tick={{ fontSize: 10, fill: '#718096' }}
                angle={-30} textAnchor="end" interval={0}
              />
              <YAxis
                domain={[0, 15]}
                tick={{ fontSize: 10, fill: '#718096' }}
                label={{ value: 'Level', angle: -90, position: 'insideLeft', fontSize: 10, fill: '#a0aec0' }}
              />
              <Tooltip
                formatter={(value) => [`Level ${value}/15`, 'Rule Level']}
                contentStyle={{ fontSize: '12px', borderRadius: '6px', border: '1px solid #e2e8f0' }}
              />
              <Bar dataKey="level" radius={[4, 4, 0, 0]}>
                {barData.map((entry, i) => (
                  <Cell key={i} fill={entry.fill} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </Card>

        {/* BAR — Alert Groups / Tactics */}
        {tacticData.length > 0 && (
          <Card title="Alert Mapping to MITRE Tactics" subtitle="Based on Wazuh rule group tags">
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={tacticData} margin={{ top: 4, right: 8, left: -10, bottom: 40 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#f0f4f8" />
                <XAxis
                  dataKey="name"
                  tick={{ fontSize: 10, fill: '#718096' }}
                  angle={-30} textAnchor="end" interval={0}
                />
                <YAxis tick={{ fontSize: 10, fill: '#718096' }} allowDecimals={false} />
                <Tooltip
                  contentStyle={{ fontSize: '12px', borderRadius: '6px', border: '1px solid #e2e8f0' }}
                />
                <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                  {tacticData.map((_, i) => (
                    <Cell key={i} fill={TACTIC_COLORS[i % TACTIC_COLORS.length]} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </Card>
        )}
      </div>
    </div>
  );
}
