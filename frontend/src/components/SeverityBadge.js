const CFG = {
  CRITICAL: { bg: '#fff5f5', border: '#fc8181', text: '#c53030', dot: '#e53e3e' },
  HIGH:     { bg: '#fffaf0', border: '#fbd38d', text: '#c05621', dot: '#ed8936' },
  MEDIUM:   { bg: '#fffff0', border: '#f6e05e', text: '#b7791f', dot: '#ecc94b' },
  LOW:      { bg: '#f0fff4', border: '#9ae6b4', text: '#276749', dot: '#38a169' },
  INFO:     { bg: '#ebf8ff', border: '#90cdf4', text: '#2b6cb0', dot: '#3182ce' },
};

export default function SeverityBadge({ severity }) {
  const upper = (severity || 'INFO').toUpperCase();
  const cfg = CFG[upper] || CFG.INFO;
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: '6px',
      padding: '4px 12px', borderRadius: '20px',
      border: `1px solid ${cfg.border}`, background: cfg.bg, color: cfg.text,
      fontSize: '11px', fontWeight: 700, letterSpacing: '0.06em',
      textTransform: 'uppercase', whiteSpace: 'nowrap',
    }}>
      <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: cfg.dot, flexShrink: 0 }}/>
      {upper}
    </span>
  );
}
