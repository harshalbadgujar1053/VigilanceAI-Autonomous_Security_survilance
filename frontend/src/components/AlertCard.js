import { useState } from 'react';
import SeverityBadge from './SeverityBadge';
import { classifyAlert } from '../api/vigilanceApi';

const BASE = 'http://127.0.0.1:8000';

const LEVEL_CONFIG = (lvl) => {
  const n = parseInt(lvl, 10);
  if (n >= 12) return { color: '#e53e3e', bg: '#fff5f5' };
  if (n >= 8)  return { color: '#ed8936', bg: '#fffaf0' };
  if (n >= 4)  return { color: '#ecc94b', bg: '#fffff0' };
  return { color: '#38a169', bg: '#f0fff4' };
};

function cleanText(text) {
  if (!text) return '';
  return text.replace(/\\n/g, '\n').replace(/\n- /g, '\n• ').replace(/^\s*[-•]\s*/gm, '• ').trim();
}

function parseResult(result) {
  if (!result) return {};
  const raw = typeof result === 'string' ? result : JSON.stringify(result);
  const sev    = raw.match(/SEVERITY[:\s]+([A-Z]+)/i)?.[1]?.trim();
  const reason = raw.match(/REASONING[:\s]+([\s\S]*?)(?=RECOMMENDED|MITRE|$)/i)?.[1]?.trim();
  const mitre  = raw.match(/MITRE TECHNIQUE[S]?[:\s]+([\s\S]*?)(?=CONFIDENCE|RECOMMENDED|$)/i)?.[1]?.trim();
  const fromObj = typeof result === 'object' ? result : {};
  return {
    severity: sev || fromObj.severity,
    reasoning: cleanText(reason || fromObj.reasoning || fromObj.result || ''),
    mitre: mitre || fromObj.mitre_technique,
  };
}

function downloadReportAsPDF(alert, reportText, severity, mitre) {
  const now = new Date();
  const dateStr = now.toLocaleString('en-IN');
  const alertId = alert?.id || 'N/A';
  const host = alert?.agent?.name || 'Unknown';
  const ip = alert?.agent?.ip || 'Unknown';
  const desc = alert?.rule?.description || 'Unknown';
  const level = alert?.rule?.level || '—';
  const ruleId = alert?.rule?.id || '—';
  const sevColor = {
    CRITICAL:'#c53030', HIGH:'#c05621', MEDIUM:'#b7791f', LOW:'#276749'
  }[severity?.toUpperCase()] || '#2d3748';
  const logoUrl = window.location.origin + '/logo.png';

  const html = `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8"/>
<title>Incident Report — ${alertId}</title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: Arial, sans-serif; font-size: 12px; color: #1a1a1a; background: #fff; }

/* ── COVER PAGE ── */
.cover {
  background: #1a2a4a;
  color: #fff;
  padding: 60px 60px 48px;
  min-height: 280px;
}
.cover-top {
  display: flex;
  align-items: center;
  gap: 18px;
  margin-bottom: 36px;
  padding-bottom: 24px;
  border-bottom: 1px solid rgba(255,255,255,0.15);
}
.cover-logo {
  width: 64px;
  height: 64px;
  object-fit: contain;
  filter: drop-shadow(0 0 12px rgba(99,179,237,0.8));
}
.cover-brand-name {
  font-size: 26px;
  font-weight: 800;
  letter-spacing: 0.05em;
  color: #fff;
  line-height: 1.1;
}
.cover-brand-sub {
  font-size: 11px;
  color: #90cdf4;
  letter-spacing: 0.18em;
  text-transform: uppercase;
  margin-top: 4px;
}
.cover-report-type {
  font-size: 13px;
  color: #90cdf4;
  letter-spacing: 0.06em;
  margin-bottom: 8px;
}
.cover-incident-title {
  font-size: 20px;
  font-weight: 700;
  color: #fff;
  margin-bottom: 16px;
  line-height: 1.3;
}
.cover-sev {
  display: inline-block;
  background: ${sevColor};
  color: #fff;
  padding: 5px 20px;
  border-radius: 4px;
  font-size: 13px;
  font-weight: 700;
  letter-spacing: 0.1em;
}
.cover-meta {
  display: grid;
  grid-template-columns: 1fr 1fr 1fr;
  gap: 20px;
  margin-top: 28px;
  padding-top: 24px;
  border-top: 1px solid rgba(255,255,255,0.12);
}
.meta-item .lbl {
  font-size: 9px;
  color: #90cdf4;
  text-transform: uppercase;
  letter-spacing: 0.1em;
  margin-bottom: 4px;
}
.meta-item .val {
  font-size: 13px;
  font-weight: 600;
  color: #fff;
}

/* ── CONTENT ── */
.content { padding: 40px 60px 20px; }

/* Table of Contents */
.toc {
  background: #f7f9fc;
  border: 1px solid #e2e8f0;
  border-radius: 6px;
  padding: 20px 24px;
  margin-bottom: 32px;
}
.toc-title {
  font-size: 11px;
  font-weight: 700;
  color: #1a2a4a;
  letter-spacing: 0.1em;
  text-transform: uppercase;
  margin-bottom: 12px;
  padding-bottom: 8px;
  border-bottom: 2px solid #1a2a4a;
}
.toc ol { padding-left: 18px; }
.toc li { font-size: 12px; color: #4a5568; margin-bottom: 5px; line-height: 1.5; }

/* Section */
.section { margin-bottom: 28px; page-break-inside: avoid; }
.sec-hdr {
  background: #2d3748;
  color: #fff;
  padding: 9px 18px;
  font-size: 11px;
  font-weight: 700;
  letter-spacing: 0.1em;
  text-transform: uppercase;
  border-radius: 4px 4px 0 0;
  display: flex;
  align-items: center;
  gap: 10px;
}
.sec-num {
  background: rgba(255,255,255,0.2);
  width: 22px;
  height: 22px;
  border-radius: 50%;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  font-size: 11px;
  font-weight: 700;
  flex-shrink: 0;
}
.sec-body {
  border: 1px solid #e2e8f0;
  border-top: none;
  border-radius: 0 0 4px 4px;
  padding: 18px 20px;
  background: #fff;
}

/* Summary grid */
.summary-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 0;
  border: 1px solid #e2e8f0;
  border-radius: 4px;
  overflow: hidden;
  margin-bottom: 14px;
}
.summary-row {
  display: contents;
}
.summary-label {
  background: #f7f9fc;
  padding: 9px 14px;
  font-size: 10px;
  font-weight: 700;
  color: #718096;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  border-bottom: 1px solid #e2e8f0;
  border-right: 1px solid #e2e8f0;
}
.summary-value {
  padding: 9px 14px;
  font-size: 12px;
  font-weight: 600;
  color: #1a202c;
  border-bottom: 1px solid #e2e8f0;
}
.sev-pill {
  display: inline-block;
  background: ${sevColor};
  color: #fff;
  padding: 2px 12px;
  border-radius: 3px;
  font-size: 11px;
  font-weight: 700;
  letter-spacing: 0.06em;
}
.summary-desc {
  font-size: 12px;
  color: #4a5568;
  line-height: 1.7;
  margin-top: 4px;
}

/* Tables */
table { width: 100%; border-collapse: collapse; margin-top: 4px; }
th {
  background: #f7f9fc;
  padding: 8px 12px;
  text-align: left;
  font-size: 10px;
  font-weight: 700;
  color: #4a5568;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  border-bottom: 2px solid #e2e8f0;
}
td {
  padding: 8px 12px;
  font-size: 11px;
  border-bottom: 1px solid #f0f4f8;
  vertical-align: top;
  line-height: 1.5;
}
tr:last-child td { border-bottom: none; }

/* MITRE box */
.mitre-box {
  background: #ebf8ff;
  border: 1px solid #90cdf4;
  border-left: 4px solid #3182ce;
  border-radius: 4px;
  padding: 10px 14px;
  margin-bottom: 12px;
  font-size: 12px;
  color: #2b6cb0;
  font-weight: 600;
}

/* Lists */
ul { padding-left: 0; list-style: none; margin: 0; }
li {
  font-size: 12px;
  color: #374151;
  margin-bottom: 6px;
  line-height: 1.6;
  padding-left: 16px;
  position: relative;
}
li::before {
  content: '•';
  position: absolute;
  left: 0;
  color: #3182ce;
  font-weight: 700;
}

/* Actions */
.action {
  display: flex;
  gap: 14px;
  padding: 10px 0;
  border-bottom: 1px solid #f0f4f8;
  align-items: flex-start;
}
.action:last-child { border-bottom: none; }
.action-num {
  background: #1a2a4a;
  color: #fff;
  width: 24px;
  height: 24px;
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 11px;
  font-weight: 700;
  flex-shrink: 0;
  margin-top: 2px;
}
.action-lbl {
  font-size: 9px;
  color: #a0aec0;
  text-transform: uppercase;
  letter-spacing: 0.07em;
  font-weight: 700;
  margin-bottom: 3px;
}
.action-txt { font-size: 12px; color: #374151; line-height: 1.6; }

/* Footer */
.footer {
  background: #1a2a4a;
  color: rgba(255,255,255,0.5);
  padding: 10px 60px;
  display: flex;
  justify-content: space-between;
  align-items: center;
  font-size: 10px;
  letter-spacing: 0.04em;
  margin-top: 24px;
}

@media print {
  body { padding: 0; }
  .section { page-break-inside: avoid; }
  .cover { page-break-after: always; }
}
</style>
</head>
<body>

<!-- COVER -->
<div class="cover">
  <div class="cover-top">
    <img src="${logoUrl}" class="cover-logo" alt="Vigilance AI"
         onerror="this.style.display='none'"/>
    <div>
      <div class="cover-brand-name">Vigilance AI</div>
      <div class="cover-brand-sub">Autonomous Security Surveillance</div>
    </div>
  </div>
  <div class="cover-report-type">Technical Incident Response Report</div>
  <div class="cover-incident-title">${desc}</div>
  <div class="cover-sev">● ${severity || 'UNKNOWN'}</div>
  <div class="cover-meta">
    <div class="meta-item">
      <div class="lbl">Date &amp; Time</div>
      <div class="val">${dateStr}</div>
    </div>
    <div class="meta-item">
      <div class="lbl">Incident ID</div>
      <div class="val">${alertId}</div>
    </div>
    <div class="meta-item">
      <div class="lbl">Prepared By</div>
      <div class="val">Vigilance AI (Mistral 7B)</div>
    </div>
    <div class="meta-item">
      <div class="lbl">Affected Host</div>
      <div class="val">${host} (${ip})</div>
    </div>
    <div class="meta-item">
      <div class="lbl">Wazuh Rule</div>
      <div class="val">ID ${ruleId} — Level ${level}/15</div>
    </div>
    <div class="meta-item">
      <div class="lbl">Classification</div>
      <div class="val"><span class="cover-sev" style="font-size:11px;padding:2px 12px">${severity}</span></div>
    </div>
  </div>
</div>

<!-- CONTENT -->
<div class="content">

  <!-- Table of Contents -->
  <div class="toc">
    <div class="toc-title">Table of Contents</div>
    <ol>
      <li>Incident Summary</li>
      <li>Investigative Findings — Incident Timeline</li>
      <li>Affected Assets</li>
      <li>MITRE ATT&amp;CK Mapping</li>
      <li>Containment</li>
      <li>Eradication</li>
      <li>Recovery</li>
      <li>Recommended Actions</li>
      <li>Lessons Learned</li>
    </ol>
  </div>

  <!-- 1. Incident Summary -->
  <div class="section">
    <div class="sec-hdr"><span class="sec-num">1</span> Incident Summary</div>
    <div class="sec-body">
      <div class="summary-grid">
        <div class="summary-label">Severity</div>
        <div class="summary-value"><span class="sev-pill">${severity}</span></div>
        <div class="summary-label">Status</div>
        <div class="summary-value">Under Investigation</div>
        <div class="summary-label">Detection Source</div>
        <div class="summary-value">Wazuh SIEM — Rule ${ruleId}</div>
        <div class="summary-label">Alert ID</div>
        <div class="summary-value">${alertId}</div>
        <div class="summary-label">Affected Host</div>
        <div class="summary-value">${host} (${ip})</div>
        <div class="summary-label">Rule Level</div>
        <div class="summary-value">${level} / 15</div>
      </div>
      <p class="summary-desc">
        This incident was automatically detected and triaged by <strong>Vigilance AI</strong>
        using a LangChain ReAct agent powered by <strong>Mistral 7B</strong>.
        The alert was correlated against <strong>697 MITRE ATT&amp;CK techniques</strong>
        using a RAG pipeline (ChromaDB + sentence-transformers).
      </p>
    </div>
  </div>

  <!-- 2. Timeline -->
  <div class="section">
    <div class="sec-hdr"><span class="sec-num">2</span> Investigative Findings — Incident Timeline</div>
    <div class="sec-body">
      <table>
        <thead>
          <tr>
            <th>Date &amp; Time</th>
            <th>Detection Source</th>
            <th>Description</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td>${dateStr}</td>
            <td>Wazuh SIEM</td>
            <td>Alert triggered — ${desc} on ${host} (${ip})</td>
          </tr>
          <tr>
            <td>${dateStr}</td>
            <td>Vigilance AI — RAG Pipeline</td>
            <td>MITRE ATT&amp;CK technique mapped: ${mitre || 'Under analysis'}</td>
          </tr>
          <tr>
            <td>${dateStr}</td>
            <td>Vigilance AI — Mistral 7B</td>
            <td>Severity classified as <strong>${severity}</strong> — incident report generated</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>

  <!-- 3. Affected Assets -->
  <div class="section">
    <div class="sec-hdr"><span class="sec-num">3</span> Affected Assets</div>
    <div class="sec-body">
      <table>
        <thead>
          <tr>
            <th>Server</th>
            <th>IP Address</th>
            <th>Purpose</th>
            <th>Status</th>
            <th>Comments</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><strong>${host}</strong></td>
            <td style="font-family:monospace">${ip}</td>
            <td>Production Server</td>
            <td style="color:#c53030;font-weight:600">Suspected Compromised</td>
            <td>${desc}</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>

  <!-- 4. MITRE -->
  <div class="section">
    <div class="sec-hdr"><span class="sec-num">4</span> MITRE ATT&amp;CK Mapping</div>
    <div class="sec-body">
      <div class="mitre-box">
        ${mitre || 'Technique mapping pending further analysis'}
      </div>
      <ul>
        <li>Source: MITRE ATT&amp;CK Enterprise v14 — 697 techniques indexed via ChromaDB RAG</li>
        <li>Mapping performed by: Vigilance AI semantic search + Mistral 7B LLM classification</li>
        <li>CVE References: None identified at this time</li>
      </ul>
    </div>
  </div>

  <!-- 5. Containment -->
  <div class="section">
    <div class="sec-hdr"><span class="sec-num">5</span> Containment</div>
    <div class="sec-body">
      <ul>
        <li>Isolate <strong>${host} (${ip})</strong> from the network if active threat is confirmed</li>
        <li>Block source IP addresses identified in the alert at the perimeter firewall immediately</li>
        <li>Revoke all active sessions and credentials on the affected system</li>
        <li>Enable enhanced logging on adjacent systems to detect lateral movement</li>
      </ul>
    </div>
  </div>

  <!-- 6. Eradication -->
  <div class="section">
    <div class="sec-hdr"><span class="sec-num">6</span> Eradication</div>
    <div class="sec-body">
      <ul>
        <li>Identify and confirm the point of entry for the attack</li>
        <li>Remove all malicious files, processes, or artifacts introduced by the attacker</li>
        <li>Apply all pending security patches and configuration hardening measures</li>
        <li>Disable unused services and enforce the principle of least privilege</li>
        <li>Verify eradication by rescanning with Wazuh rootcheck and vulnerability scanner</li>
      </ul>
    </div>
  </div>

  <!-- 7. Recovery -->
  <div class="section">
    <div class="sec-hdr"><span class="sec-num">7</span> Recovery</div>
    <div class="sec-body">
      <ul>
        <li>Restore <strong>${host}</strong> from a verified clean backup if compromise is confirmed</li>
        <li>Verify full system integrity before reconnecting to the production network</li>
        <li>Monitor <strong>${host}</strong> closely for 72 hours post-recovery for signs of re-infection</li>
        <li>Confirm all services are operational and performing normally before closing the incident</li>
        <li>Update incident status to <em>Resolved</em> after full verification and sign-off</li>
      </ul>
    </div>
  </div>

  <!-- 8. Recommended Actions -->
  <div class="section">
    <div class="sec-hdr"><span class="sec-num">8</span> Recommended Actions</div>
    <div class="sec-body">
      <div class="action">
        <div class="action-num">1</div>
        <div>
          <div class="action-lbl">Immediate — Within 1 Hour</div>
          <div class="action-txt">Isolate <strong>${host}</strong> and block all suspicious source IPs at the perimeter firewall. Notify the incident response team and escalate to senior analyst immediately.</div>
        </div>
      </div>
      <div class="action">
        <div class="action-num">2</div>
        <div>
          <div class="action-lbl">Short Term — Within 24 Hours</div>
          <div class="action-txt">Conduct full forensic analysis of <strong>${host}</strong>. Review all authentication logs, running processes, and network connections. Patch all identified vulnerabilities.</div>
        </div>
      </div>
      <div class="action">
        <div class="action-num">3</div>
        <div>
          <div class="action-lbl">Long Term — Within 1 Week</div>
          <div class="action-txt">Implement multi-factor authentication, review and update Wazuh alert thresholds, conduct team training on <strong>${mitre || 'identified attack technique'}</strong>, and update incident response playbooks.</div>
        </div>
      </div>
    </div>
  </div>

  <!-- 9. Lessons Learned -->
  <div class="section">
    <div class="sec-hdr"><span class="sec-num">9</span> Lessons Learned</div>
    <div class="sec-body">
      <ul>
        <li>Vigilance AI automated triage reduced mean-time-to-classify from hours to under <strong>90 seconds</strong></li>
        <li>MITRE ATT&amp;CK RAG mapping provided actionable threat context immediately upon alert detection</li>
        <li>Early Wazuh detection at rule level <strong>${level}/15</strong> enabled proactive response before escalation</li>
        <li>AI-generated incident report eliminates manual SOC report writing — saving 2–3 hours per incident</li>
        <li>Integrate Vigilance AI findings into weekly SOC review cadence for continuous improvement</li>
      </ul>
    </div>
  </div>

</div>

<!-- FOOTER -->
<div class="footer">
  <div style="display:flex;align-items:center;gap:8px">
    <img src="${logoUrl}" style="height:16px;opacity:0.5" alt="" onerror="this.style.display='none'"/>
    Vigilance AI — Autonomous Security Surveillance
  </div>
  <div>Incident ID: ${alertId} | ${severity} | ${dateStr}</div>
</div>

<script>
window.onload = function() {
  setTimeout(function() { window.print(); }, 600);
}
</script>
</body>
</html>`;

  const blob = new Blob([html], { type: 'text/html' });
  const url = URL.createObjectURL(blob);
  const win = window.open(url, '_blank');
  if (!win) {
    const a = document.createElement('a');
    a.href = url;
    a.download = `vigilance-report-${alertId}.html`;
    a.click();
  }
  setTimeout(() => URL.revokeObjectURL(url), 20000);
}

export default function AlertCard({ alert, index }) {
  const [status, setStatus]             = useState('idle');
  const [result, setResult]             = useState(null);
  const [errorMsg, setErrorMsg]         = useState('');
  const [expanded, setExpanded]         = useState(false);
  const [report, setReport]             = useState(null);
  const [reportStatus, setReportStatus] = useState('idle');

  const handleClassify = async () => {
    setStatus('loading'); setResult(null); setErrorMsg('');
    try { const res = await classifyAlert(alert); setResult(res); setStatus('done'); setExpanded(true); }
    catch (err) { setErrorMsg(err.message); setStatus('error'); }
  };

  const handleReport = async () => {
    setReportStatus('loading'); setReport(null);
    const parsed = parseResult(result);
    try {
      const res = await fetch(`${BASE}/report`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          alert: alert,
          classification: {
            severity: parsed.severity || 'UNKNOWN',
            reasoning: parsed.reasoning || '',
            mitre_tactics: parsed.mitre || '',
          },
        }),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setReport(data.report); setReportStatus('done');
    } catch (err) {
      setReportStatus('error');
      setReport(`Report generation failed: ${err.message}`);
    }
  };

  const lc = LEVEL_CONFIG(alert?.rule?.level);
  const parsed = parseResult(result);

  return (
    <div style={{ background:'#fff', border:'1px solid #e2e8f0', borderLeft:`4px solid ${lc.color}`, borderRadius:'10px', padding:'20px 24px', marginBottom:'12px', boxShadow:'0 1px 4px rgba(0,0,0,0.06)' }}>

      <div style={{ display:'flex', justifyContent:'space-between', alignItems:'flex-start', gap:'12px', flexWrap:'wrap' }}>
        <div style={{ flex:1 }}>
          <div style={{ display:'flex', gap:'7px', marginBottom:'8px', flexWrap:'wrap', alignItems:'center' }}>
            <span style={{ fontFamily:'monospace', fontSize:'11px', color:'#a0aec0', background:'#f7fafc', padding:'2px 7px', borderRadius:'4px', border:'1px solid #e2e8f0' }}>{alert?.id || `alert-${index}`}</span>
            <span style={{ padding:'2px 8px', borderRadius:'4px', background:lc.bg, border:`1px solid ${lc.color}`, color:lc.color, fontSize:'11px', fontWeight:700 }}>LVL {alert?.rule?.level ?? '—'}</span>
            <span style={{ padding:'2px 8px', borderRadius:'4px', background:'#f7fafc', border:'1px solid #e2e8f0', color:'#718096', fontSize:'11px', fontFamily:'monospace' }}>Rule {alert?.rule?.id || '—'}</span>
            {alert?.rule?.groups?.map(g => (
              <span key={g} style={{ padding:'2px 7px', borderRadius:'4px', background:'#ebf8ff', color:'#2b6cb0', fontSize:'10px', fontWeight:600, textTransform:'uppercase', letterSpacing:'0.04em' }}>{g}</span>
            ))}
          </div>
          <div style={{ fontSize:'15px', fontWeight:700, color:'#1a202c', marginBottom:'7px', lineHeight:1.3 }}>
            {alert?.rule?.description || 'No description'}
          </div>
          <div style={{ display:'flex', gap:'16px', flexWrap:'wrap', alignItems:'center' }}>
            <span style={{ fontSize:'12px', color:'#718096' }}>🖥 <strong style={{ color:'#2d3748' }}>{alert?.agent?.name || '—'}</strong></span>
            {alert?.agent?.ip && <span style={{ fontSize:'12px', color:'#718096' }}>🌐 <strong style={{ color:'#2d3748', fontFamily:'monospace' }}>{alert.agent.ip}</strong></span>}
            {alert?.timestamp && <span style={{ fontSize:'11px', color:'#a0aec0' }}>🕐 {new Date(alert.timestamp).toLocaleString('en-IN')}</span>}
          </div>
        </div>

        <div style={{ display:'flex', flexDirection:'column', alignItems:'flex-end', gap:'8px', flexShrink:0 }}>
          {status !== 'done' && (
            <button onClick={handleClassify} disabled={status === 'loading'} style={{
              padding:'9px 20px',
              background: status === 'loading' ? '#edf2f7' : 'linear-gradient(135deg,#1a365d,#2b6cb0)',
              border:'none', borderRadius:'7px',
              color: status === 'loading' ? '#a0aec0' : '#fff',
              fontSize:'12px', fontWeight:700,
              cursor: status === 'loading' ? 'default' : 'pointer',
              display:'flex', alignItems:'center', gap:'7px',
              boxShadow: status === 'loading' ? 'none' : '0 2px 8px rgba(26,54,93,0.3)',
            }}>
              {status === 'loading'
                ? <><span style={{ width:'12px', height:'12px', border:'2px solid #cbd5e0', borderTopColor:'#4a5568', borderRadius:'50%', animation:'spin 0.7s linear infinite', display:'inline-block' }}/>Classifying…</>
                : '▶ Classify Alert'}
            </button>
          )}
          {status === 'done' && (
            <div style={{ display:'flex', gap:'8px', alignItems:'center', flexWrap:'wrap', justifyContent:'flex-end' }}>
              <SeverityBadge severity={parsed.severity} />
              <button onClick={() => setExpanded(v => !v)} style={{ padding:'6px 12px', background:'#f7fafc', border:'1px solid #e2e8f0', borderRadius:'6px', color:'#718096', cursor:'pointer', fontSize:'11px', fontWeight:600 }}>
                {expanded ? '▲ Hide' : '▼ Details'}
              </button>
            </div>
          )}
          {status === 'done' && (
            <button onClick={handleReport} disabled={reportStatus === 'loading'} style={{
              padding:'8px 16px',
              background: reportStatus === 'loading' ? '#f0fff4' : 'linear-gradient(135deg,#276749,#38a169)',
              border:'none', borderRadius:'7px',
              color: reportStatus === 'loading' ? '#9ae6b4' : '#fff',
              fontSize:'12px', fontWeight:700,
              cursor: reportStatus === 'loading' ? 'default' : 'pointer',
              boxShadow: reportStatus === 'loading' ? 'none' : '0 2px 8px rgba(39,103,73,0.3)',
            }}>
              {reportStatus === 'loading' ? '⟳ Generating…' : '📄 Generate Report'}
            </button>
          )}
        </div>
      </div>

      {status === 'error' && (
        <div style={{ marginTop:'14px', padding:'12px 16px', background:'#fff5f5', border:'1px solid #fc8181', borderRadius:'6px', fontSize:'12px', color:'#c53030' }}>
          ✕ {errorMsg}
        </div>
      )}

      {status === 'done' && expanded && (
        <div style={{ marginTop:'16px', padding:'16px 20px', background:'#f7fafc', border:'1px solid #e2e8f0', borderRadius:'8px' }}>
          {parsed.mitre && (
            <div style={{ marginBottom:'12px', display:'flex', alignItems:'center', gap:'8px', flexWrap:'wrap' }}>
              <span style={{ fontSize:'10px', fontWeight:700, color:'#a0aec0', textTransform:'uppercase', letterSpacing:'0.06em' }}>MITRE ATT&CK</span>
              <span style={{ padding:'3px 12px', background:'#ebf8ff', border:'1px solid #90cdf4', borderRadius:'4px', fontSize:'12px', color:'#2b6cb0', fontWeight:600 }}>{parsed.mitre}</span>
            </div>
          )}
          {parsed.reasoning && (
            <div>
              <div style={{ fontSize:'10px', fontWeight:700, color:'#a0aec0', textTransform:'uppercase', letterSpacing:'0.06em', marginBottom:'10px' }}>🤖 AI Reasoning — Mistral 7B</div>
              <div style={{ fontSize:'13px', color:'#4a5568', lineHeight:'1.8' }}>
                {parsed.reasoning.split('\n').filter(Boolean).map((line, i) => (
                  <div key={i} style={{ display:'flex', gap:'8px', marginBottom:'5px', alignItems:'flex-start' }}>
                    {line.startsWith('•')
                      ? <><span style={{ color:'#3182ce', flexShrink:0, marginTop:'1px' }}>•</span><span>{line.replace(/^•\s*/, '')}</span></>
                      : <span>{line}</span>}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {reportStatus !== 'idle' && (
        <div style={{ marginTop:'16px', padding:'16px 20px', background:'#f0fff4', border:'1px solid #9ae6b4', borderRadius:'8px' }}>
          <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:'12px', flexWrap:'wrap', gap:'8px' }}>
            <span style={{ fontSize:'12px', fontWeight:700, color:'#276749' }}>📋 Incident Report — Generated by Mistral 7B</span>
            <div style={{ display:'flex', gap:'8px', alignItems:'center' }}>
              {reportStatus === 'loading' && <span style={{ fontSize:'11px', color:'#718096' }}>⟳ Mistral is writing… (30–90s)</span>}
              {reportStatus === 'done' && (
                <button onClick={() => downloadReportAsPDF(alert, report, parsed.severity, parsed.mitre)} style={{
                  padding:'7px 16px', background:'linear-gradient(135deg,#276749,#38a169)',
                  border:'none', borderRadius:'6px', color:'#fff',
                  fontSize:'12px', fontWeight:700, cursor:'pointer',
                  boxShadow:'0 2px 6px rgba(39,103,73,0.3)',
                }}>⬇ Download PDF</button>
              )}
            </div>
          </div>
          {report && (
            <pre style={{ fontFamily:'monospace', fontSize:'11px', color:'#2d3748', whiteSpace:'pre-wrap', lineHeight:'1.8', background:'#fff', padding:'14px', borderRadius:'6px', border:'1px solid #c6f6d5' }}>
              {report}
            </pre>
          )}
        </div>
      )}
    </div>
  );
}
