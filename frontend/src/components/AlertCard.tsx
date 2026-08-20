import React, { useState, useEffect } from 'react';
import { Alert, Classification } from '../types';
import { classifyAlert, generateReport, saveClassificationToDB } from '../api/vigilanceApi';
import { generateIncidentPDF } from '../utils/generatePDF';
import SeverityBadge from './SeverityBadge';
import { 
  Cpu, 
  FileText, 
  ChevronDown, 
  ChevronUp, 
  Monitor, 
  Radio, 
  FileCheck, 
  Terminal, 
  Download, 
  Printer,
  AlertCircle 
} from 'lucide-react';

interface AlertCardProps {
  alert: Alert;
  index: number;
}

const AlertCard: React.FC<AlertCardProps> = ({ alert, index }) => {
  const [status, setStatus] = useState<'idle' | 'loading' | 'done' | 'error'>('idle');
  const [result, setResult] = useState<Classification | null>(null);
  const [errorMsg, setErrorMsg] = useState('');
  const [expanded, setExpanded] = useState(false);
  const [report, setReport] = useState<string>('');
  const [reportStatus, setReportStatus] = useState<'idle' | 'loading' | 'done'>('idle');

  // Auto-populate classification from the backend's eager, ingestion-time
  // classification (Option 2 architecture) — the alert already carries
  // technique/reasoning/recommended_actions from GET /alerts by the time
  // this card renders, so Recommended Actions shows immediately with no
  // click needed, and Case Creation just needs to generate the report.
  useEffect(() => {
    if (alert.severity && alert.severity !== 'UNKNOWN' && alert.severity !== 'PENDING' && !result) {
      const reasoningLines = alert.reasoning
        ? alert.reasoning.split('|').map(s => s.trim()).filter(Boolean)
        : ['Alert classified during ingestion.'];
      const recommendedActionsLines = alert.recommended_actions
        ? alert.recommended_actions.split('|').map(s => s.trim()).filter(Boolean)
        : undefined;

      setResult({
        severity: alert.severity as any,
        technique: alert.technique || (alert.rule.groups.length > 0 ? alert.rule.groups[0].toUpperCase() : 'T1543 - THREAT BEHAVIOR'),
        reasoning: reasoningLines,
        recommendedActions: recommendedActionsLines
      });
      setStatus('done');
    }
  }, [alert.severity, alert.technique, alert.reasoning, alert.recommended_actions]);
     
  // Severity Level Mapping
  const level = alert.rule.level;
  let severityCategory: 'critical' | 'high' | 'medium' | 'low' = 'low';
  if (level >= 12) severityCategory = 'critical';
  else if (level >= 8) severityCategory = 'high';
  else if (level >= 4) severityCategory = 'medium';

  // Helper to parse raw AI text via regex
  const parseResult = (rawClassification: any): Classification => {
    if (rawClassification.severity && rawClassification.technique && rawClassification.reasoning && Array.isArray(rawClassification.reasoning)) {
      return rawClassification as Classification;
    }

    const text = rawClassification.rawText || '';
    
    // Support both [SEVERITY] and SEVERITY: formats (with/without brackets, case-insensitive)
    const severityMatch = text.match(/\[SEVERITY\]\s*(\w+)/i) || text.match(/SEVERITY:\s*(\w+)/i);
    
    // Support both [TECHNIQUE] and TECHNIQUE: formats
    const techniqueMatch = text.match(/\[TECHNIQUE\]\s*([^\n]+)/i) || text.match(/TECHNIQUE:\s*([^\n]+)/i) || text.match(/MITRE:\s*([^\n]+)/i);

    const reasoningLines: string[] = [];
    
    // Support both [REASONING] and REASONING: formats, splitting off the recommended action section
    const reasoningMatch = text.match(/\[REASONING\]\s*([\s\S]+?)(?=\[RECOMMENDED|$)/i) || text.match(/REASONING:\s*([\s\S]+?)(?=RECOMMENDED|$)/i);
    
    if (reasoningMatch) {
      const lines = reasoningMatch[1].split('\n');
      lines.forEach((line: string) => {
        const cleaned = line.replace(/^\s*-\s*/, '').trim();
        if (cleaned && !cleaned.toLowerCase().includes('recommended action')) {
          reasoningLines.push(cleaned);
        }
      });
    }

    // Support [RECOMMENDED ACTIONS] block, bulleted, one item per line
    const recommendedActionsLines: string[] = [];
    const recommendedActionsMatch = text.match(/\[RECOMMENDED ACTIONS\]\s*([\s\S]+?)(?=\[|$)/i);
    if (recommendedActionsMatch) {
      const lines = recommendedActionsMatch[1].split('\n');
      lines.forEach((line: string) => {
        const cleaned = line.replace(/^\s*[-\d.]+\s*/, '').trim();
        if (cleaned) {
          recommendedActionsLines.push(cleaned);
        }
      });
    }

    return {
      severity: (severityMatch ? severityMatch[1].toUpperCase() : (alert.rule.level >= 12 ? 'CRITICAL' : alert.rule.level >= 8 ? 'HIGH' : alert.rule.level >= 4 ? 'MEDIUM' : 'LOW')) as any,
      technique: techniqueMatch ? techniqueMatch[1].trim() : 'T1543 - Threat Behavior',
      reasoning: reasoningLines.length > 0 ? reasoningLines : ['Anomalous host event detected requiring automated SOC triage.'],
      recommendedActions: recommendedActionsLines.length > 0 ? recommendedActionsLines : ['No specific recommended actions provided.']
    };
  };

  const handleClassify = async () => {
    setStatus('loading');
    setErrorMsg('');
    try {
      const rawData = await classifyAlert(alert);
      const parsed = parseResult(rawData);
      setResult(parsed);
      setStatus('done');
      try {
        await saveClassificationToDB({
  alert_id: alert.id,
  severity: parsed.severity,
  reasoning: parsed.reasoning.join(' | '),
  mitre_tactics: parsed.technique,
  recommended_actions: (parsed.recommendedActions ?? []).join(' | ')
});
      } catch {
        // Non-fatal: dashboard already shows the result even if persistence fails
      }
    } catch (err: any) {
      setStatus('error');
      setErrorMsg(err.message || 'Failed to analyze alert payload via Mistral 7B.');
    }
  };

  const handleGenerateReport = async () => {
    if (!result) return;
    setReportStatus('loading');
    try {
      const data = await generateReport(alert, result);
      setReport(data.report);
      setReportStatus('done');
      setExpanded(true);
    } catch (err) {
      setReportStatus('idle');
      console.error('Failed to compile incident report PDF.', err);
    }
  };

  // Generate HTML document for Print PDF in a new tab
  const downloadReportAsHTMLPDF = () => {
    if (!result || !report) return;

    const htmlString = `
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <title>Incident Report - ${alert.id}</title>
        <style>
          @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;700&display=swap');
          
          body {
            font-family: 'Inter', sans-serif;
            margin: 0;
            padding: 0;
            background-color: #FFFFFF;
            color: #0F172A;
            line-height: 1.5;
          }

          /* Cover Page */
          .cover-page {
            page-break-after: always;
            height: 100vh;
            display: flex;
            flex-direction: column;
            justify-content: space-between;
            box-sizing: border-box;
            padding: 60px;
            background: linear-gradient(135deg, #0F172A 0%, #1E293B 100%);
            color: #FFFFFF;
          }

          .cover-header {
            border-bottom: 2px solid #0F766E;
            padding-bottom: 30px;
          }

          .cover-brand {
            font-size: 32px;
            font-weight: 800;
            color: #0F766E;
            letter-spacing: -0.05em;
          }

          .cover-brand-sub {
            font-size: 11px;
            font-weight: 500;
            color: #94A3B8;
            letter-spacing: 0.1em;
            margin-top: 4px;
          }

          .cover-title-section {
            margin: auto 0;
          }

          .cover-title {
            font-size: 42px;
            font-weight: 800;
            line-height: 1.1;
            margin-bottom: 10px;
          }

          .cover-subtitle {
            font-size: 16px;
            color: #94A3B8;
          }

          .cover-meta {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 20px 40px;
            border-top: 1px solid #334155;
            padding-top: 40px;
          }

          .meta-item {
            display: flex;
            flex-direction: column;
          }

          .meta-label {
            font-size: 10px;
            font-weight: 700;
            color: #64748B;
            text-transform: uppercase;
            letter-spacing: 0.05em;
          }

          .meta-value {
            font-size: 15px;
            font-weight: 500;
            color: #E2E8F0;
            margin-top: 4px;
          }

          .severity-pill {
            display: inline-block;
            padding: 6px 14px;
            border-radius: 9999px;
            font-weight: 700;
            font-size: 12px;
            text-transform: uppercase;
            margin-top: 10px;
            align-self: flex-start;
          }

          .sev-CRITICAL { background-color: #EF4444; color: #FFFFFF; }
          .sev-HIGH { background-color: #F97316; color: #FFFFFF; }
          .sev-MEDIUM { background-color: #F59E0B; color: #FFFFFF; }
          .sev-LOW { background-color: #10B981; color: #FFFFFF; }

          /* Document Content */
          .content-container {
            max-width: 800px;
            margin: 0 auto;
            padding: 60px 40px;
          }

          .section {
            margin-bottom: 40px;
            page-break-inside: avoid;
          }

          h2 {
            font-size: 20px;
            font-weight: 700;
            border-left: 4px solid #0F766E;
            padding-left: 12px;
            margin-bottom: 15px;
            color: #0F172A;
          }

          p, li {
            font-size: 14px;
            color: #334155;
            line-height: 1.6;
          }

          ol, ul {
            padding-left: 20px;
          }

          li {
            margin-bottom: 8px;
          }

          table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
            margin-bottom: 15px;
          }

          th, td {
            padding: 10px 12px;
            text-align: left;
            font-size: 13px;
            border-bottom: 1px solid #E2E8F0;
          }

          th {
            background-color: #F8FAFC;
            font-weight: 600;
            color: #475569;
          }

          .pre-block {
            background-color: #F8FAFC;
            border: 1px solid #E2E8F0;
            padding: 18px;
            border-radius: 8px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 13px;
            white-space: pre-wrap;
            color: #1E293B;
          }

          .footer {
            margin-top: 60px;
            border-top: 1px solid #E2E8F0;
            padding-top: 20px;
            display: flex;
            justify-content: space-between;
            font-size: 11px;
            color: #64748B;
          }

          @media print {
            body {
              -webkit-print-color-adjust: exact;
              print-color-adjust: exact;
            }
          }
        </style>
      </head>
      <body>
        
        <!-- COVER PAGE -->
        <div class="cover-page">
          <div class="cover-header">
            <div class="cover-brand">Vigilance AI</div>
            <div class="cover-brand-sub">AUTONOMOUS SECURITY SURVEILLANCE</div>
          </div>
          
          <div class="cover-title-section">
            <div class="cover-title">INCIDENT INVESTIGATION REPORT</div>
            <div class="cover-subtitle">Automated SIEM Triage powered by Mistral 7B LLM</div>
            <div class="severity-pill sev-${result.severity}">${result.severity}</div>
          </div>

          <div class="cover-meta">
            <div class="meta-item">
              <div class="meta-label">Incident ID</div>
              <div class="meta-value">${alert.id}</div>
            </div>
            <div class="meta-item">
              <div class="meta-label">Target Agent Host</div>
              <div class="meta-value">${alert.agent.name}</div>
            </div>
            <div class="meta-item">
              <div class="meta-label">Target Agent IP</div>
              <div class="meta-value">${alert.agent.ip}</div>
            </div>
            <div class="meta-item">
              <div class="meta-label">Incident Rule Trigger</div>
              <div class="meta-value">${alert.rule.id}</div>
            </div>
            <div class="meta-item">
              <div class="meta-label">Original Priority Sizing</div>
              <div class="meta-value">Level ${alert.rule.level}/15</div>
            </div>
            <div class="meta-item">
              <div class="meta-label">Mitre Att&ck Category</div>
              <div class="meta-value">${result.technique}</div>
            </div>
          </div>
        </div>

        <!-- REPORT CONTENT -->
        <div class="content-container">
          
          <div class="section">
            <h2>1. Executive Summary</h2>
            <p>
              An automated high-priority alert was cataloged from <strong>${alert.agent.name}</strong> on interface IP <strong>${alert.agent.ip}</strong>. 
              The rule event description indicates <strong>"${alert.rule.description}"</strong>. 
              Applying Gemini-powered RAG analysis, the threat category has been mapped as <strong>${result.technique}</strong> with <strong>${result.severity}</strong> priority tags.
            </p>
          </div>

          <div class="section">
            <h2>2. Detection Timeline & Artifacts</h2>
            <p>Security logging sequences recorded the following incident response timing:</p>
            <table>
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Origin Node</th>
                  <th>Observed Status Log</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td>${alert.timestamp}</td>
                  <td>SIEM Agent Sync</td>
                  <td>Primary threshold breach logged</td>
                </tr>
                <tr>
                  <td>${new Date().toISOString()}</td>
                  <td>Vigilance Triage Controller</td>
                  <td>Mistral 7B heuristic analysis trigger completed</td>
                </tr>
              </tbody>
            </table>
          </div>

          <div class="section">
            <h2>3. Affected Assets</h2>
            <p>Host parameters on targeted infrastructure:</p>
            <table>
              <thead>
                <tr>
                  <th>Asset ID</th>
                  <th>Host Name</th>
                  <th>System IP Address</th>
                  <th>SLA Sizing Scope</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td>${alert.agent.id}</td>
                  <td>${alert.agent.name}</td>
                  <td>${alert.agent.ip}</td>
                  <td>Production Database Space / Core App Stack</td>
                </tr>
              </tbody>
            </table>
          </div>

          <div class="section">
            <h2>4. MITRE ATT&CK Mapping</h2>
            <p>Forensic signature matching tags and groups associated with this alert:</p>
            <ul>
              <li><strong>Technique Tag:</strong> ${result.technique}</li>
              <li><strong>SIEM System Groups:</strong> ${alert.rule.groups.join(', ')}</li>
              <li><strong>Attack Path:</strong> Lateral environment intrusion mapping</li>
            </ul>
          </div>

          <div class="section">
            <h2>5. AI Analysis Findings</h2>
            <div class="pre-block">${report}</div>
          </div>

          <div class="section">
            <h2>6. Recommended Actions</h2>
            <ol>
              <li>Perform network quarantine for host node <strong>${alert.agent.name}</strong> to mitigate packet traversal.</li>
              <li>Verify root files and file descriptors listed in alert data structures.</li>
              <li>Change access keys and SSH host permissions on the secure subnet.</li>
              <li>Perform immediate audit logging scans.</li>
              <li>Update firewall parameters to drop ingress queries from related sources.</li>
              <li>Enforce high-strength authentication policies.</li>
            </ol>
          </div>

          <div class="section">
            <h2>7. Lessons Learned</h2>
            <ul>
              <li>Configure real-time alerting limits on directory space and credential attempts.</li>
              <li>Reduce high-privilege access bindings on non-standard workstations.</li>
              <li>Integrate instant API webhook notifications to alert on-call security responders.</li>
            </ul>
          </div>

          <div class="footer">
            <span>Report generated by Vigilance AI Autonomous Security Surveillance</span>
            <span>ID: ${alert.id}</span>
          </div>

        </div>

        <script>
          window.onload = function() {
            window.print();
          };
        </script>
      </body>
      </html>
    `;

    const blob = new Blob([htmlString], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const win = window.open(url, '_blank');
    if (!win) {
      // If blocked, fallback to file download
      const link = document.createElement('a');
      link.href = url;
      link.download = `Incident_Report___${alert.id}.html`;
      link.click();
    }
  };

  const downloadNativePDF = () => {
    if (!result || !report) return;
    generateIncidentPDF({ alert, classification: result, report });
  };

  return (
    <div 
      id={`alert-card-${alert.id}`} 
      className={`alert-card fade-slide-up severity-${severityCategory}`}
      style={{ animationDelay: `${index * 80}ms` }}
    >
      {/* Dynamic 4px severity stripe is applied via CSS class borders */}
      
      <div className="alert-card-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '20px' }}>
        <div className="alert-header-left" style={{ flex: 1 }}>
          <h3 className="alert-title">{alert.rule.description}</h3>
          
          <div className="alert-meta-grid" style={{ marginTop: '8px' }}>
            <span className="meta-tag" title="Hostname">
              {alert.agent.name}
            </span>
            <span className="meta-tag" title="IP Address">
              {alert.agent.ip}
            </span>
            <span className="meta-tag text-mono" title="Rule ID">
              {alert.rule.id}
            </span>
            <span className="meta-tag badge-id" title="Alert ID">
              ID: {alert.id}
            </span>
            {alert._source === 'live' && (
              <span className="meta-tag" style={{ background: 'rgba(16, 185, 129, 0.1)', color: '#10B981', border: '1px solid rgba(16, 185, 129, 0.2)', fontWeight: 700, fontSize: '10px' }}>
                LIVE
              </span>
            )}
            {alert.severity && alert.severity !== 'UNKNOWN' && alert.severity !== 'PENDING' && (
              <span className="meta-tag" style={{ background: 'rgba(56, 189, 248, 0.1)', color: '#0EA5E9', border: '1px solid rgba(56, 189, 248, 0.2)', fontWeight: 700, fontSize: '10px' }}>
                {alert.severity}
              </span>
            )}
            <span className={`severity-badge ${severityCategory}`}>
              <span className="sev-dot" />
              Level {level}/15
            </span>
          </div>
        </div>

        <div className="alert-header-right" style={{ display: 'flex', alignItems: 'center', gap: '12px', flexShrink: 0 }}>
          {status === 'idle' && (
            <button 
              id={`btn-classify-${alert.id}`}
              onClick={handleClassify} 
              className="btn btn-primary btn-sm"
            >
              Classify
            </button>
          )}

          {status === 'loading' && (
            <div className="analyzing-indicator pulse secondary btn-xs" style={{ padding: '6px 12px' }}>
              <span className="spinner small white" />
              <span>Analyzing...</span>
            </div>
          )}

          {status === 'error' && (
            <button 
              id={`btn-classify-retry-${alert.id}`}
              onClick={handleClassify} 
              className="btn btn-outline btn-error btn-sm"
            >
              Retry Classify
            </button>
          )}

          {status === 'done' && (
            <div className="classified-success-actions" style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              {reportStatus === 'idle' && (
                <button 
                  id={`btn-report-${alert.id}`}
                  onClick={handleGenerateReport} 
                  className="btn btn-secondary btn-sm"
                >
                  Case Creation
                </button>
              )}

              {reportStatus === 'loading' && (
                <div className="analyzing-indicator pulse secondary btn-xs" style={{ padding: '6px 12px' }}>
                  <span className="spinner small white" />
                  <span>Compiling...</span>
                </div>
              )}

              {reportStatus === 'done' && (
                <button 
                  id={`btn-toggle-expand-${alert.id}`}
                  onClick={() => setExpanded(!expanded)} 
                  className="btn btn-ghost btn-sm"
                >
                  {expanded ? (
                    <>
                      <ChevronUp size={15} />
                      Collapse Details
                    </>
                  ) : (
                    <>
                      <ChevronDown size={15} />
                      Expand Details
                    </>
                  )}
                </button>
              )}
            </div>
          )}
        </div>
      </div>

      {/* Error Output Box */}
      {status === 'error' && (
        <div id={`error-box-${alert.id}`} className="alert-error-box animate-slide-in">
          <AlertCircle size={18} className="error-icon" />
          <p>{errorMsg}</p>
        </div>
      )}

      {/* AI Classification Succesful Display */}
      {status === 'done' && result && (() => {
        const upperSev = result.severity?.toUpperCase() || 'LOW';
        const isCritical = upperSev === 'CRITICAL';
        const isHigh = upperSev === 'HIGH';
        const isMedium = upperSev === 'MEDIUM';

        const sevColor = 
          isCritical ? 'var(--sev-critical)' :
          isHigh ? 'var(--sev-high)' :
          isMedium ? 'var(--sev-medium)' :
          'var(--sev-low)';

        const sevBgLight = 
          isCritical ? 'var(--sev-critical-light)' :
          isHigh ? 'var(--sev-high-light)' :
          isMedium ? 'var(--sev-medium-light)' :
          'var(--sev-low-light)';

        const sevTextDark = 
          isCritical ? 'var(--sev-critical-text)' :
          isHigh ? 'var(--sev-high-text)' :
          isMedium ? 'var(--sev-medium-text)' :
          'var(--sev-low-text)';

        const sevBorder = 
          isCritical ? 'var(--sev-critical-border)' :
          isHigh ? 'var(--sev-high-border)' :
          isMedium ? 'var(--sev-medium-border)' :
          'var(--sev-low-border)';

        return (
          <div 
            id={`classification-box-${alert.id}`} 
            className="classification-box animate-slide-in"
            style={{ 
              borderLeft: `4px solid ${sevColor}`,
              backgroundColor: '#FAFBFC',
              borderRadius: '0 8px 8px 0',
              padding: '16px 20px',
              borderTop: '1px solid var(--color-border-light)',
              borderBottom: '1px solid var(--color-border-light)',
              borderRight: '1px solid var(--color-border-light)',
              boxShadow: 'inset 2px 0 8px rgba(0,0,0,0.01)'
            }}
          >
            <div className="class-header" style={{ marginBottom: '10px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div className="class-header-title" style={{ display: 'flex', alignItems: 'center' }}>
                <h4 style={{ margin: 0, fontSize: '13px', fontWeight: 700, letterSpacing: '0.02em', textTransform: 'uppercase', color: 'var(--color-text-primary)' }}>
                  Classification
                </h4>
              </div>
              <SeverityBadge severity={result.severity} />
            </div>

            <div className="class-body" style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              <div className="class-meta-row" style={{ display: 'flex', gap: '8px', alignItems: 'stretch', width: '100%' }}>
                <div 
                  className="class-section" 
                  style={{ 
                    flex: 1,
                    display: 'flex',
                    flexDirection: 'row', 
                    alignItems: 'center', 
                    gap: '4px', 
                    background: sevBgLight,
                    padding: '3px 8px',
                    borderRadius: '5px',
                    border: `1px solid ${sevBorder}`,
                    boxShadow: '0 1px 2px rgba(0,0,0,0.01)'
                  }}
                >
                  <span style={{ fontSize: '10px', fontWeight: 800, textTransform: 'uppercase', color: sevTextDark, letterSpacing: '0.05em' }}>
                    SEVERITY:
                  </span>
                  <p style={{ margin: 0, fontSize: '11px', fontWeight: 700, color: sevTextDark }}>
                    {result.severity}
                  </p>
                </div>

                <div 
                  className="class-section" 
                  style={{ 
                    flex: 1,
                    display: 'flex',
                    flexDirection: 'row', 
                    alignItems: 'center', 
                    gap: '4px', 
                    background: '#E0F2FE',
                    padding: '3px 8px',
                    borderRadius: '5px',
                    border: '1px solid #BAE6FD',
                    boxShadow: '0 1px 2px rgba(0,0,0,0.01)'
                  }}
                >
                  <span style={{ fontSize: '10px', fontWeight: 800, textTransform: 'uppercase', color: '#0369A1', letterSpacing: '0.05em' }}>
                    MITRE ATT&CK:
                  </span>
                  <p style={{ margin: 0, fontSize: '11px', fontFamily: 'var(--font-mono)', fontWeight: 600, color: '#0C4A6E' }}>
                    {result.technique}
                  </p>
                </div>
              </div>

              <div 
                className="class-section"
                style={{
                  background: 'var(--color-surface)',
                  padding: '8px 12px',
                  borderRadius: '6px',
                  border: '1px solid var(--color-border-light)',
                  boxShadow: '0 1px 2px rgba(0,0,0,0.01)'
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', marginBottom: '2px' }}>
                  <span className="section-label indigo" style={{ fontSize: '11px', fontWeight: 800, textTransform: 'uppercase', padding: '3px 8px', borderRadius: '4px', background: 'var(--color-primary-light)', color: 'var(--color-primary)', letterSpacing: '0.05em' }}>
                    REASONING
                  </span>
                </div>
                <ul className="reasoning-bullets" style={{ margin: 0, padding: 0, listStyleType: 'none', display: 'flex', flexDirection: 'column', gap: '3px' }}>
                  {result.reasoning.map((item, idx) => (
                    <li 
                      key={idx} 
                      style={{ 
                        fontSize: '12px', 
                        color: 'var(--color-text-secondary)', 
                        position: 'relative', 
                        paddingLeft: '12px',
                        lineHeight: '1.4'
                      }}
                    >
                      <span style={{ 
                        position: 'absolute', 
                        left: '0', 
                        top: '6px', 
                        width: '4px', 
                        height: '4px', 
                        borderRadius: '50%', 
                        background: sevColor 
                      }} />
                      {item}
                    </li>
                  ))}
                </ul>
              </div>

              {result.recommendedActions && result.recommendedActions.length > 0 && (
                <div 
                  className="class-section"
                  style={{
                    background: 'var(--color-surface)',
                    padding: '8px 12px',
                    borderRadius: '6px',
                    border: '1px solid var(--color-border-light)',
                    boxShadow: '0 1px 2px rgba(0,0,0,0.01)'
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', marginBottom: '2px' }}>
                    <span className="section-label emerald" style={{ fontSize: '11px', fontWeight: 800, textTransform: 'uppercase', padding: '3px 8px', borderRadius: '4px', background: '#D1FAE5', color: '#065F46', letterSpacing: '0.05em' }}>
                      RECOMMENDED ACTIONS
                    </span>
                  </div>
                  <ul className="reasoning-bullets" style={{ margin: 0, padding: 0, listStyleType: 'none', display: 'flex', flexDirection: 'column', gap: '3px' }}>
                    {result.recommendedActions.map((item, idx) => (
                      <li 
                        key={idx} 
                        style={{ 
                          fontSize: '12px', 
                          color: 'var(--color-text-secondary)', 
                          position: 'relative', 
                          paddingLeft: '12px',
                          lineHeight: '1.4'
                        }}
                      >
                        <span style={{ 
                          position: 'absolute', 
                          left: '0', 
                          top: '6px', 
                          width: '4px', 
                          height: '4px', 
                          borderRadius: '50%', 
                          background: '#059669' 
                        }} />
                        {item}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          </div>
        );
      })()}

      {/* Full Generated Report Section */}
      {reportStatus === 'done' && report && expanded && (
        <div id={`report-box-${alert.id}`} className="report-box animate-slide-in">
          <div className="report-header">
            <div className="report-header-title">
              <FileCheck size={16} className="text-emerald" />
              <h4>Case Creation Report</h4>
            </div>
            
            <div className="report-download-options">
              <button 
                id={`btn-download-pdf-${alert.id}`}
                onClick={downloadNativePDF} 
                className="btn btn-emerald-gradient btn-xs"
                title="Download High-Fidelity A4 PDF"
              >
                <Download size={13} />
                Download PDF
              </button>
              
              <button 
                id={`btn-print-pdf-${alert.id}`}
                onClick={downloadReportAsHTMLPDF} 
                className="btn btn-ghost btn-xs"
                title="Print Report with Cover Page"
              >
                <Printer size={13} />
                Print / HTML
              </button>
            </div>
          </div>

          <div className="report-body">
            <pre className="monospace-pre-block">{report}</pre>
          </div>
        </div>
      )}
    </div>
  );
};

export default AlertCard;
