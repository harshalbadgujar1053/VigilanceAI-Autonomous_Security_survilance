import React, { useState, useEffect } from 'react';
import { fetchSavedReports, fetchReportById } from '../api/vigilanceApi';

const severityColor = {
  CRITICAL: '#ff4444',
  HIGH:     '#ff8800',
  MEDIUM:   '#ffcc00',
  LOW:      '#00cc44',
  UNKNOWN:  '#888888'
};

export default function ReportsHistory() {
  const [reports, setReports]       = useState([]);
  const [loading, setLoading]       = useState(true);
  const [error, setError]           = useState(null);
  const [selected, setSelected]     = useState(null);
  const [fullReport, setFullReport] = useState(null);
  const [loadingFull, setLoadingFull] = useState(false);

  useEffect(() => {
    loadReports();
  }, []);

  async function loadReports() {
    setLoading(true);
    setError(null);
    try {
      const data = await fetchSavedReports();
      setReports(data.reports || []);
    } catch (e) {
      setError('Failed to load reports from database.');
    } finally {
      setLoading(false);
    }
  }

  async function viewFullReport(id) {
    setLoadingFull(true);
    setSelected(id);
    setFullReport(null);
    try {
      const data = await fetchReportById(id);
      setFullReport(data.report);
    } catch (e) {
      setFullReport({ error: 'Could not load full report.' });
    } finally {
      setLoadingFull(false);
    }
  }

  function closeModal() {
    setSelected(null);
    setFullReport(null);
  }

  // ── styles ──
  const styles = {
    container: { padding: '24px', color: '#e2e8f0', fontFamily: 'monospace' },
    header: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' },
    title: { fontSize: '20px', fontWeight: 700, color: '#60a5fa' },
    count: { fontSize: '13px', color: '#94a3b8' },
    refreshBtn: { padding: '6px 14px', background: '#1e40af', color: '#fff', border: 'none', borderRadius: '6px', cursor: 'pointer', fontSize: '12px' },
    table: { width: '100%', borderCollapse: 'collapse' },
    th: { padding: '10px 14px', background: '#1e293b', color: '#94a3b8', fontSize: '11px', textAlign: 'left', borderBottom: '1px solid #334155' },
    td: { padding: '10px 14px', fontSize: '12px', borderBottom: '1px solid #1e293b', verticalAlign: 'middle' },
    badge: (sev) => ({
      display: 'inline-block', padding: '2px 8px', borderRadius: '4px',
      background: severityColor[sev] || '#888', color: '#fff',
      fontSize: '11px', fontWeight: 700
    }),
    viewBtn: { padding: '4px 10px', background: '#0f766e', color: '#fff', border: 'none', borderRadius: '5px', cursor: 'pointer', fontSize: '11px' },
    emptyBox: { textAlign: 'center', padding: '60px', color: '#475569' },
    emptyIcon: { fontSize: '48px', marginBottom: '12px' },
    emptyText: { fontSize: '14px' },
    // Modal
    overlay: { position: 'fixed', top: 0, left: 0, right: 0, bottom: 0, background: 'rgba(0,0,0,0.75)', zIndex: 1000, display: 'flex', alignItems: 'center', justifyContent: 'center' },
    modal: { background: '#0f172a', border: '1px solid #334155', borderRadius: '12px', width: '80%', maxWidth: '860px', maxHeight: '80vh', display: 'flex', flexDirection: 'column' },
    modalHeader: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '16px 20px', borderBottom: '1px solid #334155' },
    modalTitle: { fontSize: '15px', fontWeight: 700, color: '#60a5fa' },
    closeBtn: { background: 'none', border: 'none', color: '#94a3b8', fontSize: '20px', cursor: 'pointer' },
    modalBody: { padding: '20px', overflowY: 'auto', flex: 1 },
    reportText: { whiteSpace: 'pre-wrap', fontSize: '12px', lineHeight: '1.7', color: '#cbd5e1' },
    loadingText: { color: '#94a3b8', textAlign: 'center', padding: '40px' }
  };

  return (
    <div style={styles.container}>
      {/* Header */}
      <div style={styles.header}>
        <div>
          <div style={styles.title}>📋 Reports History</div>
          <div style={styles.count}>
            {loading ? 'Loading...' : `${reports.length} report${reports.length !== 1 ? 's' : ''} saved in database`}
          </div>
        </div>
        <button style={styles.refreshBtn} onClick={loadReports}>↻ Refresh</button>
      </div>

      {/* Error */}
      {error && (
        <div style={{ background: '#450a0a', border: '1px solid #991b1b', borderRadius: '8px', padding: '12px 16px', color: '#fca5a5', marginBottom: '16px' }}>
          ⚠️ {error}
        </div>
      )}

      {/* Empty state */}
      {!loading && !error && reports.length === 0 && (
        <div style={styles.emptyBox}>
          <div style={styles.emptyIcon}>📭</div>
          <div style={styles.emptyText}>No reports saved yet.</div>
          <div style={{ fontSize: '12px', color: '#334155', marginTop: '8px' }}>
            Classify an alert and click "Generate Report" — it will be auto-saved here.
          </div>
        </div>
      )}

      {/* Table */}
      {!loading && reports.length > 0 && (
        <table style={styles.table}>
          <thead>
            <tr>
              <th style={styles.th}>#</th>
              <th style={styles.th}>Alert ID</th>
              <th style={styles.th}>Agent</th>
              <th style={styles.th}>Severity</th>
              <th style={styles.th}>Preview</th>
              <th style={styles.th}>Saved At</th>
              <th style={styles.th}>Action</th>
            </tr>
          </thead>
          <tbody>
            {reports.map((r, i) => (
              <tr key={r.id} style={{ background: i % 2 === 0 ? '#0f172a' : '#111827' }}>
                <td style={styles.td}>{r.id}</td>
                <td style={styles.td}><code style={{ color: '#60a5fa' }}>{r.alert_id}</code></td>
                <td style={styles.td}>{r.agent_name}</td>
                <td style={styles.td}><span style={styles.badge(r.severity)}>{r.severity}</span></td>
                <td style={styles.td} title={r.report_preview}>
                  <span style={{ color: '#94a3b8' }}>
                    {r.report_preview?.substring(0, 60)}...
                  </span>
                </td>
                <td style={styles.td} style={{ color: '#64748b', fontSize: '11px' }}>
                  {new Date(r.created_at).toLocaleString()}
                </td>
                <td style={styles.td}>
                  <button style={styles.viewBtn} onClick={() => viewFullReport(r.id)}>
                    View Full
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {/* Full Report Modal */}
      {selected && (
        <div style={styles.overlay} onClick={closeModal}>
          <div style={styles.modal} onClick={e => e.stopPropagation()}>
            <div style={styles.modalHeader}>
              <div style={styles.modalTitle}>
                📄 Full Report — {fullReport?.alert_id || '...'}
                {fullReport?.severity && (
                  <span style={{ ...styles.badge(fullReport.severity), marginLeft: '10px' }}>
                    {fullReport.severity}
                  </span>
                )}
              </div>
              <button style={styles.closeBtn} onClick={closeModal}>✕</button>
            </div>
            <div style={styles.modalBody}>
              {loadingFull && <div style={styles.loadingText}>Loading report...</div>}
              {fullReport?.error && <div style={{ color: '#fca5a5' }}>{fullReport.error}</div>}
              {fullReport?.report_text && (
                <pre style={styles.reportText}>{fullReport.report_text}</pre>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
