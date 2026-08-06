import React, { useState, useEffect, useMemo } from 'react';
import { IncidentReport } from '../types';
import { fetchSavedReports, fetchReportById } from '../api/vigilanceApi';
import SeverityBadge from './SeverityBadge';
import { 
  RefreshCw, 
  FileText, 
  Calendar, 
  Search, 
  Copy, 
  Check, 
  Shield, 
  FileCode, 
  AlertCircle,
  X,
  Eye
} from 'lucide-react';

export default function ReportsHistory() {
  const [reports, setReports] = useState<IncidentReport[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  
  // Selection and modal states
  const [activeReportId, setActiveReportId] = useState<string | null>(null);
  const [selectedReport, setSelectedReport] = useState<IncidentReport | null>(null);
  const [loadingReport, setLoadingReport] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [copied, setCopied] = useState(false);

  const loadReports = async () => {
    setLoading(true);
    setError('');
    try {
      const data = await fetchSavedReports();
      setReports(data || []);
    } catch (err: any) {
      setError(err.message || 'Failed to retrieve incident reports.');
    } finally {
      setLoading(false);
    }
  };

  const handleOpenReport = async (id: string) => {
    setActiveReportId(id);
    setLoadingReport(true);
    setCopied(false);
    try {
      const data = await fetchReportById(id);
      setSelectedReport(data);
    } catch (err: any) {
      console.error('Failed to load full report details:', err);
      // Fallback to local item if full fetch fails
      const local = reports.find(r => r.id === id);
      if (local) setSelectedReport(local);
    } finally {
      setLoadingReport(false);
    }
  };

  const handleCloseReport = () => {
    setActiveReportId(null);
    setSelectedReport(null);
    setCopied(false);
  };

  const handleCopyReport = () => {
    if (!selectedReport) return;
    navigator.clipboard.writeText(selectedReport.report_text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  useEffect(() => {
    loadReports();
  }, []);

  const formatDate = (isoStr: string) => {
    try {
      const d = new Date(isoStr);
      return d.toLocaleDateString('en-US', { 
        month: 'short', 
        day: 'numeric', 
        year: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
      });
    } catch (e) {
      return isoStr;
    }
  };

  // Filter reports based on search query
  const filteredReports = useMemo(() => {
    if (!searchQuery.trim()) return reports;
    const q = searchQuery.toLowerCase();
    return reports.filter(rep => 
      String(rep.id).toLowerCase().includes(q) ||
      rep.alert_id.toLowerCase().includes(q) ||
      rep.agent_name.toLowerCase().includes(q) ||
      (rep.title && rep.title.toLowerCase().includes(q)) ||
      (rep.preview && rep.preview.toLowerCase().includes(q))
    );
  }, [reports, searchQuery]);

  return (
    <div id="reports-tab-content" className="reports-history-wrapper">
      
      {/* Header Row */}
      <div className="reports-history-header">
        <div className="reports-title-desc">
          <div className="title-row">
            <h2>History</h2>
          </div>
          <p>
            Browse, search, and audit generated forensic summaries and security classifications.
          </p>
        </div>

        <div style={{ display: 'flex', gap: '10px', alignItems: 'center' }}>
          {/* Search box */}
          <div style={{ position: 'relative', display: 'flex', alignItems: 'center' }}>
            <Search size={14} style={{ position: 'absolute', left: '12px', color: 'var(--color-text-muted)' }} />
            <input 
              id="report-search-input"
              type="text"
              placeholder="Search reports..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              style={{
                padding: '8px 12px 8px 34px',
                borderRadius: '8px',
                background: 'var(--color-surface)',
                border: '1px solid var(--color-border)',
                color: 'var(--color-text-primary)',
                fontSize: '13px',
                outline: 'none',
                width: '220px'
              }}
            />
          </div>

          <button 
            id="btn-refresh-reports"
            onClick={loadReports} 
            className="btn btn-outline btn-sm"
            disabled={loading}
            style={{ display: 'flex', alignItems: 'center', gap: '6px' }}
          >
            <RefreshCw size={13} className={loading ? 'spin' : ''} />
            Refresh
          </button>
        </div>
      </div>

      {/* Loading State */}
      {loading ? (
        <div className="reports-skeleton-table">
          {[1, 2, 3, 4].map((num) => (
            <div key={num} className="skeleton-row shimmer" />
          ))}
        </div>
      ) : error ? (
        <div className="reports-error-card">
          <AlertCircle size={32} style={{ color: 'var(--sev-critical-text)' }} />
          <p>{error}</p>
          <button onClick={loadReports} className="btn btn-primary btn-sm">Retry</button>
        </div>
      ) : reports.length === 0 ? (
        <div className="reports-empty-state">
          <FileText size={48} className="empty-icon" />
          <h4>No Reports Available</h4>
          <p>
            Saved forensic incident reports will appear here once generated in the Alert Queue.
          </p>
        </div>
      ) : (
        <div className="reports-table-card">
          <div className="table-responsive">
            <table className="reports-table">
              <thead>
                <tr>
                  <th>Report ID</th>
                  <th>Alert ID</th>
                  <th>Host Node</th>
                  <th>Severity</th>
                  <th>Summary Preview</th>
                  <th>Created At</th>
                  <th style={{ textAlign: 'right' }}>Action</th>
                </tr>
              </thead>
              <tbody>
                {filteredReports.map((rep) => (
                  <tr key={rep.id} className="report-row-hover">
                    <td className="text-bold text-mono">
                      #{String(rep.id).slice(-6).toUpperCase()}
                    </td>
                    <td className="text-mono">
                      {rep.alert_id.substring(0, 8)}...
                    </td>
                    <td>{rep.agent_name}</td>
                    <td>
                      <SeverityBadge severity={rep.severity} />
                    </td>
                    <td>
                      <div className="text-preview">
                        {rep.title || rep.preview}
                      </div>
                    </td>
                    <td className="text-muted">
                      {formatDate(rep.created_at)}
                    </td>
                    <td style={{ textAlign: 'right' }}>
                      <button 
                        onClick={() => handleOpenReport(rep.id)}
                        className="btn btn-ghost btn-xs"
                        style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}
                      >
                        <Eye size={12} />
                        View Full
                      </button>
                    </td>
                  </tr>
                ))}
                {filteredReports.length === 0 && (
                  <tr>
                    <td colSpan={7} style={{ textAlign: 'center', padding: '24px', color: 'var(--color-text-secondary)' }}>
                      No matching incident records found.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* FULL REPORT DETAIL MODAL (Frosted Dark Overlay + Card Slide-in) */}
      {activeReportId && (
        <div className="modal-overlay" onClick={handleCloseReport}>
          <div className="modal-card" onClick={(e) => e.stopPropagation()}>
            {loadingReport ? (
              <div className="modal-loading-wrapper">
                <span className="spinner large" />
                <p>Retrieving secure ledger forensic dossier...</p>
              </div>
            ) : selectedReport ? (
              <>
                {/* Modal Header */}
                <div className="modal-header">
                  <div className="modal-title-group">
                    <span className="modal-title-badge">FORENSIC SECURITY ANALYSIS</span>
                    <h3 className="modal-title">
                      {selectedReport.title || `Incident Forensic Report for Alert ${selectedReport.alert_id.substring(0, 8)}`}
                    </h3>
                  </div>
                  <button className="modal-close-btn" onClick={handleCloseReport} title="Close dossier">
                    <X size={18} />
                  </button>
                </div>

                {/* Meta details bar */}
                <div className="modal-meta-bar">
                  <div className="modal-meta-item">
                    Dossier: <strong className="text-mono">#{String(selectedReport.id).toUpperCase()}</strong>
                  </div>
                  <div className="modal-meta-item">
                    Target Alert: <strong className="text-mono">{selectedReport.alert_id}</strong>
                  </div>
                  <div className="modal-meta-item">
                    Host: <strong>{selectedReport.agent_name}</strong>
                  </div>
                  <div className="modal-meta-item">
                    Classification: <strong>{selectedReport.severity}</strong>
                  </div>
                  <div className="modal-meta-item">
                    Compiled: <strong>{formatDate(selectedReport.created_at)}</strong>
                  </div>
                </div>

                {/* Report Body */}
                <div className="modal-body">
                  <pre className="modal-pre-block">{selectedReport.report_text}</pre>
                </div>

                {/* Modal Footer */}
                <div className="modal-footer">
                  <span className="modal-footer-brand">VIGILANCE AI Autonomous Triage</span>
                  <div style={{ display: 'flex', gap: '8px' }}>
                    <button 
                      className="btn btn-outline btn-sm" 
                      onClick={handleCopyReport}
                      style={{ display: 'flex', alignItems: 'center', gap: '6px' }}
                    >
                      {copied ? <Check size={14} style={{ color: '#10B981' }} /> : <Copy size={14} />}
                      {copied ? 'Copied to clipboard' : 'Copy Plaintext'}
                    </button>
                    <button className="btn btn-primary btn-sm" onClick={handleCloseReport}>
                      Close Ledger
                    </button>
                  </div>
                </div>
              </>
            ) : (
              <div className="modal-error-wrapper">
                <AlertCircle size={32} style={{ color: 'var(--sev-critical-text)' }} />
                <p>Failed to load full report details from database.</p>
                <button className="btn btn-outline btn-sm" onClick={() => handleOpenReport(activeReportId)}>Retry</button>
                <button className="btn btn-primary btn-sm" onClick={handleCloseReport} style={{ marginTop: '8px' }}>Close</button>
              </div>
            )}
          </div>
        </div>
      )}

    </div>
  );
}
