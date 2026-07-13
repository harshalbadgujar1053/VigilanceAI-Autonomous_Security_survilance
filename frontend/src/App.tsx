import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { Alert } from './types';
import { checkBackendHealth, fetchSiemAlerts, fetchHealth } from './api/vigilanceApi';
import AlertCard from './components/AlertCard';
import SOCCharts from './components/SOCCharts';
import ReportsHistory from './components/ReportsHistory';
import VantaBackground from './components/VantaBackground';
import VigilanceLogo from './components/VigilanceLogo';
import { 
  Shield, 
  RefreshCw, 
  LogOut, 
  Search, 
  SlidersHorizontal,
  ChevronDown,
  Clock,
  CheckCircle,
  XCircle,
  Database,
  Grid
} from 'lucide-react';

interface AppProps {
  onLogout: () => void;
}

// LiveClock Sub-component: Updates every 1s, displays HH:MM:SS + DD Mon YYYY
function LiveClock() {
  const [time, setTime] = useState(new Date());

  useEffect(() => {
    const timer = setInterval(() => {
      setTime(new Date());
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  const formatTime = (d: Date) => {
    return d.toLocaleTimeString('en-US', { 
      hour12: false, 
      hour: '2-digit', 
      minute: '2-digit', 
      second: '2-digit' 
    });
  };

  const formatDate = (d: Date) => {
    return d.toLocaleDateString('en-US', {
      day: '2-digit',
      month: 'short',
      year: 'numeric'
    });
  };

  return (
    <div id="live-clock" className="live-clock-wrapper">
      <Clock size={14} className="clock-icon" />
      <span className="clock-time">{formatTime(time)}</span>
      <span className="clock-separator">•</span>
      <span className="clock-date">{formatDate(time)}</span>
    </div>
  );
}

export default function App({ onLogout }: AppProps) {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [backendOk, setBackendOk] = useState(false);
  const [tab, setTab] = useState<'queue' | 'analytics' | 'reports'>('queue');
  const [dataSource, setDataSource] = useState<'live' | 'sample' | 'loading'>('loading');
  const [healthInfo, setHealthInfo] = useState<any>(null);

  // Filter & Sort State
  const [filter, setFilter] = useState<'ALL' | 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'>('ALL');
  const [search, setSearch] = useState('');
  const [analyticsSearch, setAnalyticsSearch] = useState('');
  const [sort, setSort] = useState<'level_desc' | 'level_asc' | 'id_asc'>('level_desc');

  // Load backend status & static alerts
  const syncDashboard = async () => {
    setLoading(true);
    setError('');
    try {
      const isOk = await checkBackendHealth();
      setBackendOk(isOk);

      const siemAlerts = await fetchSiemAlerts();
      setAlerts(siemAlerts);

      // Detect data source from the custom _source property in transformed alerts
      const src = siemAlerts.length > 0 && (siemAlerts[0] as any)._source === 'live' ? 'live' : 'sample';
      setDataSource(src);

      // Fetch detailed health status
      const h = await fetchHealth();
      if (h.success) {
        setHealthInfo(h.health);
      }
    } catch (err: any) {
      setError(err.message || 'Failed to sync SOC metrics.');
      setDataSource('sample');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    syncDashboard();
  }, []);

  // Auto-refresh every 30 seconds
  useEffect(() => {
    const interval = setInterval(() => {
      syncDashboard();
    }, 30000);
    return () => clearInterval(interval);
  }, []);

  // Compute stats based on standard rules
  // Severity counting: level >= 12 is CRITICAL, >= 8 is HIGH, >= 4 is MEDIUM, else LOW
  const totalCount = alerts.length;
  const criticalCount = alerts.filter(a => a.rule.level >= 12).length;
  const highCount = alerts.filter(a => a.rule.level >= 8 && a.rule.level < 12).length;
  const mediumCount = alerts.filter(a => a.rule.level >= 4 && a.rule.level < 8).length;
  const lowCount = alerts.filter(a => a.rule.level < 4).length;

  // Filter and sort computation
  const processedAlerts = alerts
    .filter(a => {
      // 1. Filter by category
      if (filter !== 'ALL') {
        const lvl = a.rule.level;
        let cat = 'LOW';
        if (lvl >= 12) cat = 'CRITICAL';
        else if (lvl >= 8) cat = 'HIGH';
        else if (lvl >= 4) cat = 'MEDIUM';

        if (cat !== filter) return false;
      }

      // 2. Filter by search query
      if (search.trim() !== '') {
        const query = search.toLowerCase();
        const descMatch = a.rule.description.toLowerCase().includes(query);
        const nameMatch = a.agent.name.toLowerCase().includes(query);
        const ipMatch = a.agent.ip.includes(query);
        const idMatch = a.id.toLowerCase().includes(query);
        const ruleIdMatch = a.rule.id.toLowerCase().includes(query);

        return descMatch || nameMatch || ipMatch || idMatch || ruleIdMatch;
      }

      return true;
    })
    .sort((a, b) => {
      // 3. Sort options
      if (sort === 'level_desc') {
        return b.rule.level - a.rule.level;
      } else if (sort === 'level_asc') {
        return a.rule.level - b.rule.level;
      } else if (sort === 'id_asc') {
        return a.id.localeCompare(b.id);
      }
      return 0;
    });

  const handleLogoutClick = () => {
    localStorage.removeItem('vigilance_auth');
    onLogout();
  };

  return (
    <div id="soc-dashboard-shell" className="app-shell">
      {/* Ambient background animations */}
      <VantaBackground />

      <div style={{ position: 'relative', zIndex: 1, display: 'flex', flexDirection: 'column', minHeight: '100vh', width: '100%' }}>
        {/* 1. Navbar */}
        <nav id="navbar" className="navbar">
          <div className="nav-container">
            {/* Left Brand Area */}
            <div className="nav-brand-group">
              <div className="logo-spinner-box" style={{ background: 'transparent', width: 'auto', height: 'auto' }}>
                <VigilanceLogo size={38} />
              </div>
              <div className="nav-brand-text">
                <h1>Vigilance AI</h1>
                <p>Autonomous Security Surveillance</p>
              </div>
            </div>

            {/* Center Tabs Pills */}
            <div id="nav-tabs" className="nav-tabs-pills">
              <button 
                id="tab-queue"
                onClick={() => setTab('queue')} 
                className={`tab-pill ${tab === 'queue' ? 'active' : ''}`}
              >
                Alert Queue
              </button>
              <button 
                id="tab-analytics"
                onClick={() => setTab('analytics')} 
                className={`tab-pill ${tab === 'analytics' ? 'active' : ''}`}
              >
                Dashboard
              </button>
              <button 
                id="tab-reports"
                onClick={() => setTab('reports')} 
                className={`tab-pill ${tab === 'reports' ? 'active' : ''}`}
              >
                Creation History
              </button>
            </div>

            {/* Right Status Actions */}
            <div className="nav-status-actions">
              {dataSource === 'live' ? (
                <div style={{ display: 'flex', alignItems: 'center', gap: '5px', fontSize: '11px', color: '#10B981', background: 'rgba(16, 185, 129, 0.05)', padding: '4px 10px', borderRadius: '12px', border: '1px solid rgba(16, 185, 129, 0.15)', fontWeight: 600 }}>
                  <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: '#10B981', display: 'inline-block' }} />
                  Live Data
                </div>
              ) : (
                <div style={{ display: 'flex', alignItems: 'center', gap: '5px', fontSize: '11px', color: '#F59E0B', background: 'rgba(245, 158, 11, 0.05)', padding: '4px 10px', borderRadius: '12px', border: '1px solid rgba(245, 158, 11, 0.15)', fontWeight: 600 }}>
                  <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: '#F59E0B', display: 'inline-block' }} />
                  Sample Data
                </div>
              )}
              {healthInfo && (
                <div style={{ display: 'flex', gap: '6px', fontSize: '11px', color: '#94A3B8', fontWeight: 500, marginRight: '4px' }}>
                  <span>DB: {healthInfo.database ? '✓' : '✕'}</span>
                  <span>Ollama: {healthInfo.ollama ? '✓' : '✕'}</span>
                </div>
              )}
              <LiveClock />

              <button 
                id="btn-refresh-dashboard"
                onClick={syncDashboard} 
                className="nav-action-btn refresh-btn"
                disabled={loading}
                title="Manual Dashboard Refresh"
              >
                <RefreshCw size={15} className={loading ? 'spin' : ''} />
              </button>

              <button 
                id="btn-logout"
                onClick={handleLogoutClick} 
                className="nav-action-btn logout-btn"
                title="Logout session"
              >
                <LogOut size={15} />
              </button>
            </div>
          </div>
        </nav>

        {/* 2. Stat Strip */}
        <div id="stat-strip" className="stat-strip-container">
          <div className="stat-strip-inner">
            <div className="stat-grid">
              <div onClick={() => { setTab('queue'); setFilter('ALL'); }} className={`stat-pill-card total ${filter === 'ALL' && tab === 'queue' ? 'focus-ring' : ''}`}>
                <span className="stat-title">Total Alerts</span>
                <span className="stat-val">{totalCount}</span>
              </div>

              <div onClick={() => { setTab('queue'); setFilter('CRITICAL'); }} className={`stat-pill-card critical ${filter === 'CRITICAL' && tab === 'queue' ? 'focus-ring' : ''}`}>
                <span className="stat-title">Critical</span>
                <span className="stat-val">{criticalCount}</span>
              </div>

              <div onClick={() => { setTab('queue'); setFilter('HIGH'); }} className={`stat-pill-card high ${filter === 'HIGH' && tab === 'queue' ? 'focus-ring' : ''}`}>
                <span className="stat-title">High</span>
                <span className="stat-val">{highCount}</span>
              </div>

              <div onClick={() => { setTab('queue'); setFilter('MEDIUM'); }} className={`stat-pill-card medium ${filter === 'MEDIUM' && tab === 'queue' ? 'focus-ring' : ''}`}>
                <span className="stat-title">Medium</span>
                <span className="stat-val">{mediumCount}</span>
              </div>

              <div onClick={() => { setTab('queue'); setFilter('LOW'); }} className={`stat-pill-card low ${filter === 'LOW' && tab === 'queue' ? 'focus-ring' : ''}`}>
                <span className="stat-title">Low</span>
                <span className="stat-val">{lowCount}</span>
              </div>
            </div>
          </div>
        </div>

        {/* 3. Main Body */}
        <main className="main-content-layout">
          <AnimatePresence mode="wait">
            {/* ALERT QUEUE TAB */}
            {tab === 'queue' && (
              <motion.div 
                key="queue"
                initial={{ opacity: 0, y: 15 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -15 }}
                transition={{ duration: 0.25, ease: 'easeOut' }}
                id="queue-tab-view" 
                className="queue-tab-wrapper"
              >
                {/* Toolbar */}
                <div className="toolbar-card">
                  <div className="toolbar-left">
                    <div className="search-box-wrapper">
                      <Search size={16} className="search-icon" />
                      <input 
                        id="search-input"
                        type="text" 
                        placeholder="Search by description, host, IP or Rule ID..."
                        value={search}
                        onChange={(e) => setSearch(e.target.value)}
                        className="search-input-field"
                      />
                    </div>
                  </div>

                  <div className="toolbar-right">
                    {/* Sort dropdown */}
                    <div className="sort-box-wrapper">
                      <SlidersHorizontal size={14} className="sort-icon" />
                      <select 
                        id="sort-select"
                        value={sort} 
                        onChange={(e: any) => setSort(e.target.value)}
                        className="sort-select-field"
                      >
                        <option value="level_desc">Level: Max to Min</option>
                        <option value="level_asc">Level: Min to Max</option>
                        <option value="id_asc">Alert ID: Alphabetical</option>
                      </select>
                    </div>

                    {/* Filter pill selectors */}
                    <div className="filter-pills-row">
                      {(['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const).map((lvl) => (
                        <button
                          id={`btn-filter-${lvl.toLowerCase()}`}
                          key={lvl}
                          onClick={() => setFilter(lvl)}
                          className={`filter-pill-btn ${lvl.toLowerCase()} ${filter === lvl ? 'active' : ''}`}
                        >
                          {lvl}
                        </button>
                      ))}
                    </div>
                  </div>
                </div>

                {/* Count Tag */}
                <div className="result-indicator-row">
                  <p className="result-indicator-text">
                    Showing <strong>{processedAlerts.length}</strong> of <strong>{totalCount}</strong> security events
                  </p>
                </div>

                {/* Content list */}
                {loading ? (
                  <div className="queue-skeleton-container">
                    {[1, 2, 3].map((num) => (
                      <div key={num} className="skeleton-card-item shimmer" />
                    ))}
                  </div>
                ) : error ? (
                  <div id="queue-error" className="queue-error-box">
                    <XCircle size={36} className="text-critical" />
                    <h4>Sync Failure</h4>
                    <p>{error}</p>
                    <button onClick={syncDashboard} className="btn btn-primary btn-sm">Retry Synchronize</button>
                  </div>
                ) : processedAlerts.length === 0 ? (
                  <div id="queue-empty" className="queue-empty-box">
                    <Shield size={48} className="empty-icon" />
                    <h4>No Matching Alerts Found</h4>
                    <p>Try modifying your text search filters or categories.</p>
                  </div>
                ) : (
                  <div id="alerts-list-container" className="alerts-list-wrapper">
                    {processedAlerts.map((alert, index) => (
                      <AlertCard 
                        key={alert.id} 
                        alert={alert} 
                        index={index} 
                      />
                    ))}
                  </div>
                )}
              </motion.div>
            )}

            {/* KPI DASHBOARD TAB */}
            {tab === 'analytics' && (
              <motion.div 
                key="analytics"
                initial={{ opacity: 0, y: 15 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -15 }}
                transition={{ duration: 0.25, ease: 'easeOut' }}
                id="analytics-tab-view" 
                className="analytics-tab-wrapper"
              >
                <div className="analytics-tab-header">
                  <div className="analytics-tab-title">
                    <h2>Dashboard Overview</h2>
                    <p>Aggregated heuristic insights, severity spreads, and system vulnerabilities</p>
                  </div>
                  <div className="search-box-wrapper dashboard-search-bar" style={{ maxWidth: '780px', width: '100%' }}>
                    <Search size={16} className="search-icon" />
                    <input 
                      id="analytics-search-input"
                      type="text" 
                      placeholder="Filter dashboard metrics & logs..."
                      value={analyticsSearch}
                      onChange={(e) => setAnalyticsSearch(e.target.value)}
                      className="search-input-field"
                    />
                  </div>
                </div>
                <SOCCharts 
                  alerts={alerts.filter(a => {
                    if (analyticsSearch.trim() === '') return true;
                    const query = analyticsSearch.toLowerCase();
                    const descMatch = a.rule.description.toLowerCase().includes(query);
                    const nameMatch = a.agent.name.toLowerCase().includes(query);
                    const ipMatch = a.agent.ip.includes(query);
                    const idMatch = a.id.toLowerCase().includes(query);
                    const ruleIdMatch = a.rule.id.toLowerCase().includes(query);
                    return descMatch || nameMatch || ipMatch || idMatch || ruleIdMatch;
                  })} 
                />
              </motion.div>
            )}

            {/* REPORTS HISTORY TAB */}
            {tab === 'reports' && (
              <motion.div 
                key="reports"
                initial={{ opacity: 0, y: 15 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -15 }}
                transition={{ duration: 0.25, ease: 'easeOut' }}
                id="reports-tab-view" 
                className="reports-tab-wrapper"
              >
                <ReportsHistory />
              </motion.div>
            )}
          </AnimatePresence>
        </main>
      </div>
    </div>
  );
}
