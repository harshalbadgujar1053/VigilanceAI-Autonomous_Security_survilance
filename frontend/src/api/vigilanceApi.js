const BASE_URL = 'http://127.0.0.1:8000';

// ──────────────────────────────────────────
// SAMPLE ALERTS (kept as fallback)
// ──────────────────────────────────────────
const SAMPLE_ALERTS = {
  rootkit_detection: {
    id: 'alert-001', timestamp: new Date().toISOString(),
    rule: { id: '510', level: 15, description: 'Rootkit detection: Hidden process or file detected', groups: ['rootkit', 'malware'] },
    agent: { id: '001', name: 'web-server-01', ip: '192.168.1.101' },
    data: { process: 'hidden_proc', file: '/dev/.rootkit', technique: 'T1014' },
    location: '/var/ossec/logs/alerts.log'
  },
  ransomware_detected: {
    id: 'alert-002', timestamp: new Date().toISOString(),
    rule: { id: '87105', level: 14, description: 'Ransomware detected: Mass file encryption in progress', groups: ['ransomware', 'malware'] },
    agent: { id: '002', name: 'file-server-02', ip: '192.168.1.102' },
    data: { files_encrypted: 1500, extension: '.locked', ransom_note: 'READ_ME.txt' },
    location: '/var/ossec/logs/alerts.log'
  },
  ssh_brute_force: {
    id: 'alert-003', timestamp: new Date().toISOString(),
    rule: { id: '5763', level: 10, description: 'SSH brute force attack — multiple failed logins', groups: ['authentication_failed', 'ssh'] },
    agent: { id: '003', name: 'bastion-host-03', ip: '192.168.1.103' },
    data: { src_ip: '45.33.32.156', attempts: 847, user: 'root' },
    location: '/var/log/auth.log'
  },
  sql_injection: {
    id: 'alert-004', timestamp: new Date().toISOString(),
    rule: { id: '31103', level: 9, description: 'SQL injection attempt detected in web request', groups: ['web', 'attack', 'sql_injection'] },
    agent: { id: '004', name: 'web-app-04', ip: '192.168.1.104' },
    data: { src_ip: '198.51.100.23', url: '/api/login', payload: "' OR 1=1--" },
    location: '/var/log/nginx/access.log'
  },
  privilege_escalation: {
    id: 'alert-005', timestamp: new Date().toISOString(),
    rule: { id: '5303', level: 7, description: 'Privilege escalation attempt via sudo abuse', groups: ['privilege_escalation'] },
    agent: { id: '005', name: 'dev-workstation-05', ip: '192.168.1.105' },
    data: { user: 'devuser', command: 'sudo su -', technique: 'T1548' },
    location: '/var/log/auth.log'
  },
  port_scan: {
    id: 'alert-006', timestamp: new Date().toISOString(),
    rule: { id: '40111', level: 6, description: 'Port scan detected from external IP', groups: ['recon', 'network'] },
    agent: { id: '006', name: 'firewall-06', ip: '192.168.1.1' },
    data: { src_ip: '203.0.113.42', ports_scanned: 1024, protocol: 'TCP SYN' },
    location: '/var/log/firewall.log'
  },
  low_disk_space: {
    id: 'alert-007', timestamp: new Date().toISOString(),
    rule: { id: '531', level: 3, description: 'Low disk space warning on critical partition', groups: ['system', 'low_diskspace'] },
    agent: { id: '007', name: 'db-server-07', ip: '192.168.1.107' },
    data: { partition: '/var', usage_percent: 92, free_gb: 4.2 },
    location: '/var/ossec/logs/alerts.log'
  },
  failed_login: {
    id: 'alert-008', timestamp: new Date().toISOString(),
    rule: { id: '2502', level: 2, description: 'Failed login attempt — invalid credentials', groups: ['authentication_failed'] },
    agent: { id: '008', name: 'workstation-08', ip: '192.168.1.108' },
    data: { user: 'jdoe', src_ip: '192.168.1.55', method: 'keyboard-interactive' },
    location: '/var/log/auth.log'
  }
};

// ──────────────────────────────────────────
// HEALTH CHECK
// ──────────────────────────────────────────
export async function checkBackendHealth() {
  try {
    const res = await fetch(`${BASE_URL}/`);
    return res.ok;
  } catch {
    return false;
  }
}

// ──────────────────────────────────────────
// FETCH ALERTS (sample for now)
// ──────────────────────────────────────────
export async function fetchSiemAlerts() {
  return Object.values(SAMPLE_ALERTS);
}

// ──────────────────────────────────────────
// CLASSIFY ALERT
// ──────────────────────────────────────────
export async function classifyAlert(alert) {
  const res = await fetch(`${BASE_URL}/classify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ alert })
  });
  if (!res.ok) throw new Error(`Classify failed: ${res.status}`);
  const data = await res.json();

  // Auto-save classification to DB
  if (data.success && data.classification) {
    const c = data.classification;
    saveClassificationToDB({
      alert_id: alert.id,
      severity: c.severity || 'UNKNOWN',
      reasoning: c.reasoning || '',
      mitre_tactics: Array.isArray(c.mitre_tactics)
        ? c.mitre_tactics.join(', ')
        : (c.mitre_tactics || '')
    }).catch(err => console.warn('DB save classification failed:', err));
  }

  return data;
}

// ──────────────────────────────────────────
// GENERATE REPORT
// ──────────────────────────────────────────
export async function generateReport(alert, classification) {
  const res = await fetch(`${BASE_URL}/report`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ alert, classification })
  });
  if (!res.ok) throw new Error(`Report failed: ${res.status}`);
  const data = await res.json();

  // Auto-save report to DB
  if (data.success && data.report) {
    saveReportToDB({
      alert_id: alert.id,
      severity: classification?.severity || 'UNKNOWN',
      agent_name: alert?.agent?.name || 'Unknown',
      report_text: typeof data.report === 'string'
        ? data.report
        : JSON.stringify(data.report)
    }).catch(err => console.warn('DB save report failed:', err));
  }

  return data;
}

// ──────────────────────────────────────────
// DB SAVE FUNCTIONS
// ──────────────────────────────────────────
export async function saveClassificationToDB(payload) {
  const res = await fetch(`${BASE_URL}/classifications/save`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });
  return res.json();
}

export async function saveReportToDB(payload) {
  const res = await fetch(`${BASE_URL}/reports/save`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });
  return res.json();
}

// ──────────────────────────────────────────
// FETCH SAVED REPORTS FROM DB
// ──────────────────────────────────────────
export async function fetchSavedReports() {
  const res = await fetch(`${BASE_URL}/reports`);
  if (!res.ok) throw new Error('Failed to fetch reports');
  return res.json();
}

export async function fetchReportById(id) {
  const res = await fetch(`${BASE_URL}/reports/${id}`);
  if (!res.ok) throw new Error('Report not found');
  return res.json();
}
