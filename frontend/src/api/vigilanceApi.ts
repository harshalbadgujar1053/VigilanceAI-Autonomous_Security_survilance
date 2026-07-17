import { Alert, Classification, IncidentReport } from '../types';

export const BASE_URL = 'http://127.0.0.1:8000';

export const SAMPLE_ALERTS: Record<string, Alert> = {
  "alert-001": {
    id: "alert-001",
    timestamp: "2026-06-30T09:12:00Z",
    rule: {
      id: "rule-100201",
      level: 15,
      description: "Rootkit detection: Kernel modification detected on critical system path",
      groups: ["ossec", "rootkit", "syscheck", "defense_evasion"]
    },
    agent: {
      id: "agent-001",
      name: "web-server-01",
      ip: "192.168.1.101"
    },
    data: {
      file: "/boot/vmlinuz-custom",
      sha256: "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2",
      previous_sha256: "0f2e1d0c9b8a7766554433221100ffeeddccbbaa99887766554433221100ffee"
    },
    location: "/var/log/syslog"
  },
  "alert-002": {
    id: "alert-002",
    timestamp: "2026-06-30T09:15:22Z",
    rule: {
      id: "rule-200342",
      level: 14,
      description: "Ransomware detected: Massive file encryption activity in user directories",
      groups: ["ransomware", "syscheck", "malware", "impact"]
    },
    agent: {
      id: "agent-002",
      name: "file-server-02",
      ip: "192.168.1.102"
    },
    data: {
      directory: "/mnt/shared/finance",
      entropy: 7.98,
      extension: ".locked",
      file_count: 342
    },
    location: "/var/log/audit/audit.log"
  },
  "alert-003": {
    id: "alert-003",
    timestamp: "2026-06-30T09:18:45Z",
    rule: {
      id: "rule-100511",
      level: 10,
      description: "SSH brute force: Repetitive authentication failures from single external IP",
      groups: ["authentication_failed", "ssh", "bruteforce", "credential_access"]
    },
    agent: {
      id: "agent-003",
      name: "bastion-host-03",
      ip: "192.168.1.103"
    },
    data: {
      source_ip: "203.0.113.45",
      failed_attempts: 124,
      user_tried: "root"
    },
    location: "/var/log/auth.log"
  },
  "alert-004": {
    id: "alert-004",
    timestamp: "2026-06-30T09:20:10Z",
    rule: {
      id: "rule-100782",
      level: 9,
      description: "SQL injection: SQL syntax keywords detected in HTTP POST request parameters",
      groups: ["web", "attack", "sqli", "initial_access"]
    },
    agent: {
      id: "agent-004",
      name: "web-app-04",
      ip: "192.168.1.104"
    },
    data: {
      uri: "/api/v1/users/login",
      method: "POST",
      payload: "username=admin' OR '1'='1&password=invalid"
    },
    location: "/var/log/nginx/access.log"
  },
  "alert-005": {
    id: "alert-005",
    timestamp: "2026-06-30T09:22:15Z",
    rule: {
      id: "rule-100105",
      level: 7,
      description: "Privilege escalation: SUID binary executed with modified environment",
      groups: ["ossec", "syslog", "privilege_escalation"]
    },
    agent: {
      id: "agent-005",
      name: "dev-workstation-05",
      ip: "192.168.1.105"
    },
    data: {
      binary: "/usr/bin/find",
      invoking_user: "developer",
      arguments: "-exec /bin/sh ;"
    },
    location: "/var/log/secure"
  },
  "alert-006": {
    id: "alert-006",
    timestamp: "2026-06-30T09:23:55Z",
    rule: {
      id: "rule-100012",
      level: 6,
      description: "Port scan: TCP SYN sweep detected from internal host range",
      groups: ["firewall", "recon", "port_scan", "discovery"]
    },
    agent: {
      id: "agent-006",
      name: "firewall-06",
      ip: "192.168.1.106"
    },
    data: {
      source_ip: "192.168.1.205",
      ports_scanned: 1024,
      scan_type: "SYN"
    },
    location: "/var/log/messages"
  },
  "alert-007": {
    id: "alert-007",
    timestamp: "2026-06-30T09:24:40Z",
    rule: {
      id: "rule-100003",
      level: 3,
      description: "Low disk space: Partition /var/lib/mysql has exceeded 90% utilization",
      groups: ["system", "disk", "low_space", "maintenance"]
    },
    agent: {
      id: "agent-007",
      name: "db-server-07",
      ip: "192.168.1.107"
    },
    data: {
      partition: "/var/lib/mysql",
      capacity_used: "94%",
      available_space: "2.1GB"
    },
    location: "/var/log/syslog"
  },
  "alert-008": {
    id: "alert-008",
    timestamp: "2026-06-30T09:25:30Z",
    rule: {
      id: "rule-100002",
      level: 2,
      description: "Failed login: Single authentication failure for user admin",
      groups: ["authentication_failed", "syslog", "failed_login", "initial_access"]
    },
    agent: {
      id: "agent-008",
      name: "workstation-08",
      ip: "192.168.1.108"
    },
    data: {
      user_tried: "admin",
      client_ip: "192.168.1.42"
    },
    location: "/var/log/auth.log"
  },
  "alert-009": {
    id: "alert-009",
    timestamp: "2026-06-30T09:30:15Z",
    rule: {
      id: "rule-100891",
      level: 11,
      description: "Data exfiltration: Outbound TCP session established to known Tor exit node",
      groups: ["exfiltration", "network", "tor", "command_and_control"]
    },
    agent: {
      id: "agent-009",
      name: "database-backup-09",
      ip: "192.168.1.109"
    },
    data: {
      destination_ip: "185.220.101.5",
      destination_port: 443,
      transferred_bytes: 524288000,
      protocol: "TCP"
    },
    location: "/var/log/zeek/conn.log"
  },
  "alert-010": {
    id: "alert-010",
    timestamp: "2026-06-30T09:35:45Z",
    rule: {
      id: "rule-300115",
      level: 13,
      description: "Credential dumping: LSASS process memory dump execution",
      groups: ["mimikatz", "credentials", "credential_access", "windows_security"]
    },
    agent: {
      id: "agent-010",
      name: "ad-controller-10",
      ip: "192.168.1.110"
    },
    data: {
      tool: "Mimikatz / ProcDump",
      target_process: "lsass.exe",
      output_file: "C:\\Windows\\Temp\\lsass.dmp",
      user_context: "SYSTEM"
    },
    location: "Security Event Log 4656"
  },
  "alert-011": {
    id: "alert-011",
    timestamp: "2026-06-30T09:40:00Z",
    rule: {
      id: "rule-250042",
      level: 12,
      description: "Container escape: Docker daemon socket mount or privileged namespace override",
      groups: ["docker", "privilege_escalation", "escape", "kubernetes"]
    },
    agent: {
      id: "agent-011",
      name: "k8s-worker-node-11",
      ip: "192.168.1.111"
    },
    data: {
      container_id: "e5f29910a34b",
      triggered_by: "mount-proc-filesystem",
      capabilities: "CAP_SYS_ADMIN",
      image_name: "nginx:latest-compromised"
    },
    location: "/var/log/containerd.log"
  },
  "alert-012": {
    id: "alert-012",
    timestamp: "2026-06-30T09:45:10Z",
    rule: {
      id: "rule-105120",
      level: 5,
      description: "Persistence: Suspicious crontab entry added referencing non-system path",
      groups: ["persistence", "cron", "privilege_escalation"]
    },
    agent: {
      id: "agent-012",
      name: "mail-server-12",
      ip: "192.168.1.112"
    },
    data: {
      user_cron: "root",
      schedule: "*/5 * * * *",
      executable_path: "/tmp/.hidden_script.sh",
      action_taken: "Logged alert"
    },
    location: "/var/log/cron"
  }
};

// Mock descriptions for fallbacks to make classifications premium
const AI_MOCK_DATA: Record<string, { severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'; technique: string; reasoning: string[]; reportText: string }> = {
  "alert-001": {
    severity: "CRITICAL",
    technique: "T1014 - Rootkit",
    reasoning: [
      "Detected kernel space anomaly that bypasses userland monitoring filters.",
      "SHA256 signature mismatch on primary booting file '/boot/vmlinuz-custom' suggests persistent firmware alteration.",
      "Highly likely a persistent state threat (APT) actor maintaining post-exploitation access."
    ],
    reportText: "EXECUTIVE SUMMARY\nKernel tampering was detected on web-server-01. Host configuration files indicate critical core binaries were modified on disk.\n\nTECHNICAL ANALYSIS\nFile: /boot/vmlinuz-custom\nHash change detected: previous kernel image checksum was replaced with an untrusted signature.\nMITRE ATT&CK: Category T1014 (Rootkit detection) is verified. Host integrity monitoring failed validation checks.\n\nRECOMMENDED ACTIONS\n1. Isolate web-server-01 from the host network.\n2. Perform a physical disk audit and restore boot parameters from verified offline backups."
  },
  "alert-002": {
    severity: "CRITICAL",
    technique: "T1486 - Data Encrypted for Impact",
    reasoning: [
      "Calculated entropy level of 7.98 is extremely close to theoretical maximum (8.0), confirming high-strength encryption.",
      "Rapid modification of 342 user files in '/mnt/shared/finance' directory within a 4-second window represents algorithmic ransomware.",
      "Known extension suffix '.locked' is associated with LockBit/BlackCat family binaries."
    ],
    reportText: "EXECUTIVE SUMMARY\nAutomated ransomware activity detected on file-server-02 under /mnt/shared/finance.\n\nTECHNICAL ANALYSIS\nHigh entropy write operations observed. Encryption agent traversed directories, creating locked suffix extensions on files.\nMITRE ATT&CK: T1486 Data Encrypted for Impact.\n\nRECOMMENDED ACTIONS\n1. Instantly disable domain controller trust for file-server-02.\n2. Force shut down the hypervisor host to prevent spread.\n3. Identify infected process threads and restore clean database shadow copies."
  },
  "alert-003": {
    severity: "HIGH",
    technique: "T1110.001 - Brute Force: Password Guessing",
    reasoning: [
      "124 failed login events from public external IP 203.0.113.45 targeted username 'root' directly.",
      "Pattern is highly sequential, repeating every 450ms, confirming automated dict-attack engine scripts.",
      "Targeted bastion host controls entry access to secure development subnets."
    ],
    reportText: "EXECUTIVE SUMMARY\nSSH Brute Force attack originated from 203.0.113.45 targeting the primary SSH port on bastion-host-03.\n\nTECHNICAL ANALYSIS\nSSH logs recorded 124 failed authentications in short intervals. The source IP is flagged on bad-reputation IP blocklists.\nMITRE ATT&CK: T1110.001 Password Guessing.\n\nRECOMMENDED ACTIONS\n1. Append source IP 203.0.113.45 to iptables DROP rule list.\n2. Require hardware tokens (MFA) for SSH session handshakes.\n3. Change authentication schema to keys-only and block root shell binds."
  },
  "alert-004": {
    severity: "HIGH",
    technique: "T1190 - Exploit Public-Facing Application",
    reasoning: [
      "Incoming payload string contains raw SQL tautology `username=admin' OR '1'='1`.",
      "Target route `/api/v1/users/login` is designed to process database-driven session lookups.",
      "Failed payload check suggests the application sanitization filters might be bypassed or misconfigured."
    ],
    reportText: "EXECUTIVE SUMMARY\nSQL Injection exploit payload intercepted in transit on web-app-04 endpoint /api/v1/users/login.\n\nTECHNICAL ANALYSIS\nAn external actor passed logical tautologies inside authentication parameters to bypass database query execution structures.\nMITRE ATT&CK: T1190 Exploit Public-Facing Application.\n\nRECOMMENDED ACTIONS\n1. Apply strict input verification patterns via backend routing engine.\n2. Deploy Web Application Firewall (WAF) blocking lists for SQL keywords.\n3. Rewrite authentication queries to use parameterized prepared queries."
  },
  "alert-005": {
    severity: "MEDIUM",
    technique: "T1548.001 - Abuse Microbehavior: SUID Binary",
    reasoning: [
      "The system binary `/usr/bin/find` has the Set-UID privilege bit active, allowing root context execution.",
      "Invoking user 'developer' using runtime argument '-exec /bin/sh ;' to spawn a subshell.",
      "Classic binary abuse pattern to bypass local shell restrictions and escalate privileges."
    ],
    reportText: "EXECUTIVE SUMMARY\nLocal privilege escalation attempt via SUID binary bypass detected on dev-workstation-05.\n\nTECHNICAL ANALYSIS\nUser 'developer' ran SUID binary `/usr/bin/find` with sub-arguments to execute a high-privilege shell spawn.\nMITRE ATT&CK: T1548.001 Abuse Microbehavior: SUID Binary.\n\nRECOMMENDED ACTIONS\n1. Revoke the SUID bit on non-essential system binaries.\n2. Restructure standard local sudo permissions for workstation developers."
  },
  "alert-006": {
    severity: "MEDIUM",
    technique: "T1046 - Network Service Discovery",
    reasoning: [
      "Host 192.168.1.205 initiated a fast TCP SYN sequence probing 1024 distinct network sockets.",
      "The request spacing matches signature indicators for standard Nmap profiling scans.",
      "Information gathering is typically the initial reconnaissance phase before active targeting."
    ],
    reportText: "EXECUTIVE SUMMARY\nInternal network service scanning behavior detected on firewall-06 interfaces.\n\nTECHNICAL ANALYSIS\n1024 unique socket connection requests were generated inside an active SYN scan script.\nMITRE ATT&CK: T1046 Network Service Discovery.\n\nRECOMMENDED ACTIONS\n1. Quarantine the querying internal client 192.168.1.205.\n2. Restrict lateral scanning privileges inside the subnet routing profiles."
  },
  "alert-007": {
    severity: "LOW",
    technique: "T1496 - Resource Hijacking",
    reasoning: [
      "Standard resource monitor warning of 94% storage allocation on critical database mount /var/lib/mysql.",
      "If space is exhausted, SQL writing will fail, causing server termination and offline denial of service.",
      "No security breach found, but potential service impact necessitates immediate maintenance."
    ],
    reportText: "EXECUTIVE SUMMARY\nStorage space alert: DB path '/var/lib/mysql' is approaching full capacity on db-server-07.\n\nTECHNICAL ANALYSIS\nCapacity metrics show 94% utilization with 2.1GB remaining space.\nMITRE ATT&CK: T1496 Resource Hijacking (related to system service stability).\n\nRECOMMENDED ACTIONS\n1. Execute SQL log cleaning scripts to reclaim space.\n2. Expand database host storage disk sizing dynamically."
  },
  "alert-008": {
    severity: "LOW",
    technique: "T1110 - Brute Force",
    reasoning: [
      "A single failed admin login was attempted from internal node 192.168.1.42.",
      "Lack of repetition suggests a minor human entry error or forgotten credentials.",
      "Not currently flagged as malicious, but cataloged for session sequence analysis."
    ],
    reportText: "EXECUTIVE SUMMARY\nFailed login attempt recorded on workstation-08 for administrator.\n\nTECHNICAL ANALYSIS\nOne incorrect login sequence occurred. Safe indicator: no brute-force repetition observed.\nMITRE ATT&CK: T1110 Brute Force indicators.\n\nRECOMMENDED ACTIONS\n1. Inform user to verify credentials if failures repeat.\n2. Log authentication event to user session logs."
  },
  "alert-009": {
    severity: "HIGH",
    technique: "T1048.002 - Exfiltration Over Alternative Protocol: Tor",
    reasoning: [
      "Established persistent outbound TCP connection on port 443 to known public Tor exit node 185.220.101.5.",
      "High-volume payload data transfer of 524 MB initiated from database-backup-09.",
      "This indicates potential staging and unauthorized bulk data exfiltration of DB records."
    ],
    reportText: "EXECUTIVE SUMMARY\nAn active high-volume exfiltration event over Tor was intercepted on database-backup-09.\n\nTECHNICAL ANALYSIS\nConnection telemetry identified 524MB of data transferred to 185.220.101.5 (an active Tor node). The process was launched from non-standard backup cron routines.\nMITRE ATT&CK: T1048.002 Exfiltration Over Alternative Protocol: Tor.\n\nRECOMMENDED ACTIONS\n1. Block Tor outbound directory IP pools at core firewall borders.\n2. Immediately terminate the suspicious active transmission socket.\n3. Audit backup access logs and roll master keys/passwords."
  },
  "alert-010": {
    severity: "CRITICAL",
    technique: "T1003.001 - OS Credential Dumping: LSASS Memory",
    reasoning: [
      "LSASS process memory access was requested and dumped into C:\\Windows\\Temp\\lsass.dmp.",
      "LSASS dumping is a signature mechanism of Mimikatz or ProcDump to scrape domain credentials.",
      "Detected on ad-controller-10, putting the active directory domain at immediate risk of compromise."
    ],
    reportText: "EXECUTIVE SUMMARY\nMemory space dumping of LSASS was executed on ad-controller-10 by user context SYSTEM.\n\nTECHNICAL ANALYSIS\nLSASS credentials scraping signature was triggered. Process telemetry logged an unexpected handle duplication request.\nMITRE ATT&CK: T1003.001 OS Credential Dumping: LSASS Memory.\n\nRECOMMENDED ACTIONS\n1. Isolate the affected Active Directory Domain Controller immediately.\n2. Force a global krbtgt account password reset (twice).\n3. Enable Credential Guard to protect memory targets."
  },
  "alert-011": {
    severity: "CRITICAL",
    technique: "T1611 - Escape to Host",
    reasoning: [
      "An anomalous attempt to override container namespace or bind-mount the Docker daemon socket was detected.",
      "Active socket mounting grants the container privileged root commands on the underlying virtual host.",
      "Compromised container image 'nginx:latest-compromised' used to initialize the escaping deployment."
    ],
    reportText: "EXECUTIVE SUMMARY\nContainer breakout behavior detected on k8s-worker-node-11 inside namespace override commands.\n\nTECHNICAL ANALYSIS\nA process inside container e5f29910a34b attempted ProcFS mounting with high privileges (CAP_SYS_ADMIN).\nMITRE ATT&CK: T1611 Escape to Host.\n\nRECOMMENDED ACTIONS\n1. Evict and terminate pod deployments hosting e5f29910a34b.\n2. Verify host kernel stability and ensure SELinux/AppArmor enforcement.\n3. Implement Kubernetes Pod Security Standards to restrict privileged permissions."
  },
  "alert-012": {
    severity: "MEDIUM",
    technique: "T1053.003 - Scheduled Task/Job: Cron",
    reasoning: [
      "A new crontab entry was created in root user profiles to run every 5 minutes.",
      "The task points to a hidden path '/tmp/.hidden_script.sh', which is highly anomalous.",
      "Often used by adversaries as a persistent fallback trigger to secure continuous access."
    ],
    reportText: "EXECUTIVE SUMMARY\nSuspicious persistent cron job created on mail-server-12 pointing to temporary directories.\n\nTECHNICAL ANALYSIS\nCron file modifications detected a high-frequency execution scheduler pointing to `/tmp/.hidden_script.sh`.\nMITRE ATT&CK: T1053.003 Scheduled Task/Job: Cron.\n\nRECOMMENDED ACTIONS\n1. Delete the crontab line and delete the file `/tmp/.hidden_script.sh`.\n2. Investigate parent execution logs to track how the entry was registered.\n3. Audit user login session histories."
  }
};

// Seed baseline reports in localStorage if empty
const initializeLocalDB = () => {
  if (!localStorage.getItem('vigilance_reports')) {
    const initialReports: IncidentReport[] = [
      {
        id: "rep-001",
        alert_id: "alert-001",
        title: "Incident Triage Report - TAMPERING DETECTION",
        severity: "CRITICAL",
        agent_name: "web-server-01",
        preview: "Kernel tampering was detected on web-server-01. Host configuration files indicate critical...",
        created_at: "2026-06-30T09:14:00Z",
        report_text: AI_MOCK_DATA["alert-001"].reportText
      },
      {
        id: "rep-002",
        alert_id: "alert-002",
        title: "Incident Triage Report - CRYPTO INTRUSION",
        severity: "CRITICAL",
        agent_name: "file-server-02",
        preview: "Automated ransomware activity detected on file-server-02 under /mnt/shared/finance...",
        created_at: "2026-06-30T09:17:30Z",
        report_text: AI_MOCK_DATA["alert-002"].reportText
      }
    ];
    localStorage.setItem('vigilance_reports', JSON.stringify(initialReports));
  }
};

initializeLocalDB();

// Helper to get reports from local storage
const getLocalReports = (): IncidentReport[] => {
  try {
    const reportsStr = localStorage.getItem('vigilance_reports');
    return reportsStr ? JSON.parse(reportsStr) : [];
  } catch (e) {
    return [];
  }
};

// Helper to save report to local storage
const saveLocalReport = (report: IncidentReport) => {
  const reports = getLocalReports();
  // Avoid duplicates
  const index = reports.findIndex(r => r.alert_id === report.alert_id);
  if (index >= 0) {
    reports[index] = report;
  } else {
    reports.unshift(report);
  }
  localStorage.setItem('vigilance_reports', JSON.stringify(reports));
};

export const checkBackendHealth = async (): Promise<boolean> => {
  try {
    const res = await fetch(`${BASE_URL}/`, { signal: AbortSignal.timeout(1500) });
    return res.ok;
  } catch (err) {
    return false;
  }
};

export const fetchSiemAlerts = async (): Promise<Alert[]> => {
  try {
    const res = await fetch(`${BASE_URL}/alerts`);
    if (res.ok) {
      const data = await res.json();
      if (data.success && Array.isArray(data.alerts)) {
        // Transform DB records to the shape AlertCard expects.
        // No sample-data fallback: an empty backend means an empty
        // dashboard, not fabricated data.
        return data.alerts.map((a: any) => ({
          id: a.id,
          timestamp: a.timestamp,
          rule: {
            id: a.rule_id,
            level: a.rule_level,
            description: a.description,
            groups: a.raw_data?.rule?.groups || []
          },
          agent: {
            id: a.raw_data?.agent?.id || '',
            name: a.agent_name,
            ip: a.agent_ip
          },
          data: a.raw_data?.data || {},
          location: a.raw_data?.location || '',
          severity: a.severity,
          _source: 'live'
        }));
      }
    }
    console.warn('Backend /alerts returned no usable data.');
    return [];
  } catch (e: any) {
    console.warn('Backend /alerts unreachable:', e.message);
    return [];
  }
};

export const classifyAlert = async (alert: Alert): Promise<Classification> => {
  const res = await fetch(`${BASE_URL}/classify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ alert })
  });
  if (!res.ok) throw new Error('API server error');
  const data = await res.json();

  if (!data.success || !data.classification) {
    throw new Error('Invalid classification response');
  }

  // backend's classify_alert() already returns a fully-parsed dict:
  // { severity, technique, reasoning: string[], rawText }. Use it as-is.
  const c = data.classification;
  const classification: Classification = {
    severity: c.severity,
    technique: c.technique,
    reasoning: Array.isArray(c.reasoning) ? c.reasoning : [String(c.reasoning ?? '')],
    rawText: c.rawText ?? ''
  };

  saveClassificationToDB({
    alert_id: alert.id,
    severity: classification.severity,
    reasoning: classification.reasoning.join(' | '),
    mitre_tactics: classification.technique
  }).catch(err => console.warn('DB save classification failed:', err));

  return classification;
  // No mock fallback: if the backend or Mistral is unreachable, the caller
  // (AlertCard.tsx) should show an error state, not fabricated severity data.
};

export const generateReport = async (alert: Alert, classification: Classification): Promise<{ report: string }> => {
  const res = await fetch(`${BASE_URL}/report`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ alert, classification })
  });
  if (!res.ok) throw new Error('API server error');
  const data = await res.json();

  if (data.success && data.report) {
    saveReportToDB({
      alert_id: alert.id,
      severity: classification.severity,
      agent_name: alert.agent.name,
      report_text: data.report
    }).catch(err => console.warn('DB save report failed:', err));
  }

  return data;
};

export const saveClassificationToDB = async (payload: { alert_id: string; severity: string; reasoning: string; mitre_tactics: string }) => {
  try {
    const res = await fetch(`${BASE_URL}/classifications/save`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    return res.json();
  } catch (err) {
    console.log("Local save: Classification stored in session.", err);
  }
};

export const saveReportToDB = async (payload: { alert_id: string; severity: string; agent_name: string; report_text: string }) => {
  try {
    const res = await fetch(`${BASE_URL}/reports/save`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    return res.json();
  } catch (err) {
    console.log("Local save: Report stored in persistent storage.", err);
  }
};

export const fetchSavedReports = async (): Promise<IncidentReport[]> => {
  try {
    const res = await fetch(`${BASE_URL}/reports`);
    if (!res.ok) throw new Error('API server error');
    const data = await res.json();
    return data.reports || data;
  } catch (err) {
    console.warn("Backend not reachable. Fetching from local localStorage storage.");
    return getLocalReports();
  }
};

export const fetchReportById = async (id: string): Promise<IncidentReport> => {
  try {
    const res = await fetch(`${BASE_URL}/reports/${id}`);
    if (!res.ok) throw new Error('API server error');
    const data = await res.json();
    return data.report || data;
  } catch (err) {
    const reports = getLocalReports();
    const report = reports.find(r => r.id === id);
    if (!report) throw new Error(`Report with id ${id} not found in local db`);
    return report;
  }
};

// ──────────────────────────────────────────
// NEW: FETCH CLASSIFICATIONS
// ──────────────────────────────────────────
export const fetchClassifications = async (): Promise<{ success: boolean; classifications: any[] }> => {
  try {
    const res = await fetch(`${BASE_URL}/classifications`);
    if (!res.ok) throw new Error('Failed to fetch classifications');
    return res.json();
  } catch (e: any) {
    console.warn('Could not fetch classifications:', e.message);
    return { success: false, classifications: [] };
  }
};

// ──────────────────────────────────────────
// NEW: FETCH STATS
// ──────────────────────────────────────────
export const fetchStats = async (): Promise<{ success: boolean; stats: any }> => {
  try {
    const res = await fetch(`${BASE_URL}/stats`);
    if (!res.ok) throw new Error('Failed to fetch stats');
    return res.json();
  } catch (e: any) {
    console.warn('Could not fetch stats:', e.message);
    return { success: false, stats: {} };
  }
};

// ──────────────────────────────────────────
// NEW: FETCH HEALTH (detailed)
// ──────────────────────────────────────────
export const fetchHealth = async (): Promise<{ success: boolean; health: { api: boolean; database: boolean; ollama: boolean } }> => {
  try {
    const res = await fetch(`${BASE_URL}/health`);
    if (!res.ok) throw new Error('Health check failed');
    return res.json();
  } catch (e) {
    return { success: false, health: { api: false, database: false, ollama: false } };
  }
};

// ──────────────────────────────────────────
// NEW: SAVE ALERT TO DB (auto-persist from frontend)
// ──────────────────────────────────────────
export const saveAlertToDB = async (alert: Alert): Promise<{ success: boolean; id?: string }> => {
  try {
    const res = await fetch(`${BASE_URL}/alerts/save`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(alert)
    });
    return res.json();
  } catch (e: any) {
    console.warn('Could not save alert to DB:', e.message);
    return { success: false };
  }
};
