export interface AlertRule {
  id: string;
  level: number;
  description: string;
  groups: string[];
}

export interface AlertAgent {
  id: string;
  name: string;
  ip: string;
}

export interface Alert {
  id: string;
  timestamp: string;
  rule: AlertRule;
  agent: AlertAgent;
  data?: Record<string, any>;
  location?: string;
  severity?: string;
  _source?: 'live' | 'sample';
}

export interface Classification {
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  technique: string;
  reasoning: string[];
  recommendedActions?: string[];
  rawText?: string;
}

export interface IncidentReport {
  id: string;
  alert_id: string;
  title: string;
  severity: string;
  agent_name: string;
  preview: string;
  created_at: string;
  report_text: string;
}
