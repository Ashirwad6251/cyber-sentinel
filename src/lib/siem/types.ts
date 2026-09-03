export type Severity = "INFO" | "WARN" | "ERROR" | "CRITICAL";

export type LogSource =
  | "Syslog"
  | "Windows Event"
  | "AWS CloudTrail"
  | "Firewall"
  | "Endpoint EDR"
  | "Web Server";

export interface LogEntry {
  id: string;
  timestamp: number;
  sourceIp: string;
  destIp: string;
  source: LogSource;
  eventId: string;
  message: string;
  severity: Severity;
  host: string;
  user: string;
  port: number;
  action: string;
  country: string;
  geo: { lat: number; lon: number };
}

export type AlertStatus = "New" | "Investigating" | "Closed";

export interface TimelineItem {
  at: number;
  label: string;
}

export interface AlertRecord {
  id: string;
  ruleId: string;
  ruleName: string
  title: string;
  severity: Severity;
  status: AlertStatus;
  timestamp: number;
  mitre: string;
  sourceIp: string;
  host: string;
  assignee: string;
  logIds: string[];
  timeline: TimelineItem[];
  falsePositive?: boolean;
}

export interface DetectionRule {
  id: string;
  name: string;
  enabled: boolean;
  severity: Severity;
  mitre: string;
  logSource: LogSource | "Any";
  condition: string;
  description: string;
  fired: number;
}

export type AttackVector = "ssh_brute" | "sqli" | "ransomware" | "port_scan";
