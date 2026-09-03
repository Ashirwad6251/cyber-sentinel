import type {
  AlertRecord,
  AttackVector,
  DetectionRule,
  LogEntry,
  LogSource,
  Severity,
} from "./types";

let seq = 0;
export const uid = (prefix: string) => `${prefix}-${Date.now().toString(36)}-${(seq++).toString(36)}`;

const pick = <T,>(arr: readonly T[]): T => arr[Math.floor(Math.random() * arr.length)]!;
const int = (min: number, max: number) => Math.floor(Math.random() * (max - min + 1)) + min;

export const GEO_POOL = [
  { country: "Russia", lat: 55.75, lon: 37.61 },
  { country: "China", lat: 39.9, lon: 116.4 },
  { country: "Brazil", lat: -23.55, lon: -46.63 },
  { country: "United States", lat: 40.71, lon: -74.0 },
  { country: "Germany", lat: 52.52, lon: 13.4 },
  { country: "India", lat: 19.07, lon: 72.87 },
  { country: "Netherlands", lat: 52.37, lon: 4.9 },
  { country: "Nigeria", lat: 6.52, lon: 3.37 },
  { country: "Iran", lat: 35.69, lon: 51.39 },
  { country: "Singapore", lat: 1.35, lon: 103.82 },
  { country: "Ukraine", lat: 50.45, lon: 30.52 },
  { country: "Australia", lat: -33.86, lon: 151.2 },
] as const;

export const ASSETS = [
  "dc01.corp.local",
  "web-prod-03",
  "sql-fin-01",
  "vpn-gw-edge",
  "hr-ws-114",
  "k8s-node-07",
  "bastion-01",
] as const;

const USERS = ["svc_backup", "j.doe", "a.patel", "root", "administrator", "m.chen", "SYSTEM"] as const;

export const LOG_SOURCES: LogSource[] = [
  "Syslog",
  "Windows Event",
  "AWS CloudTrail",
  "Firewall",
  "Endpoint EDR",
  "Web Server",
];

export const SEVERITIES: Severity[] = ["INFO", "WARN", "ERROR", "CRITICAL"];

export const publicIp = () => `${int(23, 223)}.${int(0, 255)}.${int(0, 255)}.${int(1, 254)}`;
export const internalIp = () => `10.${int(0, 40)}.${int(0, 255)}.${int(2, 250)}`;

const BENIGN: Array<{ source: LogSource; eventId: string; severity: Severity; message: string; action: string }> = [
  { source: "Firewall", eventId: "FW-1001", severity: "INFO", message: "ALLOW tcp/443 outbound session established", action: "allow" },
  { source: "Firewall", eventId: "FW-1004", severity: "WARN", message: "DENY tcp/3389 inbound — policy edge-deny-rdp", action: "deny" },
  { source: "Windows Event", eventId: "4624", severity: "INFO", message: "An account was successfully logged on (Logon Type 3)", action: "logon" },
  { source: "Windows Event", eventId: "4634", severity: "INFO", message: "An account was logged off", action: "logoff" },
  { source: "Windows Event", eventId: "4625", severity: "WARN", message: "An account failed to log on (bad password)", action: "logon_failed" },
  { source: "Syslog", eventId: "SSHD-27", severity: "INFO", message: "Accepted publickey for deploy from port 52344 ssh2", action: "auth" },
  { source: "Syslog", eventId: "CRON-14", severity: "INFO", message: "CRON session opened for user root by (uid=0)", action: "cron" },
  { source: "AWS CloudTrail", eventId: "AssumeRole", severity: "INFO", message: "sts:AssumeRole succeeded for role/deploy-ci", action: "api_call" },
  { source: "AWS CloudTrail", eventId: "PutObject", severity: "INFO", message: "s3:PutObject on bucket corp-artifacts", action: "api_call" },
  { source: "AWS CloudTrail", eventId: "ConsoleLogin", severity: "WARN", message: "ConsoleLogin without MFA from unrecognized device", action: "login" },
  { source: "Endpoint EDR", eventId: "EDR-3300", severity: "INFO", message: "Process chrome.exe spawned child crashpad_handler.exe", action: "process" },
  { source: "Endpoint EDR", eventId: "EDR-3341", severity: "ERROR", message: "Signature update failed — agent out of date", action: "agent" },
  { source: "Web Server", eventId: "HTTP-200", severity: "INFO", message: 'GET /api/v2/health 200 12ms "kube-probe/1.29"', action: "request" },
  { source: "Web Server", eventId: "HTTP-404", severity: "WARN", message: 'GET /wp-login.php 404 3ms "python-requests/2.31"', action: "request" },
  { source: "Web Server", eventId: "HTTP-500", severity: "ERROR", message: "POST /api/v2/orders 500 upstream timeout after 30s", action: "request" },
];

export function makeLog(partial: Partial<LogEntry> = {}): LogEntry {
  const base = pick(BENIGN);
  const geo = pick(GEO_POOL);
  return {
    id: uid("log"),
    timestamp: Date.now(),
    sourceIp: publicIp(),
    destIp: internalIp(),
    source: base.source,
    eventId: base.eventId,
    message: base.message,
    severity: base.severity,
    host: pick(ASSETS),
    user: pick(USERS),
    port: pick([22, 80, 443, 3389, 445, 8080, 1433]),
    action: base.action,
    country: geo.country,
    geo: { lat: geo.lat, lon: geo.lon },
    ...partial,
  };
}

export function seedLogs(count = 120): LogEntry[] {
  const now = Date.now();
  return Array.from({ length: count }, (_, i) =>
    makeLog({ timestamp: now - (count - i) * int(1200, 4200) }),
  ).sort((a, b) => a.timestamp - b.timestamp);
}

export const DEFAULT_RULES: DetectionRule[] = [
  {
    id: "R-1001",
    name: "SSH / Windows Brute Force Attempt",
    enabled: true,
    severity: "CRITICAL",
    mitre: "T1110",
    logSource: "Any",
    condition: 'event_id IN ("4625","SSHD-FAIL") AND count > 5 IN 60s GROUP BY source.ip',
    description: "Detects high-volume authentication failures from a single source address.",
    fired: 0,
  },
  {
    id: "R-1002",
    name: "SQL Injection Pattern in HTTP Request",
    enabled: true,
    severity: "CRITICAL",
    mitre: "T1190",
    logSource: "Web Server",
    condition: "message CONTAINS ANY (\"' OR 1=1 --\", \"UNION SELECT\", \"xp_cmdshell\")",
    description: "Flags web requests containing classic SQL injection tautologies.",
    fired: 0,
  },
  {
    id: "R-1003",
    name: "Ransomware Mass File Encryption",
    enabled: true,
    severity: "CRITICAL",
    mitre: "T1486",
    logSource: "Endpoint EDR",
    condition: "file_modify_count > 200 IN 30s AND extension_changed = true",
    description: "Detects mass file alteration paired with unauthorized process execution.",
    fired: 0,
  },
  {
    id: "R-1004",
    name: "Horizontal / Vertical Port Scan",
    enabled: true,
    severity: "ERROR",
    mitre: "T1046",
    logSource: "Firewall",
    condition: "distinct(dest.port) > 20 IN 60s GROUP BY source.ip",
    description: "Sequential connection attempts across many destination ports.",
    fired: 0,
  },
  {
    id: "R-1005",
    name: "Console Login Without MFA",
    enabled: true,
    severity: "WARN",
    mitre: "T1078",
    logSource: "AWS CloudTrail",
    condition: 'event_id == "ConsoleLogin" AND mfa_used == false',
    description: "Cloud console authentication missing multi-factor challenge.",
    fired: 0,
  },
  {
    id: "R-1006",
    name: "Suspicious LSASS Memory Access",
    enabled: false,
    severity: "CRITICAL",
    mitre: "T1003.001",
    logSource: "Endpoint EDR",
    condition: 'target_image ENDSWITH "lsass.exe" AND granted_access == "0x1010"',
    description: "Credential dumping via direct LSASS handle access.",
    fired: 0,
  },
  {
    id: "R-1007",
    name: "Impossible Travel Sign-in",
    enabled: true,
    severity: "ERROR",
    mitre: "T1078.004",
    logSource: "Any",
    condition: "geo_distance(prev_login, this_login) > 3000km IN 45m",
    description: "Same identity authenticating from geographically impossible locations.",
    fired: 0,
  },
];

export const ATTACK_META: Record<
  AttackVector,
  { label: string; mitre: string; severity: Severity; ruleId: string; description: string }
> = {
  ssh_brute: {
    label: "SSH Brute Force",
    mitre: "T1110",
    severity: "CRITICAL",
    ruleId: "R-1001",
    description: "40+ failed authentications from a single hostile source IP.",
  },
  sqli: {
    label: "SQL Injection",
    mitre: "T1190",
    severity: "CRITICAL",
    ruleId: "R-1002",
    description: "Tautology-based injection payloads against the public web tier.",
  },
  ransomware: {
    label: "Ransomware Behavior",
    mitre: "T1486",
    severity: "CRITICAL",
    ruleId: "R-1003",
    description: "Mass file rewrite plus shadow-copy deletion on an endpoint.",
  },
  port_scan: {
    label: "Port Scan",
    mitre: "T1046",
    severity: "ERROR",
    ruleId: "R-1004",
    description: "Sequential TCP connection attempts across a wide port range.",
  },
};

export function buildAttack(vector: AttackVector): { logs: LogEntry[]; alert: Omit<AlertRecord, "logIds"> } {
  const geo = pick(GEO_POOL);
  const attacker = publicIp();
  const target = pick(ASSETS);
  const dest = internalIp();
  const now = Date.now();
  const meta = ATTACK_META[vector];
  const common = {
    sourceIp: attacker,
    destIp: dest,
    host: target,
    country: geo.country,
    geo: { lat: geo.lat, lon: geo.lon },
  };

  let logs: LogEntry[] = [];

  if (vector === "ssh_brute") {
    logs = Array.from({ length: 24 }, (_, i) =>
      makeLog({
        ...common,
        timestamp: now + i * 40,
        source: i % 3 === 0 ? "Windows Event" : "Syslog",
        eventId: i % 3 === 0 ? "4625" : "SSHD-FAIL",
        severity: "ERROR",
        user: pick(["root", "admin", "oracle", "postgres", "administrator"]),
        port: 22,
        action: "logon_failed",
        message: `Failed password for invalid user ${pick(["root", "admin", "oracle", "test"])} from ${attacker} port ${int(40000, 60000)} ssh2 (attempt ${i + 1})`,
      }),
    );
  } else if (vector === "sqli") {
    const payloads = [
      "' OR 1=1 --",
      "' UNION SELECT username,password FROM users --",
      "1; WAITFOR DELAY '0:0:5' --",
      "admin'--",
      "' OR 'a'='a",
    ];
    logs = Array.from({ length: 14 }, (_, i) =>
      makeLog({
        ...common,
        timestamp: now + i * 60,
        source: "Web Server",
        eventId: i % 4 === 0 ? "HTTP-500" : "HTTP-200",
        severity: "CRITICAL",
        port: 443,
        action: "request",
        user: "anonymous",
        message: `GET /api/v1/login?user=${encodeURIComponent(pick(payloads))} — WAF bypass suspected, sqli signature match`,
      }),
    );
  } else if (vector === "ransomware") {
    const files = ["Q3_forecast.xlsx", "payroll.csv", "contracts.docx", "designs.psd", "backup.bak"];
    logs = Array.from({ length: 20 }, (_, i) =>
      makeLog({
        ...common,
        timestamp: now + i * 45,
        source: "Endpoint EDR",
        eventId: i === 0 ? "EDR-9001" : "EDR-9100",
        severity: "CRITICAL",
        port: 445,
        action: i === 0 ? "process" : "file_modify",
        user: pick(["j.doe", "SYSTEM"]),
        message:
          i === 0
            ? "Unauthorized process execution: vssadmin.exe delete shadows /all /quiet"
            : `File rewritten and extension changed: C:\\Users\\Shared\\${pick(files)} -> .lockbit3`,
      }),
    );
  } else {
    logs = Array.from({ length: 26 }, (_, i) =>
      makeLog({
        ...common,
        timestamp: now + i * 30,
        source: "Firewall",
        eventId: "FW-1004",
        severity: "WARN",
        port: 20 + i * 3,
        action: "deny",
        user: "-",
        message: `DENY tcp SYN ${attacker}:${int(40000, 60000)} -> ${dest}:${20 + i * 3} (no listening service)`,
      }),
    );
  }

  const alert: Omit<AlertRecord, "logIds"> = {
    id: uid("ALT"),
    ruleId: meta.ruleId,
    ruleName: DEFAULT_RULES.find((r) => r.id === meta.ruleId)?.name ?? meta.label,
    title: `${meta.label} detected against ${target}`,
    severity: meta.severity,
    status: "New",
    timestamp: now,
    mitre: meta.mitre,
    sourceIp: attacker,
    host: target,
    assignee: "Unassigned",
    timeline: [
      { at: now, label: `Rule ${meta.ruleId} matched ${logs.length} correlated events` },
      { at: now + 1, label: `Threat origin geolocated to ${geo.country}` },
    ],
  };

  return { logs, alert };
}
