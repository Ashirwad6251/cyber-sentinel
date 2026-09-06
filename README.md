# Cyber Sentinel

# Context & Objective

Build a full-stack enterprise SIEM (Security Information & Event Management) application called "CyberShield SIEM". The application serves Security Operations Center (SOC) analysts for monitoring, threat detection, log analysis, and incident response.

# Visual Style & Design System

- Theme: Dark cyber-ops aesthetic (Dark slate background `#0d1117`, neon emerald `#10b981` accents for normal, amber `#f59e0b` for warnings, crimson `#ef4444` for critical alerts).

- UI Framework: Tailwind CSS + Shadcn UI components, glassmorphism cards, dense data tables, monospace fonts for logs/IP addresses.

- Motion: Smooth metric transitions, pulsing status indicators for live streams.

# Core Modules & Priority Features

1. SOC Executive Overview Dashboard

   - KPI Cards: Total Ingested Logs, Events Per Second (EPS), Active Critical Alerts, Open Incidents.

   - Interactive Charts: EPS Line Chart over time, Alert Severity Distribution (Donut Chart), Top 5 Targeted Assets (Bar Chart).

   - Live Threat Map / Geo-location Visualizer showing incoming threat origins.

2. Live Log Ingestion & Stream Simulator

   - Real-time streaming log console with pause/resume toggle.

   - Standardized log schema support: Timestamp, Source IP, Destination IP, Log Source (Syslog, Windows Event, AWS CloudTrail, Firewall), Event ID, Message, Severity.

   - Filter bar: Filter by log source, severity level (INFO, WARN, ERROR, CRITICAL), and text search.

   - Log Detail Drawer: Slide-out drawer when clicking a log row showing parsed raw JSON details.

3. Attack Simulator (Interactive Demo Engine)

   - Built-in simulation control panel to trigger realistic attack vectors:

     * SSH Brute Force (High volume failed login logs from single IP).

     * SQL Injection (Web server logs containing `' OR 1=1 --`).

     * Ransomware Behavior (Mass file alteration / unauthorized process execution logs).

     * Port Scan (Sequential connection attempts across multiple ports).

   - Triggering an attack immediately pushes matching logs to the stream and generates fired alerts.

4. Threat Detection & SIGMA Rule Engine

   - Rule Inventory Table: Displays active detection rules with status toggles, severity rating, and MITRE ATT&CK technique IDs (e.g., T1110 for Brute Force).

   - Custom Rule Builder Modal: Form to create detection logic using standard fields (e.g., IF `event_id == 4625` AND `count > 5 in 60s` THEN `Trigger High Alert`).

5. Incident Response & Alert Triage Workflow

   - Alert Management Queue: Lists fired alerts with status flags (`New`, `Investigating`, `Closed`).

   - Incident Detail Page/Modal: Displays alert timeline, associated raw logs, assigned analyst, and interactive triage action buttons (e.g., "Isolate Host", "Block IP", "Mark as False Positive").

6. Log Search & Forensics Query Builder

   - Lucene-style search query bar (e.g., `source.ip: "192.168.1.50" AND severity: "CRITICAL"`).

   - Quick date-time range selector (Last 15m, 1h, 24h, Custom).

# Initial Load State & Mock Data

- Pre-populate with 100+ realistic mock logs across firewall, authentication, and endpoint systems.

- Automatically run a light background interval generating 2-3 benign logs every 5 seconds.



## Development

Prefer working locally? You need Node.js and npm — [install with nvm](https://github.com/nvm-sh/nvm#installing-and-updating).

```sh
git clone <this-repository-url>
cd <repository-name>
npm i
npm run dev
```
