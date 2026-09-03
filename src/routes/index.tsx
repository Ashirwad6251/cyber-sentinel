import { createFileRoute } from "@tanstack/react-router";
import { useMemo } from "react";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { Database, Gauge, ShieldAlert, Siren, TrendingUp } from "lucide-react";
import { useSiem } from "@/lib/siem/store";
import { Panel, SeverityBadge, StatusBadge, fmtTime } from "@/components/siem/primitives";
import { ThreatMap } from "@/components/siem/ThreatMap";
import type { Severity } from "@/lib/siem/types";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "SOC Overview — CyberShield SIEM" },
      {
        name: "description",
        content:
          "Executive SOC dashboard: events per second, alert severity distribution, targeted assets and live threat origin map.",
      },
      { property: "og:title", content: "SOC Overview — CyberShield SIEM" },
      {
        property: "og:description",
        content: "Real-time security operations metrics, alert triage queue and threat geolocation.",
      },
    ],
  }),
  component: Overview,
});

const SEV_COLOR: Record<Severity, string> = {
  INFO: "var(--info)",
  WARN: "var(--warning)",
  ERROR: "var(--chart-5)",
  CRITICAL: "var(--critical)",
};

function Kpi({
  label,
  value,
  hint,
  icon: Icon,
  tone = "primary",
}: {
  label: string;
  value: string;
  hint: string;
  icon: typeof Database;
  tone?: "primary" | "warning" | "critical";
}) {
  const toneCls =
    tone === "critical" ? "text-critical" : tone === "warning" ? "text-warning" : "text-primary";
  return (
    <div className="glass relative overflow-hidden rounded-lg p-4">
      <div className="flex items-start justify-between">
        <p className="font-mono text-[10px] tracking-[0.18em] text-muted-foreground uppercase">
          {label}
        </p>
        <Icon className={`size-4 ${toneCls}`} />
      </div>
      <p className={`mt-3 font-mono text-3xl font-bold tabular-nums ${toneCls} text-glow`}>{value}</p>
      <p className="mt-1 text-xs text-muted-foreground">{hint}</p>
    </div>
  );
}

function Overview() {
  const { logs, alerts, totalIngested, eps, epsSeries } = useSiem();

  const sevData = useMemo(() => {
    const counts: Record<Severity, number> = { INFO: 0, WARN: 0, ERROR: 0, CRITICAL: 0 };
    for (const l of logs) counts[l.severity]++;
    return (Object.keys(counts) as Severity[]).map((k) => ({ name: k, value: counts[k] }));
  }, [logs]);

  const assetData = useMemo(() => {
    const map = new Map<string, number>();
    for (const l of logs) map.set(l.host, (map.get(l.host) ?? 0) + 1);
    return [...map.entries()]
      .map(([host, count]) => ({ host, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 5);
  }, [logs]);

  const epsData = useMemo(
    () => epsSeries.map((p) => ({ time: fmtTime(p.t).slice(0, 8), eps: p.eps })),
    [epsSeries],
  );

  const criticalAlerts = alerts.filter((a) => a.severity === "CRITICAL" && a.status !== "Closed");
  const openIncidents = alerts.filter((a) => a.status !== "Closed");

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-xl font-semibold tracking-tight text-foreground">
          Security Operations Overview
        </h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Consolidated posture across firewall, identity, cloud and endpoint telemetry.
        </p>
      </div>

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <Kpi
          label="Total ingested logs"
          value={totalIngested.toLocaleString()}
          hint="Rolling 24h across 6 collectors"
          icon={Database}
        />
        <Kpi
          label="Events per second"
          value={eps.toLocaleString()}
          hint="Live ingestion pipeline throughput"
          icon={Gauge}
        />
        <Kpi
          label="Active critical alerts"
          value={String(criticalAlerts.length)}
          hint="Awaiting containment decision"
          icon={Siren}
          tone="critical"
        />
        <Kpi
          label="Open incidents"
          value={String(openIncidents.length)}
          hint="New + under investigation"
          icon={ShieldAlert}
          tone="warning"
        />
      </div>

      <div className="grid gap-4 xl:grid-cols-3">
        <Panel
          title="Events per second"
          subtitle="Ingestion throughput"
          className="xl:col-span-2"
          action={
            <span className="flex items-center gap-1 font-mono text-[11px] text-primary">
              <TrendingUp className="size-3.5" /> live
            </span>
          }
        >
          <div className="h-56">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={epsData}>
                <defs>
                  <linearGradient id="epsFill" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="var(--primary)" stopOpacity={0.5} />
                    <stop offset="100%" stopColor="var(--primary)" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis
                  dataKey="time"
                  tick={{ fontSize: 10, fill: "var(--muted-foreground)", fontFamily: "monospace" }}
                  interval="preserveStartEnd"
                  stroke="var(--border)"
                />
                <YAxis
                  tick={{ fontSize: 10, fill: "var(--muted-foreground)", fontFamily: "monospace" }}
                  stroke="var(--border)"
                  width={40}
                />
                <Tooltip
                  contentStyle={{
                    background: "var(--popover)",
                    border: "1px solid var(--border)",
                    borderRadius: 8,
                    fontFamily: "monospace",
                    fontSize: 12,
                  }}
                />
                <Area
                  type="monotone"
                  dataKey="eps"
                  stroke="var(--primary)"
                  strokeWidth={2}
                  fill="url(#epsFill)"
                  isAnimationActive={false}
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </Panel>

        <Panel title="Alert severity distribution" subtitle="Event mix by severity">
          <div className="h-56">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={sevData}
                  dataKey="value"
                  nameKey="name"
                  innerRadius="58%"
                  outerRadius="88%"
                  paddingAngle={3}
                  stroke="none"
                >
                  {sevData.map((d) => (
                    <Cell key={d.name} fill={SEV_COLOR[d.name as Severity]} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{
                    background: "var(--popover)",
                    border: "1px solid var(--border)",
                    borderRadius: 8,
                    fontFamily: "monospace",
                    fontSize: 12,
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
          <ul className="mt-2 grid grid-cols-2 gap-2 font-mono text-[11px]">
            {sevData.map((d) => (
              <li key={d.name} className="flex items-center gap-2">
                <span
                  className="size-2 rounded-sm"
                  style={{ background: SEV_COLOR[d.name as Severity] }}
                />
                <span className="text-muted-foreground">{d.name}</span>
                <span className="ml-auto text-foreground">{d.value}</span>
              </li>
            ))}
          </ul>
        </Panel>
      </div>

      <div className="grid gap-4 xl:grid-cols-3">
        <Panel title="Top 5 targeted assets" subtitle="Event volume by host">
          <div className="h-56">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={assetData} layout="vertical" margin={{ left: 10 }}>
                <XAxis type="number" hide />
                <YAxis
                  type="category"
                  dataKey="host"
                  width={110}
                  tick={{ fontSize: 10, fill: "var(--muted-foreground)", fontFamily: "monospace" }}
                  stroke="var(--border)"
                />
                <Tooltip
                  contentStyle={{
                    background: "var(--popover)",
                    border: "1px solid var(--border)",
                    borderRadius: 8,
                    fontFamily: "monospace",
                    fontSize: 12,
                  }}
                />
                <Bar dataKey="count" fill="var(--warning)" radius={[0, 4, 4, 0]} isAnimationActive={false} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Panel>

        <Panel title="Live threat map" subtitle="Inbound attack origins" className="xl:col-span-2">
          <ThreatMap logs={logs} />
        </Panel>
      </div>

      <Panel title="Latest alerts" subtitle="Most recent detections">
        <ul className="divide-y divide-border/60">
          {alerts.slice(0, 6).map((a) => (
            <li key={a.id} className="flex flex-wrap items-center gap-3 py-2 text-sm">
              <SeverityBadge severity={a.severity} />
              <span className="font-mono text-xs text-muted-foreground">{a.id}</span>
              <span className="min-w-0 flex-1 truncate text-foreground/90">{a.title}</span>
              <span className="font-mono text-xs text-warning">{a.mitre}</span>
              <StatusBadge status={a.status} />
            </li>
          ))}
        </ul>
      </Panel>
    </div>
  );
}
