import { createFileRoute } from "@tanstack/react-router";
import { useMemo, useState } from "react";
import { Ban, CheckCircle2, ShieldX, UserCheck } from "lucide-react";
import { toast } from "sonner";
import { useSiem } from "@/lib/siem/store";
import { LogTable } from "@/components/siem/LogTable";
import {
  Panel,
  SeverityBadge,
  StatusBadge,
  fmtDateTime,
} from "@/components/siem/primitives";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import type { AlertStatus } from "@/lib/siem/types";

export const Route = createFileRoute("/alerts")({
  head: () => ({
    meta: [
      { title: "Alert Triage — CyberShield SIEM" },
      {
        name: "description",
        content:
          "Incident response queue with alert timelines, correlated raw logs and containment actions like host isolation and IP blocking.",
      },
      { property: "og:title", content: "Alert Triage — CyberShield SIEM" },
      {
        property: "og:description",
        content: "Work the SOC alert queue from detection through containment and closure.",
      },
    ],
  }),
  component: AlertsPage,
});

const FILTERS = ["All", "New", "Investigating", "Closed"] as const;

function AlertsPage() {
  const { alerts, logs, updateAlert } = useSiem();
  const [filter, setFilter] = useState<(typeof FILTERS)[number]>("All");
  const [openId, setOpenId] = useState<string | null>(null);

  const visible = useMemo(
    () => alerts.filter((a) => filter === "All" || a.status === filter),
    [alerts, filter],
  );
  const active = alerts.find((a) => a.id === openId) ?? null;
  const activeLogs = useMemo(
    () => (active ? logs.filter((l) => active.logIds.includes(l.id)).reverse() : []),
    [active, logs],
  );

  const act = (label: string, status?: AlertStatus) => {
    if (!active) return;
    updateAlert(active.id, status ? { status } : {}, label);
    toast.success(label, { description: `${active.id} · ${active.host}` });
  };

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold tracking-tight text-foreground">
            Incident Response &amp; Alert Triage
          </h1>
          <p className="mt-1 text-sm text-muted-foreground">
            {alerts.filter((a) => a.status !== "Closed").length} open of {alerts.length} total alerts.
          </p>
        </div>
        <Tabs value={filter} onValueChange={(v) => setFilter(v as (typeof FILTERS)[number])}>
          <TabsList>
            {FILTERS.map((f) => (
              <TabsTrigger key={f} value={f} className="font-mono text-xs">
                {f}
              </TabsTrigger>
            ))}
          </TabsList>
        </Tabs>
      </div>

      <Panel title="Alert management queue" bodyClassName="p-0">
        <div className="overflow-x-auto">
          <table className="w-full min-w-[880px] text-left text-sm">
            <thead>
              <tr className="border-b border-border font-mono text-[10px] tracking-widest text-muted-foreground uppercase">
                <th className="px-4 py-2">Alert ID</th>
                <th className="px-4 py-2">Detection</th>
                <th className="px-4 py-2">Source IP</th>
                <th className="px-4 py-2">Asset</th>
                <th className="px-4 py-2">Analyst</th>
                <th className="px-4 py-2">Severity</th>
                <th className="px-4 py-2">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border/60">
              {visible.map((a) => (
                <tr
                  key={a.id}
                  onClick={() => setOpenId(a.id)}
                  className="cursor-pointer hover:bg-primary/5"
                >
                  <td className="px-4 py-3 font-mono text-xs text-muted-foreground">{a.id}</td>
                  <td className="px-4 py-3">
                    <p className="text-foreground">{a.title}</p>
                    <p className="font-mono text-[11px] text-warning">
                      {a.ruleId} · {a.mitre} · {fmtDateTime(a.timestamp)}
                    </p>
                  </td>
                  <td className="px-4 py-3 font-mono text-xs text-warning/90">{a.sourceIp}</td>
                  <td className="px-4 py-3 font-mono text-xs text-info/90">{a.host}</td>
                  <td className="px-4 py-3 font-mono text-xs text-foreground/80">{a.assignee}</td>
                  <td className="px-4 py-3">
                    <SeverityBadge severity={a.severity} />
                  </td>
                  <td className="px-4 py-3">
                    <StatusBadge status={a.status} />
                  </td>
                </tr>
              ))}
              {visible.length === 0 && (
                <tr>
                  <td colSpan={7} className="px-4 py-10 text-center text-sm text-muted-foreground">
                    No alerts in this queue.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </Panel>

      <Dialog open={!!active} onOpenChange={(o) => !o && setOpenId(null)}>
        <DialogContent className="max-h-[90vh] max-w-3xl overflow-y-auto">
          {active && (
            <>
              <DialogHeader>
                <DialogTitle className="flex flex-wrap items-center gap-3">
                  <span className="font-mono text-xs text-muted-foreground">{active.id}</span>
                  {active.title}
                  <SeverityBadge severity={active.severity} />
                  <StatusBadge status={active.status} />
                </DialogTitle>
              </DialogHeader>

              <div className="space-y-4">
                <dl className="grid grid-cols-2 gap-3 rounded-md border border-border bg-surface/50 p-3 font-mono text-xs sm:grid-cols-4">
                  {[
                    ["rule", active.ruleId],
                    ["mitre", active.mitre],
                    ["source.ip", active.sourceIp],
                    ["asset", active.host],
                    ["analyst", active.assignee],
                    ["detected", fmtDateTime(active.timestamp)],
                    ["events", String(active.logIds.length)],
                    ["rule.name", active.ruleName],
                  ].map(([k, v]) => (
                    <div key={k}>
                      <dt className="text-muted-foreground">{k}</dt>
                      <dd className="break-words text-foreground">{v}</dd>
                    </div>
                  ))}
                </dl>

                <div className="flex flex-wrap gap-2">
                  <Button
                    variant="destructive"
                    className="font-mono text-xs"
                    onClick={() => act("Host isolated from network", "Investigating")}
                  >
                    <ShieldX className="size-3.5" /> Isolate host
                  </Button>
                  <Button
                    variant="outline"
                    className="font-mono text-xs"
                    onClick={() => act(`Source IP ${active.sourceIp} blocked at edge`, "Investigating")}
                  >
                    <Ban className="size-3.5" /> Block IP
                  </Button>
                  <Button
                    variant="outline"
                    className="font-mono text-xs"
                    onClick={() => act("Assigned to a.patel", "Investigating")}
                  >
                    <UserCheck className="size-3.5" /> Assign to me
                  </Button>
                  <Button
                    variant="secondary"
                    className="font-mono text-xs"
                    onClick={() => act("Marked as false positive and closed", "Closed")}
                  >
                    <CheckCircle2 className="size-3.5" /> Mark false positive
                  </Button>
                </div>

                <div>
                  <h3 className="mb-2 font-mono text-[10px] tracking-widest text-muted-foreground uppercase">
                    Incident timeline
                  </h3>
                  <ol className="space-y-2 border-l border-border pl-4">
                    {active.timeline.map((t, i) => (
                      <li key={i} className="relative text-sm">
                        <span className="absolute top-1.5 -left-[21px] size-2 rounded-full bg-primary" />
                        <span className="font-mono text-[11px] text-muted-foreground">
                          {fmtDateTime(t.at)}
                        </span>
                        <p className="text-foreground/90">{t.label}</p>
                      </li>
                    ))}
                  </ol>
                </div>

                <div>
                  <h3 className="mb-2 font-mono text-[10px] tracking-widest text-muted-foreground uppercase">
                    Associated raw logs
                  </h3>
                  <LogTable
                    logs={activeLogs}
                    maxHeight="240px"
                    emptyLabel="Correlated events have rotated out of the hot buffer."
                  />
                </div>
              </div>
            </>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
