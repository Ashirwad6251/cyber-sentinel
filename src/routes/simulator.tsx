import { createFileRoute } from "@tanstack/react-router";
import { KeyRound, Lock, Network, Terminal, Zap } from "lucide-react";
import { useSiem } from "@/lib/siem/store";
import { ATTACK_META } from "@/lib/siem/mock";
import { LogTable } from "@/components/siem/LogTable";
import { Panel, SeverityBadge } from "@/components/siem/primitives";
import { Button } from "@/components/ui/button";
import type { AttackVector } from "@/lib/siem/types";

export const Route = createFileRoute("/simulator")({
  head: () => ({
    meta: [
      { title: "Attack Simulator — CyberShield SIEM" },
      {
        name: "description",
        content:
          "Trigger realistic attack vectors — SSH brute force, SQL injection, ransomware behavior and port scans — and watch detections fire.",
      },
      { property: "og:title", content: "Attack Simulator — CyberShield SIEM" },
      {
        property: "og:description",
        content: "Interactive demo engine that pushes attack telemetry into the live SIEM pipeline.",
      },
    ],
  }),
  component: SimulatorPage,
});

const ICONS: Record<AttackVector, typeof Zap> = {
  ssh_brute: KeyRound,
  sqli: Terminal,
  ransomware: Lock,
  port_scan: Network,
};

function SimulatorPage() {
  const { triggerAttack, logs, alerts } = useSiem();
  const vectors = Object.keys(ATTACK_META) as AttackVector[];
  const recent = logs.slice(-40).reverse();

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-xl font-semibold tracking-tight text-foreground">
          Attack Simulator — Demo Engine
        </h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Each vector injects correlated events into the live stream and fires its matching detection
          rule.
        </p>
      </div>

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        {vectors.map((v) => {
          const meta = ATTACK_META[v];
          const Icon = ICONS[v];
          return (
            <div key={v} className="glass flex flex-col rounded-lg p-4">
              <div className="flex items-center justify-between">
                <Icon className="size-5 text-critical" />
                <SeverityBadge severity={meta.severity} />
              </div>
              <h2 className="mt-3 text-sm font-semibold text-foreground">{meta.label}</h2>
              <p className="mt-1 flex-1 text-xs leading-relaxed text-muted-foreground">
                {meta.description}
              </p>
              <p className="mt-3 font-mono text-[10px] tracking-widest text-warning uppercase">
                MITRE {meta.mitre} · rule {meta.ruleId}
              </p>
              <Button
                onClick={() => triggerAttack(v)}
                variant="destructive"
                className="mt-3 font-mono text-xs"
              >
                <Zap className="size-3.5" /> Launch simulation
              </Button>
            </div>
          );
        })}
      </div>

      <div className="grid gap-4 xl:grid-cols-[1fr_320px]">
        <Panel title="Injected telemetry" subtitle="Last 40 ingested events" bodyClassName="p-3">
          <LogTable logs={recent} maxHeight="46vh" />
        </Panel>
        <Panel title="Fired alerts" subtitle={`${alerts.length} total`}>
          <ul className="space-y-3">
            {alerts.slice(0, 8).map((a) => (
              <li key={a.id} className="rounded-md border border-border bg-surface/50 p-3">
                <div className="flex items-center justify-between gap-2">
                  <span className="font-mono text-[11px] text-muted-foreground">{a.id}</span>
                  <SeverityBadge severity={a.severity} />
                </div>
                <p className="mt-1 text-xs text-foreground/90">{a.title}</p>
                <p className="mt-1 font-mono text-[10px] text-warning">{a.mitre}</p>
              </li>
            ))}
          </ul>
        </Panel>
      </div>
    </div>
  );
}
