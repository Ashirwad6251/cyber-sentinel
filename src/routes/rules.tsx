import { createFileRoute } from "@tanstack/react-router";
import { useState } from "react";
import { Plus } from "lucide-react";
import { useSiem } from "@/lib/siem/store";
import { LOG_SOURCES, SEVERITIES } from "@/lib/siem/mock";
import { Panel, SeverityBadge } from "@/components/siem/primitives";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import type { LogSource, Severity } from "@/lib/siem/types";

export const Route = createFileRoute("/rules")({
  head: () => ({
    meta: [
      { title: "Detection Rules — CyberShield SIEM" },
      {
        name: "description",
        content:
          "SIGMA-style detection rule inventory with MITRE ATT&CK mapping, enable toggles and a custom rule builder.",
      },
      { property: "og:title", content: "Detection Rules — CyberShield SIEM" },
      {
        property: "og:description",
        content: "Manage threat detection logic and correlation thresholds across all log sources.",
      },
    ],
  }),
  component: RulesPage,
});

function RulesPage() {
  const { rules, toggleRule, addRule } = useSiem();
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [field, setField] = useState("event_id");
  const [value, setValue] = useState("4625");
  const [count, setCount] = useState("5");
  const [windowSec, setWindowSec] = useState("60");
  const [severity, setSeverity] = useState<Severity>("CRITICAL");
  const [mitre, setMitre] = useState("T1110");
  const [logSource, setLogSource] = useState<LogSource | "Any">("Any");
  const [description, setDescription] = useState("");

  const condition = `${field} == "${value}" AND count > ${count || 0} IN ${windowSec || 0}s GROUP BY source.ip`;

  const submit = () => {
    if (!name.trim()) return;
    addRule({
      name: name.trim(),
      enabled: true,
      severity,
      mitre: mitre.trim() || "T1000",
      logSource,
      condition,
      description: description.trim() || "Custom analyst-authored detection.",
    });
    setOpen(false);
    setName("");
    setDescription("");
  };

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold tracking-tight text-foreground">
            Threat Detection &amp; SIGMA Rule Engine
          </h1>
          <p className="mt-1 text-sm text-muted-foreground">
            {rules.filter((r) => r.enabled).length} of {rules.length} rules active across the
            correlation engine.
          </p>
        </div>
        <Button onClick={() => setOpen(true)} className="font-mono text-xs">
          <Plus className="size-3.5" /> New detection rule
        </Button>
      </div>

      <Panel title="Rule inventory" bodyClassName="p-0">
        <div className="overflow-x-auto">
          <table className="w-full min-w-[900px] text-left text-sm">
            <thead>
              <tr className="border-b border-border font-mono text-[10px] tracking-widest text-muted-foreground uppercase">
                <th className="px-4 py-2">Status</th>
                <th className="px-4 py-2">Rule</th>
                <th className="px-4 py-2">Log source</th>
                <th className="px-4 py-2">MITRE</th>
                <th className="px-4 py-2">Severity</th>
                <th className="px-4 py-2 text-right">Fired</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border/60">
              {rules.map((r) => (
                <tr key={r.id} className="align-top hover:bg-primary/5">
                  <td className="px-4 py-3">
                    <Switch checked={r.enabled} onCheckedChange={() => toggleRule(r.id)} />
                  </td>
                  <td className="px-4 py-3">
                    <p className="font-medium text-foreground">{r.name}</p>
                    <p className="mt-0.5 text-xs text-muted-foreground">{r.description}</p>
                    <code className="mt-1 block rounded bg-background/70 px-2 py-1 font-mono text-[11px] text-primary/90">
                      {r.condition}
                    </code>
                  </td>
                  <td className="px-4 py-3 font-mono text-xs text-foreground/80">{r.logSource}</td>
                  <td className="px-4 py-3 font-mono text-xs text-warning">{r.mitre}</td>
                  <td className="px-4 py-3">
                    <SeverityBadge severity={r.severity} />
                  </td>
                  <td className="px-4 py-3 text-right font-mono text-xs text-foreground/80">
                    {r.fired}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>

      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>Custom rule builder</DialogTitle>
            <DialogDescription>
              Compose correlation logic using standardized event fields.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            <div className="space-y-1.5">
              <Label htmlFor="rule-name">Rule name</Label>
              <Input
                id="rule-name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="Excessive failed logons from single host"
                maxLength={120}
              />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <Label>IF field</Label>
                <Select value={field} onValueChange={setField}>
                  <SelectTrigger className="font-mono text-xs">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {["event_id", "source.ip", "user.name", "destination.port", "event.action"].map(
                      (f) => (
                        <SelectItem key={f} value={f}>
                          {f}
                        </SelectItem>
                      ),
                    )}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="rule-value">Equals</Label>
                <Input
                  id="rule-value"
                  value={value}
                  onChange={(e) => setValue(e.target.value)}
                  className="font-mono text-xs"
                  maxLength={64}
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="rule-count">Count greater than</Label>
                <Input
                  id="rule-count"
                  value={count}
                  onChange={(e) => setCount(e.target.value.replace(/\D/g, "").slice(0, 5))}
                  className="font-mono text-xs"
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="rule-window">Within (seconds)</Label>
                <Input
                  id="rule-window"
                  value={windowSec}
                  onChange={(e) => setWindowSec(e.target.value.replace(/\D/g, "").slice(0, 5))}
                  className="font-mono text-xs"
                />
              </div>
              <div className="space-y-1.5">
                <Label>Then trigger severity</Label>
                <Select value={severity} onValueChange={(v) => setSeverity(v as Severity)}>
                  <SelectTrigger className="font-mono text-xs">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {SEVERITIES.map((s) => (
                      <SelectItem key={s} value={s}>
                        {s}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1.5">
                <Label>Log source</Label>
                <Select value={logSource} onValueChange={(v) => setLogSource(v as LogSource | "Any")}>
                  <SelectTrigger className="font-mono text-xs">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="Any">Any</SelectItem>
                    {LOG_SOURCES.map((s) => (
                      <SelectItem key={s} value={s}>
                        {s}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="rule-mitre">MITRE ATT&amp;CK technique</Label>
              <Input
                id="rule-mitre"
                value={mitre}
                onChange={(e) => setMitre(e.target.value.slice(0, 16))}
                className="font-mono text-xs"
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="rule-desc">Description</Label>
              <Textarea
                id="rule-desc"
                value={description}
                onChange={(e) => setDescription(e.target.value.slice(0, 300))}
                rows={2}
              />
            </div>
            <div>
              <Label>Generated logic</Label>
              <code className="mt-1.5 block rounded-md border border-border bg-background/70 p-3 font-mono text-[11px] break-all text-primary/90">
                {condition} → ALERT {severity}
              </code>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setOpen(false)}>
              Cancel
            </Button>
            <Button onClick={submit} disabled={!name.trim()}>
              Deploy rule
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
