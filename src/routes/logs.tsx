import { createFileRoute } from "@tanstack/react-router";
import { useMemo, useState } from "react";
import { Pause, Play, Search as SearchIcon } from "lucide-react";
import { useSiem } from "@/lib/siem/store";
import { LOG_SOURCES, SEVERITIES } from "@/lib/siem/mock";
import { LogTable } from "@/components/siem/LogTable";
import { LiveDot, Panel } from "@/components/siem/primitives";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

export const Route = createFileRoute("/logs")({
  head: () => ({
    meta: [
      { title: "Live Log Stream — CyberShield SIEM" },
      {
        name: "description",
        content:
          "Real-time log ingestion console with pause/resume, source and severity filters, and raw JSON event inspection.",
      },
      { property: "og:title", content: "Live Log Stream — CyberShield SIEM" },
      {
        property: "og:description",
        content: "Stream syslog, Windows Event, CloudTrail, firewall and EDR telemetry in real time.",
      },
    ],
  }),
  component: LogsPage,
});

function LogsPage() {
  const { logs, paused, setPaused } = useSiem();
  const [source, setSource] = useState("all");
  const [severity, setSeverity] = useState("all");
  const [q, setQ] = useState("");

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return logs
      .filter((l) => source === "all" || l.source === source)
      .filter((l) => severity === "all" || l.severity === severity)
      .filter(
        (l) =>
          !needle ||
          l.message.toLowerCase().includes(needle) ||
          l.sourceIp.includes(needle) ||
          l.destIp.includes(needle) ||
          l.host.toLowerCase().includes(needle) ||
          l.eventId.toLowerCase().includes(needle),
      )
      .slice()
      .reverse();
  }, [logs, source, severity, q]);

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold tracking-tight text-foreground">
            Live Log Ingestion Stream
          </h1>
          <p className="mt-1 text-sm text-muted-foreground">
            {filtered.length.toLocaleString()} of {logs.length.toLocaleString()} buffered events ·
            click any row for parsed JSON.
          </p>
        </div>
        <Button
          variant={paused ? "default" : "outline"}
          onClick={() => setPaused(!paused)}
          className="font-mono text-xs"
        >
          {paused ? <Play className="size-3.5" /> : <Pause className="size-3.5" />}
          {paused ? "Resume stream" : "Pause stream"}
        </Button>
      </div>

      <Panel
        title="Stream filters"
        action={
          <span className="flex items-center gap-2 font-mono text-[11px] text-muted-foreground">
            <LiveDot active={!paused} />
            {paused ? "PAUSED" : "STREAMING"}
          </span>
        }
      >
        <div className="grid gap-3 sm:grid-cols-[1fr_180px_180px]">
          <div className="relative">
            <SearchIcon className="absolute top-2.5 left-3 size-4 text-muted-foreground" />
            <Input
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder="Search message, IP, host or event ID…"
              className="pl-9 font-mono text-xs"
            />
          </div>
          <Select value={source} onValueChange={setSource}>
            <SelectTrigger className="font-mono text-xs">
              <SelectValue placeholder="Log source" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All log sources</SelectItem>
              {LOG_SOURCES.map((s) => (
                <SelectItem key={s} value={s}>
                  {s}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Select value={severity} onValueChange={setSeverity}>
            <SelectTrigger className="font-mono text-xs">
              <SelectValue placeholder="Severity" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All severities</SelectItem>
              {SEVERITIES.map((s) => (
                <SelectItem key={s} value={s}>
                  {s}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      </Panel>

      <LogTable logs={filtered} animateNew={!paused} maxHeight="62vh" />
    </div>
  );
}
