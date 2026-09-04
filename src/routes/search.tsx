import { createFileRoute } from "@tanstack/react-router";
import { useMemo, useState } from "react";
import { Clock, Terminal } from "lucide-react";
import { useSiem } from "@/lib/siem/store";
import { LogTable } from "@/components/siem/LogTable";
import { Panel } from "@/components/siem/primitives";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import type { LogEntry } from "@/lib/siem/types";

export const Route = createFileRoute("/search")({
  head: () => ({
    meta: [
      { title: "Log Forensics Search — CyberShield SIEM" },
      {
        name: "description",
        content:
          "Lucene-style query builder for forensic log search with quick time-range selection across all ingested telemetry.",
      },
      { property: "og:title", content: "Log Forensics Search — CyberShield SIEM" },
      {
        property: "og:description",
        content: "Investigate historical events with field queries such as source.ip and severity.",
      },
    ],
  }),
  component: SearchPage,
});

const RANGES = [
  { label: "Last 15m", ms: 15 * 60_000 },
  { label: "Last 1h", ms: 60 * 60_000 },
  { label: "Last 24h", ms: 24 * 60 * 60_000 },
  { label: "All time", ms: Number.POSITIVE_INFINITY },
] as const;

const FIELD_MAP: Record<string, (l: LogEntry) => string> = {
  "source.ip": (l) => l.sourceIp,
  "destination.ip": (l) => l.destIp,
  "destination.port": (l) => String(l.port),
  severity: (l) => l.severity,
  "log.source": (l) => l.source,
  "event.id": (l) => l.eventId,
  "host.name": (l) => l.host,
  "user.name": (l) => l.user,
  "geo.country": (l) => l.country,
  message: (l) => l.message,
};

interface Clause {
  field: string;
  value: string;
  negate: boolean;
}

function parseQuery(q: string): { clauses: Clause[]; free: string[]; errors: string[] } {
  const clauses: Clause[] = [];
  const free: string[] = [];
  const errors: string[] = [];
  const tokens = q.match(/(?:[\w.]+\s*:\s*)?(?:"[^"]*"|\S+)/g) ?? [];
  for (const raw of tokens) {
    const token = raw.trim();
    if (/^(AND|OR|NOT)$/i.test(token)) continue;
    const m = token.match(/^([\w.]+)\s*:\s*"?([^"]*)"?$/);
    if (m) {
      const [, field, value] = m;
      if (!FIELD_MAP[field!]) {
        errors.push(`unknown field "${field}"`);
        continue;
      }
      clauses.push({ field: field!, value: value!.toLowerCase(), negate: false });
    } else {
      free.push(token.replace(/"/g, "").toLowerCase());
    }
  }
  return { clauses, free, errors };
}

function SearchPage() {
  const { logs } = useSiem();
  const [input, setInput] = useState('severity: "CRITICAL"');
  const [query, setQuery] = useState('severity: "CRITICAL"');
  const [range, setRange] = useState<(typeof RANGES)[number]["label"]>("Last 24h");
  const [customFrom, setCustomFrom] = useState("");

  const rangeMs = RANGES.find((r) => r.label === range)?.ms ?? Number.POSITIVE_INFINITY;

  const { results, errors } = useMemo(() => {
    const { clauses, free, errors } = parseQuery(query);
    const cutoff = customFrom
      ? new Date(customFrom).getTime()
      : rangeMs === Number.POSITIVE_INFINITY
        ? 0
        : Date.now() - rangeMs;
    const results = logs
      .filter((l) => l.timestamp >= cutoff)
      .filter((l) =>
        clauses.every((c) => FIELD_MAP[c.field]!(l).toLowerCase().includes(c.value)),
      )
      .filter((l) =>
        free.every(
          (f) =>
            l.message.toLowerCase().includes(f) ||
            l.sourceIp.includes(f) ||
            l.host.toLowerCase().includes(f),
        ),
      )
      .reverse();
    return { results, errors };
  }, [logs, query, rangeMs, customFrom]);

  const examples = [
    'source.ip: "10." AND severity: "CRITICAL"',
    'log.source: "Firewall" AND destination.port: "3389"',
    'event.id: "4625"',
    'message: "1=1"',
  ];

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-xl font-semibold tracking-tight text-foreground">
          Log Search &amp; Forensics
        </h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Query the hot buffer with Lucene-style field expressions.
        </p>
      </div>

      <Panel title="Query builder">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            setQuery(input);
          }}
          className="space-y-3"
        >
          <div className="flex flex-col gap-2 sm:flex-row">
            <div className="relative flex-1">
              <Terminal className="absolute top-2.5 left-3 size-4 text-primary" />
              <Input
                value={input}
                onChange={(e) => setInput(e.target.value.slice(0, 300))}
                placeholder='source.ip: "192.168.1.50" AND severity: "CRITICAL"'
                className="pl-9 font-mono text-xs"
              />
            </div>
            <Button type="submit" className="font-mono text-xs">
              Run query
            </Button>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <Clock className="size-3.5 text-muted-foreground" />
            {RANGES.map((r) => (
              <button
                key={r.label}
                type="button"
                onClick={() => {
                  setRange(r.label);
                  setCustomFrom("");
                }}
                className={`rounded-md border px-2.5 py-1 font-mono text-[11px] transition-colors ${
                  range === r.label && !customFrom
                    ? "border-primary/50 bg-primary/10 text-primary"
                    : "border-border text-muted-foreground hover:text-foreground"
                }`}
              >
                {r.label}
              </button>
            ))}
            <label className="ml-2 flex items-center gap-2 font-mono text-[11px] text-muted-foreground">
              Custom from
              <Input
                type="datetime-local"
                value={customFrom}
                onChange={(e) => setCustomFrom(e.target.value)}
                className="h-8 w-52 font-mono text-[11px]"
              />
            </label>
          </div>

          <div className="flex flex-wrap gap-2">
            {examples.map((ex) => (
              <button
                key={ex}
                type="button"
                onClick={() => {
                  setInput(ex);
                  setQuery(ex);
                }}
                className="rounded border border-border bg-surface/50 px-2 py-1 font-mono text-[10px] text-muted-foreground hover:text-primary"
              >
                {ex}
              </button>
            ))}
          </div>

          {errors.length > 0 && (
            <p className="font-mono text-[11px] text-destructive">
              Query warning: {errors.join(", ")} — supported fields:{" "}
              {Object.keys(FIELD_MAP).join(", ")}
            </p>
          )}
        </form>
      </Panel>

      <div className="flex items-center justify-between font-mono text-[11px] text-muted-foreground">
        <span>
          {results.length.toLocaleString()} hits · {customFrom ? `since ${customFrom}` : range}
        </span>
        <span>buffer {logs.length.toLocaleString()} events</span>
      </div>

      <LogTable logs={results} maxHeight="55vh" emptyLabel="No events matched this query." />
    </div>
  );
}
