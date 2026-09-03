import { useState } from "react";
import { Sheet, SheetContent, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { ScrollArea } from "@/components/ui/scroll-area";
import { SeverityBadge, fmtDateTime, fmtTime } from "./primitives";
import type { LogEntry } from "@/lib/siem/types";
import { cn } from "@/lib/utils";

export function LogTable({
  logs,
  emptyLabel = "No events match the current filters.",
  animateNew = false,
  maxHeight = "60vh",
}: {
  logs: LogEntry[];
  emptyLabel?: string;
  animateNew?: boolean;
  maxHeight?: string;
}) {
  const [selected, setSelected] = useState<LogEntry | null>(null);

  return (
    <>
      <div className="overflow-hidden rounded-md border border-border">
        <div className="grid grid-cols-[130px_120px_130px_130px_90px_1fr_90px] gap-2 border-b border-border bg-surface-2/60 px-3 py-2 font-mono text-[10px] tracking-widest text-muted-foreground uppercase">
          <span>Timestamp</span>
          <span>Source</span>
          <span>Source IP</span>
          <span>Dest IP</span>
          <span>Event ID</span>
          <span>Message</span>
          <span className="text-right">Severity</span>
        </div>
        <ScrollArea style={{ height: maxHeight }}>
          {logs.length === 0 ? (
            <p className="px-3 py-10 text-center text-sm text-muted-foreground">{emptyLabel}</p>
          ) : (
            <ul className="divide-y divide-border/60">
              {logs.map((log, i) => (
                <li key={log.id}>
                  <button
                    onClick={() => setSelected(log)}
                    className={cn(
                      "grid w-full grid-cols-[130px_120px_130px_130px_90px_1fr_90px] items-center gap-2 px-3 py-1.5 text-left font-mono text-xs transition-colors hover:bg-primary/5",
                      animateNew && i === 0 && "scan-in",
                      log.severity === "CRITICAL" && "bg-critical/5",
                    )}
                  >
                    <span className="text-muted-foreground">{fmtTime(log.timestamp)}</span>
                    <span className="truncate text-foreground/70">{log.source}</span>
                    <span className="text-warning/90">{log.sourceIp}</span>
                    <span className="text-info/90">{log.destIp}</span>
                    <span className="text-foreground/70">{log.eventId}</span>
                    <span className="truncate text-foreground/90">{log.message}</span>
                    <span className="text-right">
                      <SeverityBadge severity={log.severity} />
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </ScrollArea>
      </div>

      <Sheet open={!!selected} onOpenChange={(o) => !o && setSelected(null)}>
        <SheetContent className="w-full overflow-y-auto sm:max-w-xl">
          {selected && (
            <>
              <SheetHeader>
                <SheetTitle className="font-mono text-sm">
                  Event {selected.eventId} · {selected.source}
                </SheetTitle>
              </SheetHeader>
              <div className="space-y-4 px-4 pb-8">
                <div className="flex items-center gap-2">
                  <SeverityBadge severity={selected.severity} />
                  <span className="font-mono text-xs text-muted-foreground">
                    {fmtDateTime(selected.timestamp)}
                  </span>
                </div>
                <p className="text-sm leading-relaxed text-foreground/90">{selected.message}</p>
                <dl className="grid grid-cols-2 gap-3 rounded-md border border-border bg-surface/60 p-3 font-mono text-xs">
                  {[
                    ["source.ip", selected.sourceIp],
                    ["destination.ip", selected.destIp],
                    ["destination.port", String(selected.port)],
                    ["host.name", selected.host],
                    ["user.name", selected.user],
                    ["event.action", selected.action],
                    ["geo.country", selected.country],
                    ["log.source", selected.source],
                  ].map(([k, v]) => (
                    <div key={k}>
                      <dt className="text-muted-foreground">{k}</dt>
                      <dd className="text-foreground">{v}</dd>
                    </div>
                  ))}
                </dl>
                <div>
                  <h3 className="mb-2 font-mono text-[10px] tracking-widest text-muted-foreground uppercase">
                    Raw JSON
                  </h3>
                  <pre className="overflow-x-auto rounded-md border border-border bg-background/80 p-3 font-mono text-[11px] leading-relaxed text-primary/90">
                    {JSON.stringify(selected, null, 2)}
                  </pre>
                </div>
              </div>
            </>
          )}
        </SheetContent>
      </Sheet>
    </>
  );
}
