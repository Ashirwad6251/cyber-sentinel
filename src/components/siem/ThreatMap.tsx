import { useMemo } from "react";
import type { LogEntry } from "@/lib/siem/types";
import { cn } from "@/lib/utils";

const project = (lat: number, lon: number) => ({
  x: ((lon + 180) / 360) * 100,
  y: ((90 - lat) / 180) * 100,
});

export function ThreatMap({ logs }: { logs: LogEntry[] }) {
  const origins = useMemo(() => {
    const map = new Map<string, { country: string; lat: number; lon: number; count: number; worst: string }>();
    for (const log of logs.slice(-400)) {
      const key = log.country;
      const cur = map.get(key);
      const worst =
        log.severity === "CRITICAL" || cur?.worst === "CRITICAL"
          ? "CRITICAL"
          : log.severity === "ERROR" || cur?.worst === "ERROR"
            ? "ERROR"
            : "INFO";
      map.set(key, {
        country: key,
        lat: log.geo.lat,
        lon: log.geo.lon,
        count: (cur?.count ?? 0) + 1,
        worst,
      });
    }
    return [...map.values()].sort((a, b) => b.count - a.count);
  }, [logs]);

  const hq = project(37.77, -122.42);

  return (
    <div className="relative aspect-[2/1] w-full overflow-hidden rounded-md border border-border bg-background/60">
      <div className="grid-bg absolute inset-0" />
      <svg viewBox="0 0 100 50" className="absolute inset-0 h-full w-full" preserveAspectRatio="none">
        {origins.map((o) => {
          const p = project(o.lat, o.lon);
          const color =
            o.worst === "CRITICAL"
              ? "var(--critical)"
              : o.worst === "ERROR"
                ? "var(--warning)"
                : "var(--primary)";
          const mx = (p.x + hq.x) / 2;
          const my = Math.min(p.y, hq.y / 2) - 8;
          return (
            <g key={o.country}>
              <path
                d={`M ${p.x} ${p.y / 2} Q ${mx} ${my} ${hq.x} ${hq.y / 2}`}
                fill="none"
                stroke={color}
                strokeWidth="0.25"
                opacity="0.45"
              />
              <circle cx={p.x} cy={p.y / 2} r={Math.min(1.8, 0.5 + o.count / 40)} fill={color} opacity="0.9" />
              <circle cx={p.x} cy={p.y / 2} r="2.4" fill="none" stroke={color} strokeWidth="0.15" opacity="0.4" />
            </g>
          );
        })}
        <circle cx={hq.x} cy={hq.y / 2} r="1.2" fill="var(--primary)" />
        <circle cx={hq.x} cy={hq.y / 2} r="3" fill="none" stroke="var(--primary)" strokeWidth="0.2" opacity="0.5" />
      </svg>

      <div className="absolute top-3 left-3 font-mono text-[10px] tracking-widest text-muted-foreground uppercase">
        Threat origin telemetry · SOC HQ us-west-1
      </div>
      <ul className="absolute right-3 bottom-3 space-y-1 rounded-md border border-border bg-background/80 p-2 font-mono text-[10px] backdrop-blur">
        {origins.slice(0, 5).map((o) => (
          <li key={o.country} className="flex items-center gap-2">
            <span
              className={cn(
                "size-1.5 rounded-full",
                o.worst === "CRITICAL"
                  ? "bg-critical"
                  : o.worst === "ERROR"
                    ? "bg-warning"
                    : "bg-primary",
              )}
            />
            <span className="w-28 truncate text-foreground/80">{o.country}</span>
            <span className="text-muted-foreground">{o.count}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}
