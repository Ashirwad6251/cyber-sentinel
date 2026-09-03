import { cn } from "@/lib/utils";
import type { AlertStatus, Severity } from "@/lib/siem/types";
import type { ReactNode } from "react";

const sevStyles: Record<Severity, string> = {
  INFO: "border-info/40 bg-info/10 text-info",
  WARN: "border-warning/40 bg-warning/10 text-warning",
  ERROR: "border-destructive/30 bg-destructive/10 text-destructive",
  CRITICAL: "border-critical/60 bg-critical/20 text-critical text-glow",
};

export function SeverityBadge({ severity, className }: { severity: Severity; className?: string }) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded border px-1.5 py-0.5 font-mono text-[10px] font-semibold tracking-widest uppercase",
        sevStyles[severity],
        className,
      )}
    >
      {severity}
    </span>
  );
}

const statusStyles: Record<AlertStatus, string> = {
  New: "border-critical/50 bg-critical/15 text-critical",
  Investigating: "border-warning/50 bg-warning/15 text-warning",
  Closed: "border-primary/40 bg-primary/10 text-primary",
};

export function StatusBadge({ status }: { status: AlertStatus }) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 text-[11px] font-medium",
        statusStyles[status],
      )}
    >
      <span className="size-1.5 rounded-full bg-current" />
      {status}
    </span>
  );
}

export function Panel({
  title,
  subtitle,
  action,
  children,
  className,
  bodyClassName,
}: {
  title?: string;
  subtitle?: string;
  action?: ReactNode;
  children: ReactNode;
  className?: string;
  bodyClassName?: string;
}) {
  return (
    <section className={cn("glass rounded-lg", className)}>
      {(title || action) && (
        <header className="flex items-center justify-between gap-3 border-b border-border px-4 py-3">
          <div>
            {title && (
              <h2 className="font-mono text-xs font-semibold tracking-[0.18em] text-muted-foreground uppercase">
                {title}
              </h2>
            )}
            {subtitle && <p className="mt-1 text-sm text-foreground/80">{subtitle}</p>}
          </div>
          {action}
        </header>
      )}
      <div className={cn("p-4", bodyClassName)}>{children}</div>
    </section>
  );
}

export function LiveDot({ active }: { active: boolean }) {
  return (
    <span
      className={cn(
        "inline-block size-2 rounded-full",
        active ? "pulse-dot bg-primary text-primary" : "bg-muted-foreground",
      )}
    />
  );
}

export const fmtTime = (t: number) =>
  new Date(t).toLocaleTimeString("en-GB", { hour12: false }) +
  "." +
  String(t % 1000).padStart(3, "0");

export const fmtDateTime = (t: number) =>
  new Date(t).toLocaleString("en-GB", { hour12: false });
