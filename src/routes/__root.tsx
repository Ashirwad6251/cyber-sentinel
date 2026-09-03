import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  Outlet,
  Link,
  createRootRouteWithContext,
  useRouter,
  HeadContent,
  Scripts,
} from "@tanstack/react-router";
import { useEffect, type ReactNode } from "react";
import {
  Activity,
  AlertTriangle,
  LayoutDashboard,
  Radio,
  Search,
  ShieldAlert,
  Swords,
} from "lucide-react";

import appCss from "../styles.css?url";
import { reportLovableError } from "../lib/lovable-error-reporting";
import { SiemProvider, useSiem } from "@/lib/siem/store";
import { Toaster } from "@/components/ui/sonner";
import { LiveDot } from "@/components/siem/primitives";

function NotFoundComponent() {
  return (
    <div className="flex min-h-screen items-center justify-center bg-background px-4">
      <div className="max-w-md text-center">
        <h1 className="font-mono text-7xl font-bold text-primary">404</h1>
        <h2 className="mt-4 text-xl font-semibold text-foreground">Console not found</h2>
        <p className="mt-2 text-sm text-muted-foreground">
          This SOC module does not exist or has been decommissioned.
        </p>
        <div className="mt-6">
          <Link
            to="/"
            className="inline-flex items-center justify-center rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground transition-colors hover:bg-primary/90"
          >
            Back to overview
          </Link>
        </div>
      </div>
    </div>
  );
}

function ErrorComponent({ error, reset }: { error: Error; reset: () => void }) {
  console.error(error);
  const router = useRouter();
  useEffect(() => {
    reportLovableError(error, { boundary: "tanstack_root_error_component" });
  }, [error]);

  return (
    <div className="flex min-h-screen items-center justify-center bg-background px-4">
      <div className="max-w-md text-center">
        <h1 className="text-xl font-semibold tracking-tight text-foreground">
          This console didn't load
        </h1>
        <p className="mt-2 text-sm text-muted-foreground">
          Something went wrong on our end. You can retry or return to the overview.
        </p>
        <div className="mt-6 flex flex-wrap justify-center gap-2">
          <button
            onClick={() => {
              router.invalidate();
              reset();
            }}
            className="inline-flex items-center justify-center rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground transition-colors hover:bg-primary/90"
          >
            Try again
          </button>
          <a
            href="/"
            className="inline-flex items-center justify-center rounded-md border border-input bg-background px-4 py-2 text-sm font-medium text-foreground transition-colors hover:bg-accent"
          >
            Go home
          </a>
        </div>
      </div>
    </div>
  );
}

export const Route = createRootRouteWithContext<{ queryClient: QueryClient }>()({
  head: () => ({
    meta: [
      { charSet: "utf-8" },
      { name: "viewport", content: "width=device-width, initial-scale=1" },
      { title: "CyberShield SIEM — SOC Console" },
      {
        name: "description",
        content:
          "CyberShield SIEM: live log ingestion, threat detection rules and incident response for security operations teams.",
      },
      { name: "author", content: "CyberShield" },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
    links: [
      { rel: "stylesheet", href: appCss },
      { rel: "preconnect", href: "https://fonts.googleapis.com" },
      { rel: "preconnect", href: "https://fonts.gstatic.com", crossOrigin: "anonymous" },
      {
        rel: "stylesheet",
        href: "https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;700&display=swap",
      },
      { rel: "icon", href: "/favicon.ico", type: "image/x-icon" },
    ],
  }),
  shellComponent: RootShell,
  component: RootComponent,
  notFoundComponent: NotFoundComponent,
  errorComponent: ErrorComponent,
});

function RootShell({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <head>
        <HeadContent />
      </head>
      <body>
        {children}
        <Scripts />
      </body>
    </html>
  );
}

const NAV = [
  { to: "/", label: "Overview", icon: LayoutDashboard },
  { to: "/logs", label: "Live Stream", icon: Radio },
  { to: "/simulator", label: "Attack Sim", icon: Swords },
  { to: "/rules", label: "Detections", icon: ShieldAlert },
  { to: "/alerts", label: "Alert Triage", icon: AlertTriangle },
  { to: "/search", label: "Forensics", icon: Search },
] as const;

function Chrome({ children }: { children: ReactNode }) {
  const { eps, paused, alerts } = useSiem();
  const critical = alerts.filter((a) => a.severity === "CRITICAL" && a.status !== "Closed").length;

  return (
    <div className="flex min-h-screen">
      <aside className="sticky top-0 hidden h-screen w-56 shrink-0 flex-col border-r border-border bg-sidebar/80 backdrop-blur lg:flex">
        <div className="flex items-center gap-2 px-4 py-5">
          <Activity className="size-5 text-primary" />
          <div>
            <p className="font-mono text-sm font-bold tracking-tight text-foreground">
              CyberShield
            </p>
            <p className="font-mono text-[10px] tracking-[0.2em] text-primary uppercase">SIEM</p>
          </div>
        </div>
        <nav className="flex-1 space-y-1 px-2">
          {NAV.map(({ to, label, icon: Icon }) => (
            <Link
              key={to}
              to={to}
              activeOptions={{ exact: to === "/" }}
              className="flex items-center gap-2.5 rounded-md px-3 py-2 text-sm text-sidebar-foreground/70 transition-colors hover:bg-sidebar-accent hover:text-sidebar-accent-foreground"
              activeProps={{
                className:
                  "bg-primary/10 text-primary border border-primary/30 shadow-glow font-medium",
              }}
            >
              <Icon className="size-4" />
              {label}
              {to === "/alerts" && critical > 0 && (
                <span className="ml-auto rounded-full bg-critical/20 px-1.5 font-mono text-[10px] text-critical">
                  {critical}
                </span>
              )}
            </Link>
          ))}
        </nav>
        <div className="border-t border-border p-4 font-mono text-[10px] text-muted-foreground">
          <p>SOC-1 · TIER 2 ANALYST</p>
          <p className="mt-1 text-primary">a.patel@cybershield.io</p>
        </div>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-20 flex items-center justify-between gap-4 border-b border-border bg-background/80 px-4 py-3 backdrop-blur">
          <nav className="flex gap-1 overflow-x-auto lg:hidden">
            {NAV.map(({ to, label }) => (
              <Link
                key={to}
                to={to}
                activeOptions={{ exact: to === "/" }}
                className="rounded px-2 py-1 font-mono text-[11px] whitespace-nowrap text-muted-foreground"
                activeProps={{ className: "bg-primary/10 text-primary" }}
              >
                {label}
              </Link>
            ))}
          </nav>
          <div className="ml-auto flex items-center gap-4 font-mono text-[11px]">
            <span className="flex items-center gap-2 text-muted-foreground">
              <LiveDot active={!paused} />
              {paused ? "INGEST PAUSED" : "INGEST LIVE"}
            </span>
            <span className="text-muted-foreground">
              EPS <span className="text-primary">{eps.toLocaleString()}</span>
            </span>
            <span className="text-muted-foreground">
              CRIT <span className="text-critical">{critical}</span>
            </span>
          </div>
        </header>
        <main className="min-w-0 flex-1 p-4 lg:p-6">{children}</main>
      </div>
    </div>
  );
}

function RootComponent() {
  const { queryClient } = Route.useRouteContext();

  return (
    <QueryClientProvider client={queryClient}>
      <SiemProvider>
        <Chrome>
          {/* Required: nested routes render here. Removing <Outlet /> breaks all child routes. */}
          <Outlet />
        </Chrome>
        <Toaster position="top-right" />
      </SiemProvider>
    </QueryClientProvider>
  );
}
