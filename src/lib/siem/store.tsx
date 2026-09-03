import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { toast } from "sonner";
import {
  ATTACK_META,
  DEFAULT_RULES,
  buildAttack,
  makeLog,
  seedLogs,
  uid,
} from "./mock";
import type {
  AlertRecord,
  AlertStatus,
  AttackVector,
  DetectionRule,
  LogEntry,
} from "./types";

const MAX_LOGS = 1200;

interface SiemState {
  logs: LogEntry[];
  alerts: AlertRecord[];
  rules: DetectionRule[];
  paused: boolean;
  totalIngested: number;
  eps: number;
  epsSeries: Array<{ t: number; eps: number }>;
  setPaused: (v: boolean) => void;
  triggerAttack: (v: AttackVector) => void;
  toggleRule: (id: string) => void;
  addRule: (r: Omit<DetectionRule, "id" | "fired">) => void;
  updateAlert: (id: string, patch: Partial<AlertRecord>, timelineLabel?: string) => void;
}

const SiemContext = createContext<SiemState | null>(null);

function initialAlerts(logs: LogEntry[]): AlertRecord[] {
  const now = Date.now();
  const pickLogs = (n: number) => logs.slice(-n).map((l) => l.id);
  return [
    {
      id: "ALT-4471",
      ruleId: "R-1005",
      ruleName: "Console Login Without MFA",
      title: "AWS console login without MFA from unrecognized device",
      severity: "WARN",
      status: "Investigating",
      timestamp: now - 1000 * 60 * 22,
      mitre: "T1078",
      sourceIp: "185.220.101.44",
      host: "aws-prod-account",
      assignee: "a.patel",
      logIds: pickLogs(3),
      timeline: [
        { at: now - 1000 * 60 * 22, label: "Rule R-1005 matched 1 event" },
        { at: now - 1000 * 60 * 18, label: "Assigned to a.patel" },
      ],
    },
    {
      id: "ALT-4468",
      ruleId: "R-1007",
      ruleName: "Impossible Travel Sign-in",
      title: "Impossible travel sign-in for identity j.doe",
      severity: "ERROR",
      status: "New",
      timestamp: now - 1000 * 60 * 51,
      mitre: "T1078.004",
      sourceIp: "103.216.44.19",
      host: "hr-ws-114",
      assignee: "Unassigned",
      logIds: pickLogs(5),
      timeline: [{ at: now - 1000 * 60 * 51, label: "Rule R-1007 matched 2 events" }],
    },
    {
      id: "ALT-4455",
      ruleId: "R-1004",
      ruleName: "Horizontal / Vertical Port Scan",
      title: "Port scan against vpn-gw-edge from 45.155.205.233",
      severity: "ERROR",
      status: "Closed",
      timestamp: now - 1000 * 60 * 140,
      mitre: "T1046",
      sourceIp: "45.155.205.233",
      host: "vpn-gw-edge",
      assignee: "m.chen",
      logIds: pickLogs(8),
      timeline: [
        { at: now - 1000 * 60 * 140, label: "Rule R-1004 matched 26 events" },
        { at: now - 1000 * 60 * 120, label: "Source IP blocked at edge firewall" },
        { at: now - 1000 * 60 * 118, label: "Closed by m.chen" },
      ],
    },
  ];
}

export function SiemProvider({ children }: { children: ReactNode }) {
  const seeded = useMemo(() => seedLogs(126), []);
  const [logs, setLogs] = useState<LogEntry[]>(seeded);
  const [alerts, setAlerts] = useState<AlertRecord[]>(() => initialAlerts(seeded));
  const [rules, setRules] = useState<DetectionRule[]>(() =>
    DEFAULT_RULES.map((r) => ({ ...r, fired: r.id === "R-1004" ? 1 : r.id === "R-1005" ? 1 : 0 })),
  );
  const [paused, setPaused] = useState(false);
  const [totalIngested, setTotalIngested] = useState(1_482_930 + seeded.length);
  const [epsSeries, setEpsSeries] = useState<Array<{ t: number; eps: number }>>(() => {
    const now = Date.now();
    return Array.from({ length: 30 }, (_, i) => ({
      t: now - (30 - i) * 2000,
      eps: 220 + Math.round(Math.sin(i / 2.5) * 45 + Math.random() * 40),
    }));
  });

  const windowCount = useRef(0);
  const pausedRef = useRef(paused);
  pausedRef.current = paused;

  const pushLogs = useCallback((incoming: LogEntry[]) => {
    windowCount.current += incoming.length;
    setTotalIngested((t) => t + incoming.length);
    setLogs((prev) => {
      const next = [...prev, ...incoming];
      return next.length > MAX_LOGS ? next.slice(next.length - MAX_LOGS) : next;
    });
  }, []);

  // Background benign ingestion: 2-3 logs every 5s
  useEffect(() => {
    const id = setInterval(() => {
      if (pausedRef.current) return;
      const n = 2 + Math.floor(Math.random() * 2);
      pushLogs(Array.from({ length: n }, () => makeLog()));
    }, 5000);
    return () => clearInterval(id);
  }, [pushLogs]);

  // EPS sampler
  useEffect(() => {
    const id = setInterval(() => {
      const synthetic = pausedRef.current ? 0 : 210 + Math.round(Math.random() * 90);
      const eps = synthetic + windowCount.current * 12;
      windowCount.current = 0;
      setEpsSeries((prev) => [...prev.slice(-59), { t: Date.now(), eps }]);
    }, 2000);
    return () => clearInterval(id);
  }, []);

  const triggerAttack = useCallback(
    (vector: AttackVector) => {
      const { logs: attackLogs, alert } = buildAttack(vector);
      pushLogs(attackLogs);
      const full: AlertRecord = { ...alert, logIds: attackLogs.map((l) => l.id) };
      setAlerts((prev) => [full, ...prev]);
      setRules((prev) =>
        prev.map((r) => (r.id === alert.ruleId ? { ...r, fired: r.fired + 1 } : r)),
      );
      toast.error(`${ATTACK_META[vector].label} simulated`, {
        description: `${attackLogs.length} events ingested — alert ${full.id} fired (${alert.mitre}).`,
      });
    },
    [pushLogs],
  );

  const toggleRule = useCallback((id: string) => {
    setRules((prev) => prev.map((r) => (r.id === id ? { ...r, enabled: !r.enabled } : r)));
  }, []);

  const addRule = useCallback((r: Omit<DetectionRule, "id" | "fired">) => {
    const rule: DetectionRule = { ...r, id: uid("R").toUpperCase(), fired: 0 };
    setRules((prev) => [rule, ...prev]);
    toast.success("Detection rule deployed", { description: rule.name });
  }, []);

  const updateAlert = useCallback(
    (id: string, patch: Partial<AlertRecord>, timelineLabel?: string) => {
      setAlerts((prev) =>
        prev.map((a) =>
          a.id === id
            ? {
                ...a,
                ...patch,
                timeline: timelineLabel
                  ? [...a.timeline, { at: Date.now(), label: timelineLabel }]
                  : a.timeline,
              }
            : a,
        ),
      );
    },
    [],
  );

  const value = useMemo<SiemState>(
    () => ({
      logs,
      alerts,
      rules,
      paused,
      totalIngested,
      eps: epsSeries[epsSeries.length - 1]?.eps ?? 0,
      epsSeries,
      setPaused,
      triggerAttack,
      toggleRule,
      addRule,
      updateAlert,
    }),
    [logs, alerts, rules, paused, totalIngested, epsSeries, triggerAttack, toggleRule, addRule, updateAlert],
  );

  return <SiemContext.Provider value={value}>{children}</SiemContext.Provider>;
}

export function useSiem() {
  const ctx = useContext(SiemContext);
  if (!ctx) throw new Error("useSiem must be used inside SiemProvider");
  return ctx;
}

export const severityRank: Record<string, number> = { INFO: 0, WARN: 1, ERROR: 2, CRITICAL: 3 };

export function statusOf(alerts: AlertRecord[], status: AlertStatus) {
  return alerts.filter((a) => a.status === status);
}
