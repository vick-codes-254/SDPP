import {
  Activity, AlertTriangle, Bot, Clock, Database, Gauge, ShieldAlert, Siren, Timer, Zap,
} from "lucide-react";
import { useEffect, useState, type ReactNode } from "react";
import { AreaChart, HBars, MultiLine, VBars } from "@/components/charts";
import { SeverityGlyph, StatCard } from "@/components/metrics";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { useAuth } from "@/context/AuthContext";
import { api } from "@/lib/api";
import { cn } from "@/lib/utils";

type Dict = Record<string, unknown>;
const num = (v: unknown) => (typeof v === "number" ? v : Number(v ?? 0));
const fmtMin = (m: number | null | undefined) =>
  m == null ? "—" : m >= 60 ? `${Math.floor(m / 60)}h ${Math.round(m % 60)}m` : `${Math.round(m)}m`;
const minutesBetween = (a?: string, b?: string) =>
  a && b ? (new Date(a).getTime() - new Date(b).getTime()) / 60000 : null;

const SEV_COLOR: Record<string, string> = {
  critical: "var(--sev-critical)", high: "var(--sev-high)", medium: "var(--sev-medium)",
  low: "var(--sev-low)", info: "var(--sev-info)", none: "#8B93A3",
};

// ── small UI helpers ───────────────────────────────────────────
function Dots({ page, pages, onPage }: { page: number; pages: number; onPage: (p: number) => void }) {
  if (pages <= 1) return null;
  return (
    <div className="flex items-center justify-center gap-1.5 pt-3">
      {Array.from({ length: pages }).map((_, i) => (
        <button key={i} onClick={() => onPage(i)}
          className={cn("h-1.5 rounded-full transition-all", i === page ? "w-4 bg-primary" : "w-1.5 bg-muted-foreground/40 hover:bg-muted-foreground/70")} />
      ))}
    </div>
  );
}

function BigStat({ value, label, color }: { value: ReactNode; label: string; color?: string }) {
  return (
    <div className="shrink-0 text-right">
      <div className="kpi-hero text-3xl" style={color ? { color } : undefined}>{value}</div>
      <div className="label-micro mt-1">{label}</div>
    </div>
  );
}

// ── Donut (with Unresolved / Closed / All tabs, by severity) ───
function StatusDonutCard({ incidents }: { incidents: Dict[] }) {
  const [tab, setTab] = useState<"Unresolved" | "Closed" | "All">("Unresolved");
  const filtered = incidents.filter((i) => {
    const s = String(i.status);
    if (tab === "Unresolved") return !["resolved", "closed"].includes(s);
    if (tab === "Closed") return ["resolved", "closed"].includes(s);
    return true;
  });
  let high = 0, med = 0, low = 0;
  for (const i of filtered) {
    const s = String(i.severity);
    if (s === "critical" || s === "high") high++; else if (s === "medium") med++; else low++;
  }
  const segs = [
    { label: "High", value: high, color: "var(--sev-critical)" },
    { label: "Medium", value: med, color: "var(--sev-high)" },
    { label: "Low", value: low, color: "var(--sev-medium)" },
  ];
  const sum = high + med + low || 1;
  const C = 2 * Math.PI * 42;
  let off = 0;
  return (
    <Card>
      <CardHeader className="flex-row items-center justify-between">
        <CardTitle>Events by Status</CardTitle>
        <div className="flex gap-1 rounded-md border border-border p-0.5">
          {(["Unresolved", "Closed", "All"] as const).map((t) => (
            <button key={t} onClick={() => setTab(t)}
              className={cn("rounded px-2 py-0.5 text-[11px] font-medium transition-colors",
                tab === t ? "bg-primary/15 text-primary" : "text-muted-foreground hover:text-foreground")}>
              {t}
            </button>
          ))}
        </div>
      </CardHeader>
      <CardContent className="flex items-center gap-5">
        <div className="relative h-40 w-40 shrink-0">
          <svg viewBox="0 0 100 100" className="h-full w-full -rotate-90">
            <circle cx={50} cy={50} r={42} fill="none" stroke="hsl(var(--muted))" strokeWidth={11} opacity={0.4} />
            {segs.map((s, i) => {
              const len = (s.value / sum) * C;
              const el = <circle key={i} cx={50} cy={50} r={42} fill="none" stroke={s.color} strokeWidth={11}
                strokeDasharray={`${len} ${C - len}`} strokeDashoffset={-off} />;
              off += len;
              return el;
            })}
          </svg>
          <div className="absolute inset-0 flex flex-col items-center justify-center">
            <span className="kpi-hero text-3xl">{filtered.length}</span>
            <span className="label-micro mt-0.5">events</span>
          </div>
        </div>
        <div className="space-y-1.5 text-sm">
          {segs.map((s) => (
            <div key={s.label} className="flex items-center gap-2">
              <span className="h-2.5 w-2.5 rounded-sm" style={{ background: s.color }} />
              <span className="text-muted-foreground">{s.label}</span>
              <span className="ml-auto tabular-nums">{s.value}</span>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}

// ── Workload by type (bars + total + pagination) ───────────────
function WorkloadCard({ items }: { items: { label: string; value: number }[] }) {
  const [page, setPage] = useState(0);
  const size = 5;
  const pages = Math.ceil(items.length / size) || 1;
  const slice = items.slice(page * size, page * size + size);
  const total = items.reduce((a, b) => a + b.value, 0);
  return (
    <Card>
      <CardHeader><CardTitle>Workload by Type</CardTitle></CardHeader>
      <CardContent>
        <div className="flex items-center gap-4">
          <div className="flex-1">{slice.length ? <HBars items={slice} /> : <p className="text-sm text-muted-foreground">No events yet.</p>}</div>
          <BigStat value={total} label="Total events" />
        </div>
        <Dots page={page} pages={pages} onPage={setPage} />
      </CardContent>
    </Card>
  );
}

// ── Open incidents (table + pagination) ────────────────────────
function OpenIncidentsCard({ incidents }: { incidents: Dict[] }) {
  const [page, setPage] = useState(0);
  const open = incidents.filter((i) => !["resolved", "closed"].includes(String(i.status)));
  const size = 6;
  const pages = Math.ceil(open.length / size) || 1;
  const slice = open.slice(page * size, page * size + size);
  const sla = (i: Dict) => {
    const due = i.sla_due_at as string | undefined;
    if (!due) return <span className="text-muted-foreground">—</span>;
    const rem = (new Date(due).getTime() - Date.now()) / 60000;
    return rem < 0
      ? <span className="font-medium" style={{ color: "var(--sev-critical)" }}>Breached</span>
      : <span className="text-muted-foreground">{fmtMin(rem)} left</span>;
  };
  return (
    <Card>
      <CardHeader><CardTitle>Open Incidents</CardTitle></CardHeader>
      <CardContent className="p-0">
        <table className="data-table">
          <thead><tr><th>Name</th><th>SLA</th><th>Severity</th></tr></thead>
          <tbody>
            {slice.map((i) => (
              <tr key={String(i.id)}>
                <td className="max-w-[180px] truncate">{String(i.title)}</td>
                <td>{sla(i)}</td>
                <td><SeverityGlyph severity={String(i.severity)} /></td>
              </tr>
            ))}
            {open.length === 0 && <tr><td colSpan={3} className="py-6 text-center text-muted-foreground">No open incidents</td></tr>}
          </tbody>
        </table>
        <div className="px-3 pb-3"><Dots page={page} pages={pages} onPage={setPage} /></div>
      </CardContent>
    </Card>
  );
}

export function MissionControl() {
  const { user } = useAuth();
  const org = (user?.organization_id as string | undefined) ?? "";
  const [d, setD] = useState<{
    kpis: Dict; rt: Dict; soc: Dict; threats: Dict;
    incidents: Dict[]; detections: Dict[]; rules: Dict[]; incTrend: Dict[]; thrTrend: Dict[];
  } | null>(null);

  useEffect(() => {
    if (!org) return;
    const g = <T,>(p: string, fb: T) => api.get<T>(p).catch(() => fb);
    Promise.all([
      g<Dict>(`/analytics/kpis?organization_id=${org}`, {}),
      g<Dict>(`/analytics/response-times?organization_id=${org}`, {}),
      g<Dict>(`/cyber/soc?organization_id=${org}`, {}),
      g<Dict>(`/detections/threats/summary?organization_id=${org}`, {}),
      g<Dict[]>(`/incidents`, []),
      g<Dict[]>(`/detections?organization_id=${org}`, []),
      g<Dict[]>(`/workflows/rules?organization_id=${org}`, []),
      g<Dict[]>(`/analytics/trends/incidents?organization_id=${org}&days=14`, []),
      g<Dict[]>(`/analytics/trends/threats?organization_id=${org}&days=14`, []),
    ]).then(([kpis, rt, soc, threats, incidents, detections, rules, incTrend, thrTrend]) =>
      setD({ kpis, rt, soc, threats, incidents, detections, rules, incTrend, thrTrend }));
  }, [org]);

  if (!d) return <p className="text-muted-foreground">Loading mission control…</p>;

  const incTrendData = d.incTrend.map((x) => num(x.count));
  const thrTrendData = d.thrTrend.map((x) => num(x.count));
  const pctDelta = (s: number[]) => s.length >= 2
    ? Math.round(((s.at(-1)! - s.at(-2)!) / Math.max(1, s.at(-2)!)) * 100) : undefined;

  // SLA compliance
  let within = 0, breached = 0, maxTtr = 0;
  for (const i of d.incidents) {
    const due = i.sla_due_at as string | undefined, res = i.resolved_at as string | undefined;
    if (res && due) { if (new Date(res) <= new Date(due)) within++; else breached++; }
    else if (due && !res && Date.now() > new Date(due).getTime()) breached++;
    const ttr = minutesBetween(res, i.created_at as string);
    if (ttr && ttr > maxTtr) maxTtr = ttr;
  }
  const considered = within + breached;
  const compliancePct = considered ? Math.round((within / considered) * 100) : 100;
  const overPct = 100 - compliancePct;

  const detBySev: Record<string, number> = {};
  for (const x of d.detections) detBySev[String(x.severity)] = (detBySev[String(x.severity)] ?? 0) + 1;

  const byType = (d.soc.by_type as Dict) ?? {};
  const eventItems = Object.entries(byType).map(([k, v]) => ({ label: k, value: num(v) }))
    .filter((x) => x.value > 0).sort((a, b) => b.value - a.value);

  const ruleItems = d.rules.map((r) => ({ label: String(r.name), value: num(r.trigger_count) }))
    .filter((x) => x.value > 0).slice(0, 8);
  const automationRuns = d.rules.reduce((a, r) => a + num(r.trigger_count), 0);
  const avgActions = d.rules.length ? Math.round(automationRuns / d.rules.length) : 0;

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Mission Control</h1>
        <p className="text-sm text-muted-foreground">SOC efficiency, workload, and operational health</p>
      </div>

      {/* Business-value KPI strip */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-7">
        <StatCard label="Open Incidents" value={num(d.kpis.open_incidents)} delta={pctDelta(incTrendData)} icon={Siren} accent="var(--sev-high)" />
        <StatCard label="Active Threats" value={num(d.threats.total)} delta={pctDelta(thrTrendData)} icon={ShieldAlert} accent="var(--sev-critical)" />
        <StatCard label="Cyber Events" value={num(d.soc.open_events)} icon={AlertTriangle} accent="var(--sev-medium)" />
        <StatCard label="Mean TTR" value={fmtMin(d.rt.avg_resolve_minutes as number)} icon={Timer} accent="var(--iris)" />
        <StatCard label="Mean TTA" value={fmtMin(d.rt.avg_ack_minutes as number)} icon={Clock} accent="var(--signal)" />
        <StatCard label="SLA Breached" value={num(d.rt.sla_breached_open)} icon={Gauge} accent="var(--sev-critical)" />
        <StatCard label="Automation Runs" value={automationRuns} icon={Bot} accent="var(--sev-low)" />
      </div>

      {/* Row 2 — SLA, Workload, Donut */}
      <div className="grid gap-4 lg:grid-cols-3">
        <Card>
          <CardHeader><CardTitle>SLA Compliance · 14 days</CardTitle></CardHeader>
          <CardContent>
            <div className="flex items-center gap-4">
              <div className="flex-1">
                <AreaChart data={incTrendData} color={overPct > 20 ? "var(--sev-critical)" : "var(--sev-low)"} height={116} />
              </div>
              <BigStat value={`${compliancePct}%`} label="within SLA"
                color={overPct > 20 ? "var(--sev-critical)" : "var(--sev-low)"} />
            </div>
            <div className="mt-3 flex gap-4 text-xs text-muted-foreground">
              <span className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-full" style={{ background: "var(--sev-low)" }} /> Within SLA ({within})</span>
              <span className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-full" style={{ background: "var(--sev-critical)" }} /> Over SLA ({breached})</span>
            </div>
          </CardContent>
        </Card>
        <WorkloadCard items={eventItems} />
        <StatusDonutCard incidents={d.incidents} />
      </div>

      {/* Row 3 — Performance, Activity, Open */}
      <div className="grid gap-4 lg:grid-cols-3">
        <Card>
          <CardHeader><CardTitle>Response Performance</CardTitle></CardHeader>
          <CardContent className="grid grid-cols-2 gap-y-5">
            {[
              ["Mean Time to Resolve", fmtMin(d.rt.avg_resolve_minutes as number)],
              ["Max Time to Resolve", fmtMin(maxTtr || null)],
              ["Mean Time to Ack", fmtMin(d.rt.avg_ack_minutes as number)],
              ["Open SLA Breached", String(num(d.rt.sla_breached_open))],
            ].map(([k, v]) => (
              <div key={k}>
                <div className="kpi-hero text-2xl">{v}</div>
                <div className="label-micro mt-1">{k}</div>
              </div>
            ))}
          </CardContent>
        </Card>
        <Card>
          <CardHeader><CardTitle>Activity Over Time</CardTitle></CardHeader>
          <CardContent>
            <MultiLine series={[
              { label: "Incidents", color: "var(--iris)", data: incTrendData },
              { label: "Detections", color: "var(--sev-high)", data: thrTrendData },
            ]} />
          </CardContent>
        </Card>
        <OpenIncidentsCard incidents={d.incidents} />
      </div>

      {/* Row 4 — bars + big stat */}
      <div className="grid gap-4 lg:grid-cols-3">
        <Card>
          <CardHeader className="flex-row items-center justify-between">
            <CardTitle>Executed Playbooks &amp; Actions</CardTitle>
            <Zap className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="flex items-end gap-4">
              <div className="flex-1">{ruleItems.length ? <VBars items={ruleItems} /> : <p className="text-sm text-muted-foreground">No automation runs yet.</p>}</div>
              <div className="shrink-0 space-y-3 text-right">
                <div><div className="kpi-hero text-2xl">{automationRuns}</div><div className="label-micro mt-1">Actions executed</div></div>
                <div><div className="kpi-hero text-lg text-muted-foreground">{avgActions}</div><div className="label-micro">Avg / rule</div></div>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader><CardTitle>Detections by Severity</CardTitle></CardHeader>
          <CardContent>
            <div className="flex items-end gap-4">
              <div className="flex-1">
                <VBars items={["critical", "high", "medium", "low", "info"].map((s) => ({ label: s, value: detBySev[s] ?? 0, color: SEV_COLOR[s] }))} />
              </div>
              <BigStat value={d.detections.length} label="Detections" />
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex-row items-center justify-between">
            <CardTitle>Incoming Events</CardTitle>
            <Database className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="flex items-end gap-4">
              <div className="flex-1"><VBars items={eventItems.slice(0, 6).map((e) => ({ ...e, color: "var(--signal)" }))} /></div>
              <BigStat value={num(d.soc.total_events)} label="Total events" />
            </div>
          </CardContent>
        </Card>
      </div>

      <div className="flex items-center gap-2 pt-1 text-xs text-muted-foreground">
        <Activity className="h-3.5 w-3.5" /> Live SOC metrics · auto-derived from incidents, detections, cyber events &amp; automation.
      </div>
    </div>
  );
}
