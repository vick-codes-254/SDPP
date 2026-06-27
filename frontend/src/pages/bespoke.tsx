import {
  Activity,
  AlertTriangle,
  Camera as CameraIcon,
  CreditCard,
  Gauge,
  Radio,
  ScanFace,
  ShieldAlert,
  Siren,
  Video,
} from "lucide-react";
import { useEffect, useState, type ComponentType, type ReactNode } from "react";
import { HexHostmap, type HexNode } from "@/components/HexHostmap";
import {
  KeyIndicator, KeyIndicatorStrip, SeverityGlyph, StatCard, StatusBanner,
} from "@/components/metrics";
import { CYBER_TO_TACTIC, MitreMatrix } from "@/components/MitreMatrix";
import { TriageTable, sevCell } from "@/components/TriageTable";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import { useAuth } from "@/context/AuthContext";
import { api } from "@/lib/api";

type Dict = Record<string, unknown>;
const num = (v: unknown) => (typeof v === "number" ? v : Number(v ?? 0));

function Stat({ icon: Icon, label, value, accent }: {
  icon: ComponentType<{ className?: string }>; label: string; value: ReactNode; accent?: string;
}) {
  return (
    <Card>
      <CardHeader className="flex-row items-center justify-between space-y-0 pb-2">
        <CardTitle>{label}</CardTitle>
        <Icon className={`h-4 w-4 ${accent ?? "text-muted-foreground"}`} />
      </CardHeader>
      <CardContent><div className="text-2xl font-semibold">{value}</div></CardContent>
    </Card>
  );
}

function useOrg() {
  const { user } = useAuth();
  return (user?.organization_id as string | undefined) ?? "";
}

function Bars({ data }: { data: Record<string, number> }) {
  const max = Math.max(1, ...Object.values(data));
  const entries = Object.entries(data).filter(([, v]) => v > 0);
  if (!entries.length) return <p className="text-sm text-muted-foreground">No data yet.</p>;
  return (
    <div className="space-y-1.5">
      {entries.map(([k, v]) => (
        <div key={k} className="flex items-center gap-2 text-sm">
          <span className="w-40 shrink-0 truncate text-muted-foreground">{k.replace(/_/g, " ")}</span>
          <div className="h-2 flex-1 rounded bg-muted">
            <div className="h-2 rounded bg-primary" style={{ width: `${(v / max) * 100}%` }} />
          </div>
          <span className="w-8 text-right tabular-nums">{v}</span>
        </div>
      ))}
    </div>
  );
}

// ── Executive Dashboard ─────────────────────────────────────────
export function ExecutiveDashboard() {
  const org = useOrg();
  const [kpis, setKpis] = useState<Dict | null>(null);
  const [enc, setEnc] = useState<Dict | null>(null);
  const [soc, setSoc] = useState<Dict | null>(null);
  const [threats, setThreats] = useState<Dict | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    if (!org) return;
    api.get<Dict>(`/analytics/kpis?organization_id=${org}`).then(setKpis).catch((e) => setErr(e.message));
    api.get<Dict>("/security-dashboard").then(setEnc).catch(() => undefined);
    api.get<Dict>(`/cyber/soc?organization_id=${org}`).then(setSoc).catch(() => undefined);
    api.get<Dict>(`/detections/threats/summary?organization_id=${org}`).then(setThreats).catch(() => undefined);
  }, [org]);

  if (err) return <p className="text-destructive">{err}</p>;
  if (!kpis) return <p className="text-muted-foreground">Loading…</p>;
  const health = num(enc?.encryption_health_score);

  const activeThreats = num(threats?.total);
  const openIncidents = num(kpis.open_incidents);
  const openCyber = num(kpis.open_cyber_events);
  const posture =
    activeThreats > 0 || openIncidents > 0 ? "critical" : openCyber > 0 ? "warning" : "ok";

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Executive Dashboard</h1>
          <p className="text-sm text-muted-foreground">Unified physical &amp; cyber security posture</p>
        </div>
        {enc && (
          <Badge variant={health >= 90 ? "success" : health >= 70 ? "warning" : "destructive"}>
            Encryption health {health}%
          </Badge>
        )}
      </div>

      <StatusBanner tone={posture}>
        {posture === "ok"
          ? "All clear — no active threats or open incidents."
          : `${activeThreats} active threat(s), ${openIncidents} open incident(s), ${openCyber} open cyber event(s).`}
      </StatusBanner>

      {/* Key Indicators strip (Splunk ES) */}
      <KeyIndicatorStrip>
        <KeyIndicator label="Active Threats" value={activeThreats} tone={activeThreats ? "critical" : "ok"} />
        <KeyIndicator label="Open Incidents" value={openIncidents} tone={openIncidents ? "warning" : "ok"} />
        <KeyIndicator label="Cyber Events" value={openCyber} tone={openCyber ? "warning" : "ok"} />
        <KeyIndicator label="Cameras Online" value={`${num(kpis.cameras_online)}/${num(kpis.cameras)}`} tone="default" />
        <KeyIndicator label="Guards On Duty" value={num(kpis.guards_on_duty)} tone="default" />
        <KeyIndicator label="Visitors On Site" value={num(kpis.visitors_on_site)} tone="default" />
      </KeyIndicatorStrip>

      {/* Premium KPI cards (CrowdStrike numerals + Grafana stat) */}
      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        <StatCard label="Sites" value={num(kpis.sites)} icon={Gauge} accent="var(--iris)" />
        <StatCard label="Open Threats" value={num(kpis.open_threats)} icon={ShieldAlert} accent="var(--sev-high)" />
        <StatCard label="Cameras" value={num(kpis.cameras)} icon={Video} accent="var(--signal)" />
        <StatCard label="Encryption Health" value={`${health}%`} icon={Activity}
          accent={health >= 90 ? "var(--sev-low)" : "var(--sev-high)"} />
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        <Card>
          <CardHeader><CardTitle>Threats by risk</CardTitle></CardHeader>
          <CardContent>
            <Bars data={Object.fromEntries(
              Object.entries(threats ?? {}).filter(([k]) => k !== "total").map(([k, v]) => [k, num(v)]),
            )} />
          </CardContent>
        </Card>
        <Card>
          <CardHeader><CardTitle>Cyber events by type</CardTitle></CardHeader>
          <CardContent>
            <Bars data={Object.fromEntries(
              Object.entries((soc?.by_type as Dict) ?? {}).map(([k, v]) => [k, num(v)]),
            )} />
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

// ── Live Monitoring ─────────────────────────────────────────────
export function LiveMonitoring() {
  const org = useOrg();
  const [cams, setCams] = useState<Dict[]>([]);
  const [health, setHealth] = useState<Dict | null>(null);
  useEffect(() => {
    if (!org) return;
    api.get<Dict[]>(`/cameras?organization_id=${org}`).then(setCams).catch(() => undefined);
    api.get<Dict>(`/cameras/health?organization_id=${org}`).then(setHealth).catch(() => undefined);
  }, [org]);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="flex items-center gap-2 text-2xl font-semibold"><Radio className="h-6 w-6 text-primary" /> Live Monitoring</h1>
        {health && (
          <span className="text-sm text-muted-foreground">
            {num(health.online)}/{num(health.total)} online · {num(health.recording)} recording
          </span>
        )}
      </div>
      {cams.length > 0 && (
        <Card>
          <CardHeader><CardTitle>Camera fleet health</CardTitle></CardHeader>
          <CardContent>
            <HexHostmap nodes={cams.map((c): HexNode => ({
              label: String(c.name),
              meta: String(c.status),
              status: c.status === "online" ? "ok" : c.status === "offline" ? "crit" : "warn",
            }))} />
          </CardContent>
        </Card>
      )}
      {cams.length === 0 ? (
        <p className="text-muted-foreground">No cameras registered. Add cameras under Physical Security → Cameras.</p>
      ) : (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {cams.map((c) => {
            const online = c.status === "online";
            return (
              <Card key={String(c.id)} className="overflow-hidden">
                <div className="flex aspect-video items-center justify-center bg-black/80 text-muted-foreground">
                  {online ? <CameraIcon className="h-10 w-10 text-primary/70" /> : <span className="text-xs">SIGNAL LOST</span>}
                </div>
                <CardContent className="flex items-center justify-between py-3">
                  <div>
                    <div className="font-medium">{String(c.name)}</div>
                    <div className="text-xs text-muted-foreground">{String(c.manufacturer ?? "camera")}</div>
                  </div>
                  <div className="flex items-center gap-2">
                    {Boolean(c.is_recording) && <Badge variant="destructive">● REC</Badge>}
                    <Badge variant={online ? "success" : "muted"}>{String(c.status)}</Badge>
                  </div>
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ── SOC / Cyber ─────────────────────────────────────────────────
export function SOC() {
  const org = useOrg();
  const [events, setEvents] = useState<Dict[]>([]);
  const [soc, setSoc] = useState<Dict | null>(null);
  const load = () => {
    if (!org) return;
    api.get<Dict[]>(`/cyber/events?organization_id=${org}`).then(setEvents).catch(() => undefined);
    api.get<Dict>(`/cyber/soc?organization_id=${org}`).then(setSoc).catch(() => undefined);
  };
  useEffect(load, [org]);

  return (
    <div className="space-y-6">
      <h1 className="flex items-center gap-2 text-2xl font-semibold">
        <ShieldAlert className="h-6 w-6 text-primary" /> Security Operations Center
      </h1>
      <div className="grid grid-cols-2 gap-4 md:grid-cols-3">
        <Stat icon={AlertTriangle} label="Total cyber events" value={num(soc?.total_events)} accent="text-amber-400" />
        <Stat icon={Siren} label="Open events" value={num(soc?.open_events)} accent="text-destructive" />
        <Stat icon={Activity} label="Event types seen" value={Object.values((soc?.by_type as Dict) ?? {}).filter((v) => num(v) > 0).length} />
      </div>
      <Card>
        <CardHeader><CardTitle>MITRE ATT&CK — cyber tactics</CardTitle></CardHeader>
        <CardContent>
          <MitreMatrix counts={events.reduce<Record<string, number>>((acc, e) => {
            const tac = CYBER_TO_TACTIC[String(e.event_type)];
            if (tac) acc[tac] = (acc[tac] ?? 0) + 1;
            return acc;
          }, {})} />
        </CardContent>
      </Card>
      <Card>
        <CardHeader><CardTitle>Cyber event queue</CardTitle></CardHeader>
        <CardContent className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="text-left text-muted-foreground">
              <tr><th className="pb-2 pr-4">Type</th><th className="pb-2 pr-4">Severity</th>
                <th className="pb-2 pr-4">User</th><th className="pb-2 pr-4">Title</th><th className="pb-2">When</th></tr>
            </thead>
            <tbody>
              {events.map((e) => (
                <tr key={String(e.id)} className="border-t border-border/50">
                  <td className="py-2 pr-4">{String(e.event_type)}</td>
                  <td className="py-2 pr-4">
                    <Badge variant={e.severity === "critical" || e.severity === "high" ? "destructive" : "muted"}>
                      {String(e.severity)}
                    </Badge>
                  </td>
                  <td className="py-2 pr-4">{String(e.username ?? "—")}</td>
                  <td className="py-2 pr-4">{String(e.title)}</td>
                  <td className="py-2 text-muted-foreground">{String(e.occurred_at ?? "").slice(0, 16)}</td>
                </tr>
              ))}
              {events.length === 0 && (
                <tr><td colSpan={5} className="py-3 text-center text-muted-foreground">No cyber events</td></tr>
              )}
            </tbody>
          </table>
        </CardContent>
      </Card>
    </div>
  );
}

// ── Analytics ───────────────────────────────────────────────────
export function Analytics() {
  const org = useOrg();
  const [rt, setRt] = useState<Dict | null>(null);
  const [up, setUp] = useState<Dict | null>(null);
  const [det, setDet] = useState<Dict | null>(null);
  const [trend, setTrend] = useState<Dict[]>([]);
  useEffect(() => {
    if (!org) return;
    api.get<Dict>(`/analytics/response-times?organization_id=${org}`).then(setRt).catch(() => undefined);
    api.get<Dict>(`/analytics/camera-uptime?organization_id=${org}`).then(setUp).catch(() => undefined);
    api.get<Dict>(`/analytics/detections?organization_id=${org}`).then(setDet).catch(() => undefined);
    api.get<Dict[]>(`/analytics/trends/incidents?organization_id=${org}`).then(setTrend).catch(() => undefined);
  }, [org]);

  return (
    <div className="space-y-6">
      <h1 className="flex items-center gap-2 text-2xl font-semibold"><Gauge className="h-6 w-6 text-primary" /> Analytics & BI</h1>
      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        <Stat icon={Activity} label="Avg ack (min)" value={rt?.avg_ack_minutes != null ? String(rt.avg_ack_minutes) : "—"} />
        <Stat icon={Activity} label="Avg resolve (min)" value={rt?.avg_resolve_minutes != null ? String(rt.avg_resolve_minutes) : "—"} />
        <Stat icon={AlertTriangle} label="SLA breached (open)" value={num(rt?.sla_breached_open)} accent="text-destructive" />
        <Stat icon={Video} label="Camera uptime" value={`${num(up?.uptime_pct)}%`} accent="text-primary" />
      </div>
      <div className="grid gap-4 md:grid-cols-2">
        <Card>
          <CardHeader><CardTitle>Detections by type</CardTitle></CardHeader>
          <CardContent><Bars data={Object.fromEntries(Object.entries(det ?? {}).map(([k, v]) => [k, num(v)]))} /></CardContent>
        </Card>
        <Card>
          <CardHeader><CardTitle>Incident trend (per day)</CardTitle></CardHeader>
          <CardContent>
            <Bars data={Object.fromEntries(trend.map((d) => [String(d.date).slice(5), num(d.count)]))} />
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

// ── Emergency Response ──────────────────────────────────────────
const EMERGENCIES = ["panic", "lockdown", "evacuation", "fire", "medical", "police", "broadcast"];

export function Emergency() {
  const org = useOrg();
  const [events, setEvents] = useState<Dict[]>([]);
  const [sites, setSites] = useState<Dict[]>([]);
  const [site, setSite] = useState("");
  const [msg, setMsg] = useState<string | null>(null);

  const load = () => {
    if (!org) return;
    api.get<Dict[]>(`/emergency/events?organization_id=${org}`).then(setEvents).catch(() => undefined);
    api.get<Dict[]>(`/sites?organization_id=${org}`).then(setSites).catch(() => undefined);
  };
  useEffect(load, [org]);

  const trigger = async (type: string) => {
    setMsg(null);
    try {
      const r = await api.post<Dict>("/emergency/trigger", {
        organization_id: org, event_type: type, site_id: site || null, message: `${type} triggered from console`,
      });
      setMsg(`${type.toUpperCase()} triggered — ${num(r.notified_count)} recipients notified.`);
      load();
    } catch (e) {
      setMsg(e instanceof Error ? e.message : "Failed");
    }
  };

  return (
    <div className="space-y-6">
      <h1 className="flex items-center gap-2 text-2xl font-semibold"><Siren className="h-6 w-6 text-destructive" /> Emergency Response</h1>
      <Card>
        <CardHeader><CardTitle>Trigger emergency</CardTitle></CardHeader>
        <CardContent className="space-y-3">
          <div className="max-w-xs">
            <Select value={site} onValueChange={setSite}>
              <SelectTrigger><SelectValue placeholder="All sites (optional)" /></SelectTrigger>
              <SelectContent>{sites.map((s) => <SelectItem key={String(s.id)} value={String(s.id)}>{String(s.name)}</SelectItem>)}</SelectContent>
            </Select>
          </div>
          <div className="flex flex-wrap gap-2">
            {EMERGENCIES.map((t) => (
              <Button key={t} variant={t === "panic" || t === "fire" ? "destructive" : "outline"} onClick={() => trigger(t)}>
                {t}
              </Button>
            ))}
          </div>
          {msg && <p className="text-sm text-muted-foreground">{msg}</p>}
        </CardContent>
      </Card>
      <Card>
        <CardHeader><CardTitle>Recent emergencies</CardTitle></CardHeader>
        <CardContent className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="text-left text-muted-foreground">
              <tr><th className="pb-2 pr-4">Type</th><th className="pb-2 pr-4">Status</th>
                <th className="pb-2 pr-4">Notified</th><th className="pb-2">Actions</th></tr>
            </thead>
            <tbody>
              {events.map((e) => (
                <tr key={String(e.id)} className="border-t border-border/50">
                  <td className="py-2 pr-4 font-medium">{String(e.event_type)}</td>
                  <td className="py-2 pr-4"><Badge variant={e.status === "resolved" ? "success" : "destructive"}>{String(e.status)}</Badge></td>
                  <td className="py-2 pr-4">{num(e.notified_count)}</td>
                  <td className="py-2">
                    {e.status !== "resolved" && (
                      <Button size="sm" variant="outline"
                        onClick={async () => { await api.post(`/emergency/events/${e.id}/resolve`); load(); }}>
                        Resolve
                      </Button>
                    )}
                  </td>
                </tr>
              ))}
              {events.length === 0 && <tr><td colSpan={4} className="py-3 text-center text-muted-foreground">No emergencies</td></tr>}
            </tbody>
          </table>
        </CardContent>
      </Card>
    </div>
  );
}

// ── Billing ─────────────────────────────────────────────────────
export function Billing() {
  const org = useOrg();
  const [sub, setSub] = useState<Dict | null>(null);
  const [usage, setUsage] = useState<Dict | null>(null);
  const [invoices, setInvoices] = useState<Dict[]>([]);
  const [plan, setPlan] = useState("professional");

  const load = () => {
    if (!org) return;
    api.get<Dict | null>(`/billing/subscription?organization_id=${org}`).then(setSub).catch(() => undefined);
    api.get<Dict>(`/billing/usage?organization_id=${org}`).then(setUsage).catch(() => undefined);
    api.get<Dict[]>(`/billing/invoices?organization_id=${org}`).then(setInvoices).catch(() => undefined);
  };
  useEffect(load, [org]);

  const savePlan = async () => {
    await api.put(`/billing/subscription`, { organization_id: org, plan });
    load();
  };

  const used = (usage?.used as Dict) ?? {};
  const limits = (usage?.limits as Dict) ?? {};

  return (
    <div className="space-y-6">
      <h1 className="flex items-center gap-2 text-2xl font-semibold"><CreditCard className="h-6 w-6 text-primary" /> Billing & Subscription</h1>
      <div className="grid gap-4 md:grid-cols-2">
        <Card>
          <CardHeader><CardTitle>Plan</CardTitle></CardHeader>
          <CardContent className="space-y-3">
            <div className="text-sm text-muted-foreground">
              Current: <span className="font-medium text-foreground">{String(sub?.plan ?? "—")}</span>
              {sub?.status ? <Badge variant="muted" className="ml-2">{String(sub.status)}</Badge> : null}
            </div>
            <div className="flex items-center gap-2">
              <div className="w-48">
                <Select value={plan} onValueChange={setPlan}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {["trial", "starter", "professional", "enterprise"].map((p) => <SelectItem key={p} value={p}>{p}</SelectItem>)}
                  </SelectContent>
                </Select>
              </div>
              <Button onClick={savePlan}>Update plan</Button>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader><CardTitle>Usage vs plan</CardTitle></CardHeader>
          <CardContent className="space-y-2 text-sm">
            {Object.keys(used).map((k) => (
              <div key={k} className="flex justify-between">
                <span className="text-muted-foreground">{k}</span>
                <span>{num(used[k])} / {limits[k] == null ? "∞" : num(limits[k])}</span>
              </div>
            ))}
            {Object.keys(used).length === 0 && <p className="text-muted-foreground">No usage data.</p>}
          </CardContent>
        </Card>
      </div>
      <Card>
        <CardHeader><CardTitle>Invoices</CardTitle></CardHeader>
        <CardContent className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="text-left text-muted-foreground">
              <tr><th className="pb-2 pr-4">Number</th><th className="pb-2 pr-4">Amount</th>
                <th className="pb-2 pr-4">Status</th><th className="pb-2">Actions</th></tr>
            </thead>
            <tbody>
              {invoices.map((inv) => (
                <tr key={String(inv.id)} className="border-t border-border/50">
                  <td className="py-2 pr-4 font-medium">{String(inv.number)}</td>
                  <td className="py-2 pr-4">{String(inv.currency)} {num(inv.amount)}</td>
                  <td className="py-2 pr-4"><Badge variant={inv.status === "paid" ? "success" : "warning"}>{String(inv.status)}</Badge></td>
                  <td className="py-2">
                    {inv.status !== "paid" && (
                      <Button size="sm" variant="outline"
                        onClick={async () => { await api.post(`/billing/invoices/${inv.id}/pay`, { method: "card" }); load(); }}>
                        Pay
                      </Button>
                    )}
                  </td>
                </tr>
              ))}
              {invoices.length === 0 && <tr><td colSpan={4} className="py-3 text-center text-muted-foreground">No invoices</td></tr>}
            </tbody>
          </table>
        </CardContent>
      </Card>
    </div>
  );
}

// ── AI Detections triage (CrowdStrike-style queue + flyout) ─────
const DET_TYPES = [
  "person", "unknown_person", "weapon", "fire", "smoke", "intrusion",
  "perimeter_breach", "loitering", "tailgating", "vehicle", "abandoned_object", "crowd",
];
const SEV_OPTS = ["critical", "high", "medium", "low", "info"];
const DET_STATUS = ["new", "reviewing", "confirmed", "dismissed"];
const SEVVAR: Record<string, string> = {
  critical: "var(--sev-critical)", high: "var(--sev-high)", medium: "var(--sev-medium)",
  low: "var(--sev-low)", info: "var(--sev-info)",
};
const sevColorVar = (s: string) => SEVVAR[s.toLowerCase()];

function DRow({ k, v, mono }: { k: string; v: string; mono?: boolean }) {
  return (
    <div className="flex justify-between gap-4 border-b border-border/50 py-1.5">
      <span className="text-muted-foreground">{k}</span>
      <span className={mono ? "mono text-xs" : ""}>{v}</span>
    </div>
  );
}

function IngestControl({ org, reload }: { org: string; reload: () => void }) {
  const [type, setType] = useState("intrusion");
  const [busy, setBusy] = useState(false);
  return (
    <div className="flex items-center gap-2">
      <div className="w-44">
        <Select value={type} onValueChange={setType}>
          <SelectTrigger><SelectValue /></SelectTrigger>
          <SelectContent>
            {DET_TYPES.map((t) => <SelectItem key={t} value={t}>{t.replace(/_/g, " ")}</SelectItem>)}
          </SelectContent>
        </Select>
      </div>
      <Button disabled={busy} onClick={async () => {
        setBusy(true);
        try { await api.post("/detections/ingest", { organization_id: org, detection_type: type, confidence: 0.9 }); reload(); }
        finally { setBusy(false); }
      }}>
        <ScanFace className="h-4 w-4" /> Ingest
      </Button>
    </div>
  );
}

export function DetectionsTriage() {
  const org = useOrg();
  return (
    <TriageTable
      title="AI Detections"
      icon={ScanFace}
      description="Triage AI detection events from cameras and sensors. Select a row to investigate."
      list={(o) => `/detections?organization_id=${o}`}
      searchKeys={["detection_type", "label", "status"]}
      headerActions={(reload) => <IngestControl org={org} reload={reload} />}
      filters={[
        { key: "severity", label: "Severity", options: SEV_OPTS.map((v) => ({ value: v, label: v })) },
        { key: "status", label: "Status", options: DET_STATUS.map((v) => ({ value: v, label: v })) },
        { key: "detection_type", label: "Type", options: DET_TYPES.map((v) => ({ value: v, label: v.replace(/_/g, " ") })) },
      ]}
      columns={[
        { key: "severity", label: "Severity", width: "140px", render: sevCell("severity"), tint: (r) => sevColorVar(String(r.severity)) },
        { key: "detection_type", label: "Type", render: (r) => <span className="capitalize">{String(r.detection_type).replace(/_/g, " ")}</span> },
        { key: "confidence", label: "Confidence", mono: true, render: (r) => `${Math.round(num(r.confidence) * 100)}%` },
        { key: "status", label: "Status", render: (r) => (
          <Badge variant={r.status === "confirmed" ? "destructive" : r.status === "dismissed" ? "muted" : "warning"}>
            {String(r.status)}
          </Badge>
        ) },
        { key: "detected_at", label: "Detected", mono: true, render: (r) => String(r.detected_at ?? "").slice(0, 16).replace("T", " ") },
      ]}
      renderDrawer={(row, reload, close) => {
        const setStatus = async (s: string) => { await api.post(`/detections/${row.id}/status`, { status: s }); reload(); close(); };
        return (
          <div className="space-y-4">
            <SeverityGlyph severity={String(row.severity)} />
            <div className="text-lg font-semibold capitalize">{String(row.detection_type).replace(/_/g, " ")}</div>
            <div className="text-sm">
              <DRow k="Confidence" v={`${Math.round(num(row.confidence) * 100)}%`} />
              <DRow k="Status" v={String(row.status)} />
              <DRow k="Detected" v={String(row.detected_at ?? "").slice(0, 16).replace("T", " ")} />
              <DRow k="Detection ID" v={String(row.id)} mono />
              {row.threat_id ? <DRow k="Correlated threat" v={String(row.threat_id)} mono /> : null}
            </div>
            <div className="flex flex-wrap gap-2 pt-1">
              <Button size="sm" variant="outline" onClick={() => setStatus("reviewing")}>Mark reviewing</Button>
              <Button size="sm" variant="outline" onClick={() => setStatus("confirmed")}>Confirm</Button>
              <Button size="sm" variant="outline" onClick={() => setStatus("dismissed")}>Dismiss</Button>
            </div>
          </div>
        );
      }}
    />
  );
}
