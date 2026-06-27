import { Activity, Banknote, Building2, Camera as CameraIcon, ShieldAlert, Wallet } from "lucide-react";
import { useEffect, useMemo, useState, type ReactNode } from "react";
import { AreaChart, Funnel, HBars, MultiLine, Scatter, Treemap, VBars } from "@/components/charts";
import { HexHostmap, type HexNode } from "@/components/HexHostmap";
import { StatusBanner } from "@/components/metrics";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { useAuth } from "@/context/AuthContext";
import { api } from "@/lib/api";

type Dict = Record<string, unknown>;
const num = (v: unknown) => (typeof v === "number" ? v : Number(v ?? 0));
const cap = (s: string) => s.replace(/_/g, " ");
const money = (n: number) => {
  const a = Math.abs(n);
  if (a >= 1e6) return `$${(n / 1e6).toFixed(2)}M`;
  if (a >= 1e3) return `$${(n / 1e3).toFixed(1)}K`;
  return `$${n.toFixed(0)}`;
};

const SEV_COLOR: Record<string, string> = {
  critical: "var(--sev-critical)", high: "var(--sev-high)", medium: "var(--sev-medium)",
  low: "var(--sev-low)", info: "var(--sev-info)",
};
const SEV_ORDER = ["critical", "high", "medium", "low", "info"] as const;
const PALETTE = ["var(--iris)", "var(--signal)", "var(--sev-high)", "var(--sev-critical)",
  "var(--sev-medium)", "var(--sev-low)", "#a78bfa", "#22d3ee", "#f472b6", "#34d399"];

/** Power BI "card" visual — micro label over a big value. */
function KpiHero({ label, value, icon: Icon, accent = "var(--iris)", sub }: {
  label: string; value: ReactNode; icon?: typeof Wallet; accent?: string; sub?: string;
}) {
  return (
    <div className="rounded-lg border border-border bg-card p-4">
      <div className="flex items-center justify-between">
        <span className="label-micro">{label}</span>
        {Icon && <Icon className="h-4 w-4" style={{ color: accent }} />}
      </div>
      <div className="kpi-hero mt-1.5 text-2xl" style={{ color: accent }}>{value}</div>
      {sub && <div className="mt-0.5 text-xs text-muted-foreground">{sub}</div>}
    </div>
  );
}

export function ExecutiveBI() {
  const { user } = useAuth();
  const org = (user?.organization_id as string | undefined) ?? "";
  const [d, setD] = useState<{
    kpis: Dict; threats: Dict; soc: Dict; enc: Dict; sub: Dict | null;
    invoices: Dict[]; payments: Dict[]; detections: Dict[]; incidents: Dict[];
    breakdown: Dict; incTrend: Dict[]; thrTrend: Dict[]; sites: Dict[]; cameras: Dict[];
  } | null>(null);

  useEffect(() => {
    if (!org) return;
    const g = <T,>(p: string, fb: T) => api.get<T>(p).catch(() => fb);
    Promise.all([
      g<Dict>(`/analytics/kpis?organization_id=${org}`, {}),
      g<Dict>(`/detections/threats/summary?organization_id=${org}`, {}),
      g<Dict>(`/cyber/soc?organization_id=${org}`, {}),
      g<Dict>(`/security-dashboard`, {}),
      g<Dict | null>(`/billing/subscription?organization_id=${org}`, null),
      g<Dict[]>(`/billing/invoices?organization_id=${org}`, []),
      g<Dict[]>(`/billing/payments?organization_id=${org}`, []),
      g<Dict[]>(`/detections?organization_id=${org}`, []),
      g<Dict[]>(`/incidents`, []),
      g<Dict>(`/analytics/detections?organization_id=${org}`, {}),
      g<Dict[]>(`/analytics/trends/incidents?organization_id=${org}&days=30`, []),
      g<Dict[]>(`/analytics/trends/threats?organization_id=${org}&days=30`, []),
      g<Dict[]>(`/sites?organization_id=${org}`, []),
      g<Dict[]>(`/cameras?organization_id=${org}`, []),
    ]).then(([kpis, threats, soc, enc, sub, invoices, payments, detections, incidents, breakdown, incTrend, thrTrend, sites, cameras]) =>
      setD({ kpis, threats, soc, enc, sub, invoices, payments, detections, incidents, breakdown, incTrend, thrTrend, sites, cameras }));
  }, [org]);

  const derived = useMemo(() => {
    if (!d) return null;
    // ── Financials ──
    const invoiced = d.invoices.reduce((a, i) => a + num(i.amount), 0);
    const collected = d.invoices.filter((i) => i.status === "paid").reduce((a, i) => a + num(i.amount), 0);
    const outstanding = invoiced - collected;
    const mrr = num(d.sub?.monthly_price);
    const arr = mrr * 12;
    // invoices by month → area
    const byMonth = new Map<string, number>();
    for (const i of d.invoices) {
      const k = String(i.issued_at ?? i.created_at ?? "").slice(0, 7);
      if (k) byMonth.set(k, (byMonth.get(k) ?? 0) + num(i.amount));
    }
    const months = [...byMonth.keys()].sort();
    const invoiceArea = months.map((m) => byMonth.get(m) ?? 0);
    // ── Detection / incident lifecycle funnel ──
    const st: Record<string, number> = {};
    for (const x of d.detections) st[String(x.status)] = (st[String(x.status)] ?? 0) + 1;
    const openInc = d.incidents.filter((i) => !["resolved", "closed"].includes(String(i.status))).length;
    const closedInc = d.incidents.length - openInc;
    const funnel = [
      { label: "Detections", value: d.detections.length, color: "var(--signal)" },
      { label: "Under review", value: (st.reviewing ?? 0) + (st.confirmed ?? 0), color: "var(--iris)" },
      { label: "Confirmed", value: st.confirmed ?? 0, color: "var(--sev-medium)" },
      { label: "Active threats", value: num(d.threats.total), color: "var(--sev-high)" },
      { label: "Open incidents", value: openInc, color: "var(--sev-critical)" },
      { label: "Resolved", value: closedInc, color: "var(--sev-low)" },
    ];
    // ── Treemap: detections by type ──
    const treemap = Object.entries(d.breakdown).map(([k, v], i) => ({
      label: cap(k), value: num(v), color: PALETTE[i % PALETTE.length],
    }));
    // ── Scatter: per-site cameras vs detections (bubble = open incidents) ──
    const camBy: Record<string, number> = {}, detBy: Record<string, number> = {}, incBy: Record<string, number> = {};
    for (const c of d.cameras) camBy[String(c.site_id)] = (camBy[String(c.site_id)] ?? 0) + 1;
    for (const x of d.detections) if (x.site_id) detBy[String(x.site_id)] = (detBy[String(x.site_id)] ?? 0) + 1;
    for (const i of d.incidents) if (i.site_id) incBy[String(i.site_id)] = (incBy[String(i.site_id)] ?? 0) + 1;
    const scatter = d.sites.map((s, i) => ({
      x: camBy[String(s.id)] ?? 0, y: detBy[String(s.id)] ?? 0,
      r: 5 + Math.min(14, incBy[String(s.id)] ?? 0), label: String(s.name), color: PALETTE[i % PALETTE.length],
    }));
    // ── Severity / cyber bars ──
    const bySev: Record<string, number> = {};
    for (const x of d.detections) bySev[String(x.severity)] = (bySev[String(x.severity)] ?? 0) + 1;
    const cyberBars = Object.entries((d.soc.by_type as Dict) ?? {})
      .map(([k, v]) => ({ label: k, value: num(v) })).filter((e) => e.value > 0)
      .sort((a, b) => b.value - a.value).slice(0, 6);
    return {
      invoiced, collected, outstanding, arr, mrr, months, invoiceArea, funnel, treemap, scatter, bySev, cyberBars,
      health: num(d.enc?.encryption_health_score),
    };
  }, [d]);

  if (!d || !derived) return <p className="text-muted-foreground">Loading executive metrics…</p>;

  const activeThreats = num(d.threats.total);
  const openIncidents = num(d.kpis.open_incidents);
  const openCyber = num(d.kpis.open_cyber_events);
  const posture = activeThreats > 0 || openIncidents > 0 ? "critical" : openCyber > 0 ? "warning" : "ok";
  const incTrendData = d.incTrend.map((x) => num(x.count));
  const thrTrendData = d.thrTrend.map((x) => num(x.count));

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Executive Metrics Dashboard</h1>
        <p className="text-sm text-muted-foreground">Business &amp; security posture at a glance</p>
      </div>

      <StatusBanner tone={posture}>
        {posture === "ok"
          ? "All clear — no active threats or open incidents."
          : `${activeThreats} active threat(s), ${openIncidents} open incident(s), ${openCyber} open cyber event(s).`}
      </StatusBanner>

      {/* KPI card row — Power BI "cards" */}
      <div className="grid grid-cols-2 gap-3 md:grid-cols-3 lg:grid-cols-6">
        <KpiHero label="ARR" value={money(derived.arr)} icon={Banknote} accent="var(--sev-low)" sub={`${money(derived.mrr)}/mo`} />
        <KpiHero label="Collected" value={money(derived.collected)} icon={Wallet} accent="var(--signal)" />
        <KpiHero label="Outstanding" value={money(derived.outstanding)} icon={Wallet} accent="var(--sev-high)" />
        <KpiHero label="Sites" value={num(d.kpis.sites)} icon={Building2} accent="var(--iris)" />
        <KpiHero label="Cameras" value={`${num(d.kpis.cameras_online)}/${num(d.kpis.cameras)}`} icon={CameraIcon} accent="var(--signal)" />
        <KpiHero label="Encryption Health" value={`${derived.health}%`} icon={Activity}
          accent={derived.health >= 90 ? "var(--sev-low)" : "var(--sev-high)"} />
      </div>

      {/* Row — revenue area, treemap, threats donut-ish bars */}
      <div className="grid gap-4 lg:grid-cols-3">
        <Card>
          <CardHeader><CardTitle>Invoiced revenue · by month</CardTitle></CardHeader>
          <CardContent>
            {derived.invoiceArea.length > 1
              ? <AreaChart data={derived.invoiceArea} color="var(--sev-low)" height={180} />
              : <p className="py-12 text-center text-sm text-muted-foreground">{money(derived.invoiced)} invoiced · need ≥2 months for a trend.</p>}
          </CardContent>
        </Card>
        <Card>
          <CardHeader><CardTitle>Detections by type</CardTitle></CardHeader>
          <CardContent><Treemap items={derived.treemap} height={200} /></CardContent>
        </Card>
        <Card>
          <CardHeader><CardTitle>Active threats by risk</CardTitle></CardHeader>
          <CardContent>
            <VBars height={200} items={SEV_ORDER.map((s) => ({ label: s, value: num(d.threats[s]), color: SEV_COLOR[s] }))} />
          </CardContent>
        </Card>
      </div>

      {/* Row — funnel pipeline, scatter, activity */}
      <div className="grid gap-4 lg:grid-cols-3">
        <Card>
          <CardHeader><CardTitle>Threat → incident pipeline</CardTitle></CardHeader>
          <CardContent className="pt-2"><Funnel stages={derived.funnel} /></CardContent>
        </Card>
        <Card>
          <CardHeader><CardTitle>Site exposure · cameras vs detections</CardTitle></CardHeader>
          <CardContent><Scatter points={derived.scatter} height={200} xLabel="cameras →" yLabel="↑ detections" /></CardContent>
        </Card>
        <Card>
          <CardHeader><CardTitle>Activity · 30 days</CardTitle></CardHeader>
          <CardContent>
            <MultiLine height={180} series={[
              { label: "Threats", color: "var(--sev-critical)", data: thrTrendData },
              { label: "Incidents", color: "var(--iris)", data: incTrendData },
            ]} />
          </CardContent>
        </Card>
      </div>

      {/* Row — site map, cyber bars, detection severity */}
      <div className="grid gap-4 lg:grid-cols-3">
        <Card>
          <CardHeader><CardTitle>Sites health</CardTitle></CardHeader>
          <CardContent>
            {d.sites.length
              ? <HexHostmap nodes={d.sites.map((s): HexNode => ({
                  label: String(s.name), meta: String(s.site_type ?? ""),
                  status: s.status === "active" ? "ok" : s.status === "inactive" ? "crit" : "warn",
                }))} />
              : <p className="text-sm text-muted-foreground">No sites yet.</p>}
          </CardContent>
        </Card>
        <Card>
          <CardHeader><CardTitle>Cyber events by type</CardTitle></CardHeader>
          <CardContent>
            {derived.cyberBars.length ? <HBars items={derived.cyberBars} /> : <p className="text-sm text-muted-foreground">No cyber events.</p>}
          </CardContent>
        </Card>
        <Card>
          <CardHeader><CardTitle>Detections by severity</CardTitle></CardHeader>
          <CardContent>
            <VBars height={180} items={SEV_ORDER.map((s) => ({ label: s, value: derived.bySev[s] ?? 0, color: SEV_COLOR[s] }))} />
          </CardContent>
        </Card>
      </div>

      <div className="flex items-center gap-2 pt-1 text-xs text-muted-foreground">
        <ShieldAlert className="h-3.5 w-3.5" /> Executive view · unified business &amp; security metrics.
      </div>
    </div>
  );
}
