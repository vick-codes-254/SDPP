import {
  Activity, BadgeCheck, Crosshair, Eye, Flame, Radar, ShieldAlert, ShieldX,
} from "lucide-react";
import { useEffect, useMemo, useState, type ReactNode } from "react";
import { DonutChart, MultiLine, VBars } from "@/components/charts";
import { SeverityGlyph, StatCard } from "@/components/metrics";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { useAuth } from "@/context/AuthContext";
import { api } from "@/lib/api";

type Dict = Record<string, unknown>;
const num = (v: unknown) => (typeof v === "number" ? v : Number(v ?? 0));
const cap = (s: string) => s.replace(/_/g, " ");

const SEV_COLOR: Record<string, string> = {
  critical: "var(--sev-critical)", high: "var(--sev-high)", medium: "var(--sev-medium)",
  low: "var(--sev-low)", info: "var(--sev-info)",
};
const SEV_ORDER = ["critical", "high", "medium", "low", "info"] as const;
// Stable palette so each detection type keeps its colour across charts.
const TYPE_PALETTE = [
  "var(--iris)", "var(--signal)", "var(--sev-high)", "var(--sev-critical)",
  "var(--sev-medium)", "var(--sev-low)", "#a78bfa", "#22d3ee", "#f472b6", "#34d399",
];

function BigStat({ value, label, color }: { value: ReactNode; label: string; color?: string }) {
  return (
    <div className="shrink-0 text-right">
      <div className="kpi-hero text-3xl" style={color ? { color } : undefined}>{value}</div>
      <div className="label-micro mt-1">{label}</div>
    </div>
  );
}

/** CrowdScore-style ring gauge: a 0-100 risk index, higher = more exposure. */
function ThreatScoreCard({ score }: { score: number }) {
  const tone = score >= 70 ? "var(--sev-critical)" : score >= 40 ? "var(--sev-high)" : "var(--sev-low)";
  const grade = score >= 70 ? "Elevated" : score >= 40 ? "Guarded" : "Low";
  const R = 42, C = 2 * Math.PI * R, len = (score / 100) * C;
  return (
    <Card>
      <CardHeader className="flex-row items-center justify-between">
        <CardTitle>Threat Score</CardTitle>
        <Radar className="h-4 w-4 text-muted-foreground" />
      </CardHeader>
      <CardContent className="flex items-center gap-5">
        <div className="relative h-40 w-40 shrink-0">
          <svg viewBox="0 0 100 100" className="h-full w-full -rotate-90">
            <circle cx={50} cy={50} r={R} fill="none" stroke="hsl(var(--muted))" strokeWidth={11} opacity={0.4} />
            <circle cx={50} cy={50} r={R} fill="none" stroke={tone} strokeWidth={11}
              strokeLinecap="round" strokeDasharray={`${len} ${C - len}`} />
          </svg>
          <div className="absolute inset-0 flex flex-col items-center justify-center">
            <span className="kpi-hero text-3xl" style={{ color: tone }}>{score}</span>
            <span className="label-micro mt-0.5">/ 100</span>
          </div>
        </div>
        <div className="space-y-2 text-sm">
          <div className="flex items-center gap-2">
            <span className="h-2.5 w-2.5 rounded-full" style={{ background: tone }} />
            <span className="font-medium" style={{ color: tone }}>{grade} exposure</span>
          </div>
          <p className="text-xs text-muted-foreground">
            Composite of active threats weighted by risk level. Lower is safer.
          </p>
        </div>
      </CardContent>
    </Card>
  );
}

/** Most-recent detections — the EPP "Most recent detections" panel. */
function RecentDetectionsCard({ detections }: { detections: Dict[] }) {
  const rows = useMemo(
    () => [...detections]
      .sort((a, b) => String(b.detected_at ?? "").localeCompare(String(a.detected_at ?? "")))
      .slice(0, 7),
    [detections],
  );
  return (
    <Card>
      <CardHeader><CardTitle>Most recent detections</CardTitle></CardHeader>
      <CardContent className="p-0">
        <table className="data-table">
          <thead><tr><th>Severity</th><th>Type</th><th>Detected</th><th>Status</th></tr></thead>
          <tbody>
            {rows.map((r) => (
              <tr key={String(r.id)}>
                <td><SeverityGlyph severity={String(r.severity)} /></td>
                <td className="capitalize">{cap(String(r.detection_type))}</td>
                <td className="tabular-nums text-muted-foreground">
                  {String(r.detected_at ?? "").slice(0, 16).replace("T", " ")}
                </td>
                <td><Badge variant={r.status === "confirmed" ? "destructive" : r.status === "dismissed" ? "muted" : "warning"}>{String(r.status)}</Badge></td>
              </tr>
            ))}
            {rows.length === 0 && <tr><td colSpan={4} className="py-6 text-center text-muted-foreground">No detections yet</td></tr>}
          </tbody>
        </table>
      </CardContent>
    </Card>
  );
}

/** Active threats with escalate-to-incident — the EPP "Detections by name" list, but actionable. */
function ActiveThreatsCard({ threats, reload }: { threats: Dict[]; reload: () => void }) {
  const rows = useMemo(
    () => [...threats].sort((a, b) => num(b.score) - num(a.score)).slice(0, 8),
    [threats],
  );
  const escalate = async (id: string) => { await api.post(`/detections/threats/${id}/escalate`); reload(); };
  return (
    <Card>
      <CardHeader className="flex-row items-center justify-between">
        <CardTitle>Active threats</CardTitle>
        <span className="label-micro">{threats.length} total</span>
      </CardHeader>
      <CardContent className="p-0">
        <table className="data-table">
          <thead><tr><th>Threat</th><th>Risk</th><th>Score</th><th>Hits</th><th></th></tr></thead>
          <tbody>
            {rows.map((t) => (
              <tr key={String(t.id)}>
                <td className="max-w-[180px] truncate">{String(t.title)}</td>
                <td><SeverityGlyph severity={String(t.risk_level)} /></td>
                <td className="tabular-nums">{num(t.score)}</td>
                <td className="tabular-nums text-muted-foreground">{num(t.detection_count)}</td>
                <td className="text-right">
                  {t.status !== "escalated" ? (
                    <Button size="sm" variant="outline" onClick={() => escalate(String(t.id))}>Escalate</Button>
                  ) : <span className="text-xs text-muted-foreground">escalated</span>}
                </td>
              </tr>
            ))}
            {rows.length === 0 && <tr><td colSpan={5} className="py-6 text-center text-muted-foreground">No active threats</td></tr>}
          </tbody>
        </table>
      </CardContent>
    </Card>
  );
}

export function ThreatCenter() {
  const { user } = useAuth();
  const org = (user?.organization_id as string | undefined) ?? "";
  const [d, setD] = useState<{
    summary: Dict; detections: Dict[]; threats: Dict[]; breakdown: Dict; thrTrend: Dict[]; incTrend: Dict[];
  } | null>(null);
  const [tick, setTick] = useState(0);
  const reload = () => setTick((t) => t + 1);

  useEffect(() => {
    if (!org) return;
    const g = <T,>(p: string, fb: T) => api.get<T>(p).catch(() => fb);
    Promise.all([
      g<Dict>(`/detections/threats/summary?organization_id=${org}`, {}),
      g<Dict[]>(`/detections?organization_id=${org}`, []),
      g<Dict[]>(`/detections/threats/list?organization_id=${org}`, []),
      g<Dict>(`/analytics/detections?organization_id=${org}`, {}),
      g<Dict[]>(`/analytics/trends/threats?organization_id=${org}&days=14`, []),
      g<Dict[]>(`/analytics/trends/incidents?organization_id=${org}&days=14`, []),
    ]).then(([summary, detections, threats, breakdown, thrTrend, incTrend]) =>
      setD({ summary, detections, threats, breakdown, thrTrend, incTrend }));
  }, [org, tick]);

  if (!d) return <p className="text-muted-foreground">Loading threat center…</p>;

  // ── KPI counters from the detection feed ──────────────────────
  const byStatus: Record<string, number> = {};
  const bySev: Record<string, number> = {};
  for (const x of d.detections) {
    byStatus[String(x.status)] = (byStatus[String(x.status)] ?? 0) + 1;
    bySev[String(x.severity)] = (bySev[String(x.severity)] ?? 0) + 1;
  }

  // ── Threat-score composite (active threats weighted by risk) ──
  const sum = d.summary;
  const score = Math.min(100,
    num(sum.critical) * 20 + num(sum.high) * 8 + num(sum.medium) * 3 + num(sum.low));

  // ── Detection-type donut + ranked bars ────────────────────────
  const typeEntries = Object.entries(d.breakdown)
    .map(([k, v]) => ({ label: k, value: num(v) }))
    .filter((e) => e.value > 0).sort((a, b) => b.value - a.value);
  const typeSegments = typeEntries.slice(0, 8).map((e, i) => ({
    label: cap(e.label), value: e.value, color: TYPE_PALETTE[i % TYPE_PALETTE.length],
  }));
  const typeTotal = typeEntries.reduce((a, e) => a + e.value, 0);

  // ── Risk-level donut (active threats) ─────────────────────────
  const riskSegments = SEV_ORDER
    .map((s) => ({ label: s, value: num(sum[s]), color: SEV_COLOR[s] }))
    .filter((s) => s.value > 0);

  // ── Activity trend lines ──────────────────────────────────────
  const thrTrendData = d.thrTrend.map((x) => num(x.count));
  const incTrendData = d.incTrend.map((x) => num(x.count));

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Threat Center</h1>
        <p className="text-sm text-muted-foreground">
          Detections, correlated threats, and exposure across the estate
        </p>
      </div>

      {/* KPI strip — the EPP header counters */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
        <StatCard label="New Detections" value={byStatus.new ?? 0} icon={Radar} accent="var(--signal)" />
        <StatCard label="Active Threats" value={num(sum.total)} icon={ShieldAlert} accent="var(--sev-critical)" />
        <StatCard label="Critical" value={num(sum.critical)} icon={Flame} accent="var(--sev-critical)" />
        <StatCard label="Under Review" value={byStatus.reviewing ?? 0} icon={Eye} accent="var(--sev-high)" />
        <StatCard label="Confirmed" value={byStatus.confirmed ?? 0} icon={BadgeCheck} accent="var(--sev-medium)" />
        <StatCard label="Dismissed" value={byStatus.dismissed ?? 0} icon={ShieldX} accent="var(--sev-low)" />
      </div>

      {/* Row 2 — type donut · activity lines · recent detections */}
      <div className="grid gap-4 lg:grid-cols-3">
        <Card>
          <CardHeader><CardTitle>Detections by Type</CardTitle></CardHeader>
          <CardContent>
            {typeSegments.length
              ? <DonutChart segments={typeSegments} total={typeTotal} label="detections" />
              : <p className="text-sm text-muted-foreground">No detections yet.</p>}
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex-row items-center justify-between">
            <CardTitle>Activity · Detections</CardTitle>
            <Activity className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <MultiLine series={[
              { label: "Threats", color: "var(--sev-critical)", data: thrTrendData },
              { label: "Incidents", color: "var(--iris)", data: incTrendData },
            ]} />
          </CardContent>
        </Card>
        <RecentDetectionsCard detections={d.detections} />
      </div>

      {/* Row 3 — severity bars · risk donut · score gauge */}
      <div className="grid gap-4 lg:grid-cols-3">
        <Card>
          <CardHeader><CardTitle>Detections by Severity</CardTitle></CardHeader>
          <CardContent>
            <div className="flex items-end gap-4">
              <div className="flex-1">
                <VBars items={SEV_ORDER.map((s) => ({ label: s, value: bySev[s] ?? 0, color: SEV_COLOR[s] }))} />
              </div>
              <BigStat value={d.detections.length} label="Detections" />
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex-row items-center justify-between">
            <CardTitle>Threats by Risk</CardTitle>
            <Crosshair className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            {riskSegments.length
              ? <DonutChart segments={riskSegments} total={num(sum.total)} label="threats" />
              : <p className="text-sm text-muted-foreground">No active threats.</p>}
          </CardContent>
        </Card>
        <ThreatScoreCard score={score} />
      </div>

      {/* Row 4 — top types · active threats list */}
      <div className="grid gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-1">
          <CardHeader><CardTitle>Top Detection Types</CardTitle></CardHeader>
          <CardContent className="space-y-2">
            {typeEntries.slice(0, 6).map((e, i) => (
              <div key={e.label} className="flex items-center gap-3 text-sm">
                <span className="h-2.5 w-2.5 shrink-0 rounded-sm" style={{ background: TYPE_PALETTE[i % TYPE_PALETTE.length] }} />
                <span className="flex-1 truncate capitalize text-muted-foreground">{cap(e.label)}</span>
                <span className="tabular-nums">{e.value}</span>
              </div>
            ))}
            {typeEntries.length === 0 && <p className="text-sm text-muted-foreground">No detections yet.</p>}
          </CardContent>
        </Card>
        <div className="lg:col-span-2">
          <ActiveThreatsCard threats={d.threats} reload={reload} />
        </div>
      </div>

      <div className="flex items-center gap-2 pt-1 text-xs text-muted-foreground">
        <Activity className="h-3.5 w-3.5" /> Live threat metrics · derived from detections, correlated threats &amp; trends.
      </div>
    </div>
  );
}
