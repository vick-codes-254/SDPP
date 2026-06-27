import { useEffect, useMemo, useState, type ReactNode } from "react";
import { AreaChart, Gauge, MultiLine, StackedArea, StackedBars } from "@/components/charts";
import { Sparkline } from "@/components/metrics";
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
const dayKey = (ts: unknown) => String(ts ?? "").slice(0, 10);

/** Bucket rows into per-day, per-severity series over the most recent days. */
function stackByDaySeverity(rows: Dict[], tsKey: string, days = 14) {
  const present = [...new Set(rows.map((r) => dayKey(r[tsKey])).filter(Boolean))].sort();
  const labels = present.slice(-days);
  const series = SEV_ORDER.map((sev) => ({
    label: sev,
    color: SEV_COLOR[sev],
    data: labels.map((d) => rows.filter((r) => dayKey(r[tsKey]) === d && String(r.severity) === sev).length),
  }));
  return { labels: labels.map((d) => d.slice(5)), series };
}

/** Grafana "stat" panel — big coloured numeral over a sparkline background. */
function GrafanaStat({ label, value, color, spark }: {
  label: string; value: ReactNode; color: string; spark: number[];
}) {
  return (
    <Card className="relative overflow-hidden">
      <CardHeader className="pb-1"><CardTitle className="text-xs font-normal text-muted-foreground">{label}</CardTitle></CardHeader>
      <CardContent className="pb-2">
        <div className="kpi-hero text-4xl" style={{ color }}>{value}</div>
      </CardContent>
      <div className="pointer-events-none absolute inset-x-0 bottom-0 opacity-70">
        <Sparkline data={spark.length ? spark : [0, 0]} color={color} width={300} height={34} />
      </div>
    </Card>
  );
}

export function AnalyticsBI() {
  const { user } = useAuth();
  const org = (user?.organization_id as string | undefined) ?? "";
  const [d, setD] = useState<{
    rt: Dict; up: Dict; breakdown: Dict; incTrend: Dict[]; thrTrend: Dict[];
    detections: Dict[]; incidents: Dict[];
  } | null>(null);

  useEffect(() => {
    if (!org) return;
    const g = <T,>(p: string, fb: T) => api.get<T>(p).catch(() => fb);
    Promise.all([
      g<Dict>(`/analytics/response-times?organization_id=${org}`, {}),
      g<Dict>(`/analytics/camera-uptime?organization_id=${org}`, {}),
      g<Dict>(`/analytics/detections?organization_id=${org}`, {}),
      g<Dict[]>(`/analytics/trends/incidents?organization_id=${org}&days=14`, []),
      g<Dict[]>(`/analytics/trends/threats?organization_id=${org}&days=14`, []),
      g<Dict[]>(`/detections?organization_id=${org}`, []),
      g<Dict[]>(`/incidents`, []),
    ]).then(([rt, up, breakdown, incTrend, thrTrend, detections, incidents]) =>
      setD({ rt, up, breakdown, incTrend, thrTrend, detections, incidents }));
  }, [org]);

  const detStack = useMemo(() => d ? stackByDaySeverity(d.detections, "detected_at") : null, [d]);
  const incStack = useMemo(() => d ? stackByDaySeverity(d.incidents, "created_at") : null, [d]);

  if (!d) return <p className="text-muted-foreground">Loading analytics…</p>;

  const incTrendData = d.incTrend.map((x) => num(x.count));
  const thrTrendData = d.thrTrend.map((x) => num(x.count));

  // Gauges
  const uptime = num(d.up.uptime_pct);
  const byStatus: Record<string, number> = {};
  for (const x of d.detections) byStatus[String(x.status)] = (byStatus[String(x.status)] ?? 0) + 1;
  const total = d.detections.length || 1;
  const triaged = (byStatus.reviewing ?? 0) + (byStatus.confirmed ?? 0) + (byStatus.dismissed ?? 0);
  const reviewRate = Math.round((triaged / total) * 100);

  // Top detection types (Grafana "Google hits A–E")
  const topTypes = Object.entries(d.breakdown)
    .map(([k, v]) => ({ label: cap(k), value: num(v) }))
    .filter((e) => e.value > 0).sort((a, b) => b.value - a.value).slice(0, 5);

  const openInc = d.incidents.filter((i) => !["resolved", "closed"].includes(String(i.status))).length;

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Analytics &amp; BI</h1>
        <p className="text-sm text-muted-foreground">Operational telemetry across detections, incidents &amp; estate health</p>
      </div>

      {/* Row 1 — two time-series, a 2×2 gauge/stat block */}
      <div className="grid gap-4 lg:grid-cols-4">
        <Card className="lg:col-span-2">
          <CardHeader><CardTitle>Incidents &amp; Threats · 14 days</CardTitle></CardHeader>
          <CardContent>
            <MultiLine height={160} series={[
              { label: "Threats", color: "var(--sev-critical)", data: thrTrendData },
              { label: "Incidents", color: "var(--iris)", data: incTrendData },
            ]} />
          </CardContent>
        </Card>
        <Card>
          <CardHeader><CardTitle>Detections · 14 days</CardTitle></CardHeader>
          <CardContent>
            <AreaChart data={detStack?.series.reduce<number[]>((acc, s) =>
              s.data.map((v, i) => (acc[i] ?? 0) + v), [])
              ?? []} color="var(--iris)" height={160} />
          </CardContent>
        </Card>
        <div className="grid grid-cols-2 gap-4">
          <Card><CardHeader className="pb-0"><CardTitle className="text-xs font-normal text-muted-foreground">Camera Uptime</CardTitle></CardHeader>
            <CardContent className="pt-1"><Gauge value={uptime} unit="%" /></CardContent></Card>
          <Card><CardHeader className="pb-0"><CardTitle className="text-xs font-normal text-muted-foreground">Triage Rate</CardTitle></CardHeader>
            <CardContent className="pt-1"><Gauge value={reviewRate} unit="%" /></CardContent></Card>
          <GrafanaStat label="Open Incidents" value={openInc} color="var(--sev-high)" spark={incTrendData} />
          <GrafanaStat label="Active Threats" value={thrTrendData.reduce((a, b) => a + b, 0)} color="var(--sev-low)" spark={thrTrendData} />
        </div>
      </div>

      {/* Row 2 — stacked-area detections + top-type "stat bars" */}
      <div className="grid gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader><CardTitle>Detections over time · by severity</CardTitle></CardHeader>
          <CardContent>
            {detStack && detStack.labels.length > 1
              ? <StackedArea series={detStack.series} height={240} />
              : <p className="py-12 text-center text-sm text-muted-foreground">Not enough history yet.</p>}
          </CardContent>
        </Card>
        <Card>
          <CardHeader><CardTitle>Top Detection Types</CardTitle></CardHeader>
          <CardContent>
            <div className="flex h-[240px] items-end gap-2">
              {topTypes.length ? topTypes.map((t) => {
                const max = Math.max(...topTypes.map((x) => x.value), 1);
                return (
                  <div key={t.label} className="flex flex-1 flex-col items-center justify-end gap-2">
                    <span className="kpi-hero text-xl" style={{ color: "var(--sev-low)" }}>{t.value}</span>
                    <div className="w-full rounded-t" style={{ height: `${(t.value / max) * 170}px`, minHeight: 4, background: "color-mix(in srgb, var(--sev-low) 55%, transparent)" }} />
                    <span className="w-full truncate text-center text-[10px] capitalize text-muted-foreground">{t.label}</span>
                  </div>
                );
              }) : <p className="text-sm text-muted-foreground">No detections yet.</p>}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Row 3 — full-width stacked bars (incidents by severity / day) */}
      <Card>
        <CardHeader><CardTitle>Incidents by severity · per day</CardTitle></CardHeader>
        <CardContent>
          {incStack && incStack.labels.length
            ? <StackedBars labels={incStack.labels} series={incStack.series} height={220} />
            : <p className="py-12 text-center text-sm text-muted-foreground">No incident history yet.</p>}
        </CardContent>
      </Card>
    </div>
  );
}
