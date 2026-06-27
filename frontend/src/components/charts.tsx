import { useId } from "react";

/** Lightweight, dependency-free SVG charts for the SentinelIQ dashboards. */

export function AreaChart({ data, color = "var(--iris)", height = 120 }: {
  data: number[]; color?: string; height?: number;
}) {
  const id = useId();
  if (!data.length) return <Empty height={height} />;
  const w = 320;
  const max = Math.max(...data, 1);
  const min = Math.min(...data, 0);
  const span = max - min || 1;
  const step = w / Math.max(1, data.length - 1);
  const pts = data.map((v, i) => [i * step, height - ((v - min) / span) * (height - 10) - 5] as const);
  const line = pts.map((p) => p.join(",")).join(" ");
  const area = `0,${height} ${line} ${w},${height}`;
  return (
    <svg viewBox={`0 0 ${w} ${height}`} preserveAspectRatio="none" className="w-full" style={{ height }}>
      <defs>
        <linearGradient id={id} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity="0.35" />
          <stop offset="100%" stopColor={color} stopOpacity="0" />
        </linearGradient>
      </defs>
      <polygon points={area} fill={`url(#${id})`} />
      <polyline points={line} fill="none" stroke={color} strokeWidth={2} vectorEffect="non-scaling-stroke" />
    </svg>
  );
}

export function MultiLine({ series, height = 140 }: {
  series: { label: string; color: string; data: number[] }[]; height?: number;
}) {
  const w = 320;
  const all = series.flatMap((s) => s.data);
  if (!all.length) return <Empty height={height} />;
  const max = Math.max(...all, 1);
  const len = Math.max(...series.map((s) => s.data.length), 1);
  const step = w / Math.max(1, len - 1);
  return (
    <div>
      <svg viewBox={`0 0 ${w} ${height}`} preserveAspectRatio="none" className="w-full" style={{ height }}>
        {series.map((s, si) => (
          <polyline key={si}
            points={s.data.map((v, i) => `${i * step},${height - (v / max) * (height - 10) - 5}`).join(" ")}
            fill="none" stroke={s.color} strokeWidth={1.5} vectorEffect="non-scaling-stroke" />
        ))}
      </svg>
      <div className="mt-2 flex flex-wrap gap-3 text-xs text-muted-foreground">
        {series.map((s, i) => (
          <span key={i} className="flex items-center gap-1.5">
            <span className="h-2 w-2 rounded-full" style={{ background: s.color }} /> {s.label}
          </span>
        ))}
      </div>
    </div>
  );
}

export function DonutChart({ segments, total, label }: {
  segments: { label: string; value: number; color: string }[]; total: number | string; label: string;
}) {
  const sum = segments.reduce((a, s) => a + s.value, 0) || 1;
  const R = 42, C = 2 * Math.PI * R;
  let offset = 0;
  return (
    <div className="flex items-center gap-5">
      <div className="relative h-40 w-40 shrink-0">
        <svg viewBox="0 0 100 100" className="h-full w-full -rotate-90">
          <circle cx={50} cy={50} r={R} fill="none" stroke="hsl(var(--muted))" strokeWidth={11} opacity={0.4} />
          {segments.map((s, i) => {
            const len = (s.value / sum) * C;
            const el = (
              <circle key={i} cx={50} cy={50} r={R} fill="none" stroke={s.color} strokeWidth={11}
                strokeDasharray={`${len} ${C - len}`} strokeDashoffset={-offset} />
            );
            offset += len;
            return el;
          })}
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="kpi-hero text-3xl">{total}</span>
          <span className="label-micro mt-0.5">{label}</span>
        </div>
      </div>
      <div className="space-y-1.5 text-sm">
        {segments.map((s, i) => (
          <div key={i} className="flex items-center gap-2">
            <span className="h-2.5 w-2.5 rounded-sm" style={{ background: s.color }} />
            <span className="capitalize text-muted-foreground">{s.label}</span>
            <span className="ml-auto tabular-nums">{s.value}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

export function HBars({ items }: { items: { label: string; value: number; color?: string }[] }) {
  const max = Math.max(...items.map((i) => i.value), 1);
  if (!items.length) return <p className="text-sm text-muted-foreground">No data.</p>;
  return (
    <div className="space-y-2">
      {items.map((it, i) => (
        <div key={i} className="flex items-center gap-3 text-sm">
          <span className="w-28 shrink-0 truncate capitalize text-muted-foreground">{it.label.replace(/_/g, " ")}</span>
          <div className="h-2.5 flex-1 rounded bg-muted/40">
            <div className="h-2.5 rounded" style={{ width: `${(it.value / max) * 100}%`, background: it.color ?? "var(--iris)" }} />
          </div>
          <span className="w-10 text-right tabular-nums">{it.value}</span>
        </div>
      ))}
    </div>
  );
}

export function VBars({ items, height = 150 }: {
  items: { label: string; value: number; color?: string }[]; height?: number;
}) {
  const max = Math.max(...items.map((i) => i.value), 1);
  if (!items.length) return <p className="text-sm text-muted-foreground">No data.</p>;
  return (
    <div className="flex items-end gap-2" style={{ height }}>
      {items.map((it, i) => (
        <div key={i} className="flex flex-1 flex-col items-center justify-end gap-1.5" title={`${it.label}: ${it.value}`}>
          <span className="text-xs tabular-nums text-muted-foreground">{it.value}</span>
          <div className="w-full rounded-t"
            style={{ height: `${(it.value / max) * (height - 36)}px`, minHeight: 2, background: it.color ?? "var(--iris)" }} />
          <span className="w-full truncate text-center text-[10px] capitalize text-muted-foreground">{it.label.replace(/_/g, " ")}</span>
        </div>
      ))}
    </div>
  );
}

// ── Grafana-style primitives ───────────────────────────────────

/** Polar point with 0° at top, growing clockwise. */
function gaugePt(cx: number, cy: number, r: number, deg: number) {
  const rad = (deg * Math.PI) / 180;
  return { x: cx + r * Math.sin(rad), y: cy - r * Math.cos(rad) };
}
function gaugeArc(cx: number, cy: number, r: number, startDeg: number, endDeg: number) {
  const s = gaugePt(cx, cy, r, startDeg), e = gaugePt(cx, cy, r, endDeg);
  const large = (endDeg - startDeg) % 360 > 180 ? 1 : 0;
  return `M ${s.x} ${s.y} A ${r} ${r} 0 ${large} 1 ${e.x} ${e.y}`;
}

/** Grafana radial gauge — 270° sweep, threshold-coloured value arc. */
export function Gauge({ value, max = 100, label, unit = "", color }: {
  value: number; max?: number; label?: string; unit?: string; color?: string;
}) {
  const frac = Math.max(0, Math.min(1, max ? value / max : 0));
  const START = 225, SWEEP = 270;
  const arcColor = color ?? (frac >= 0.66 ? "var(--sev-low)" : frac >= 0.33 ? "var(--sev-high)" : "var(--sev-critical)");
  return (
    <div className="flex flex-col items-center">
      <svg viewBox="0 0 120 110" className="w-full" style={{ maxHeight: 150 }}>
        <path d={gaugeArc(60, 60, 46, START, START + SWEEP)} fill="none"
          stroke="hsl(var(--muted))" strokeWidth={10} strokeLinecap="round" opacity={0.4} />
        {frac > 0 && (
          <path d={gaugeArc(60, 60, 46, START, START + SWEEP * frac)} fill="none"
            stroke={arcColor} strokeWidth={10} strokeLinecap="round" />
        )}
        <text x={60} y={62} textAnchor="middle" className="kpi-hero"
          style={{ fontSize: 22, fill: arcColor }}>{value}{unit}</text>
      </svg>
      {label && <span className="label-micro -mt-1">{label}</span>}
    </div>
  );
}

/** Stacked area time-series (Grafana "server requests"). */
export function StackedArea({ series, height = 220 }: {
  series: { label: string; color: string; data: number[] }[]; height?: number;
}) {
  const w = 640;
  const len = Math.max(...series.map((s) => s.data.length), 1);
  if (len <= 1) return <Empty height={height} />;
  const totals = Array.from({ length: len }, (_, i) => series.reduce((a, s) => a + (s.data[i] ?? 0), 0));
  const max = Math.max(...totals, 1);
  const step = w / (len - 1);
  const y = (v: number) => height - (v / max) * (height - 8) - 4;
  let baseline = new Array(len).fill(0);
  const polys = series.map((s) => {
    const top = baseline.map((b, i) => b + (s.data[i] ?? 0));
    const topPts = top.map((v, i) => `${i * step},${y(v)}`);
    const botPts = [...baseline].map((v, i) => `${i * step},${y(v)}`).reverse();
    const poly = `${topPts.join(" ")} ${botPts.join(" ")}`;
    baseline = top;
    return { poly, color: s.color, top: top.map((v, i) => `${i * step},${y(v)}`).join(" ") };
  });
  return (
    <div>
      <svg viewBox={`0 0 ${w} ${height}`} preserveAspectRatio="none" className="w-full" style={{ height }}>
        {polys.map((p, i) => (
          <g key={i}>
            <polygon points={p.poly} fill={p.color} fillOpacity={0.55} />
            <polyline points={p.top} fill="none" stroke={p.color} strokeWidth={1.5} vectorEffect="non-scaling-stroke" />
          </g>
        ))}
      </svg>
      <Legend series={series} />
    </div>
  );
}

/** Stacked vertical bars over time (Grafana "client side full page load"). */
export function StackedBars({ labels, series, height = 220 }: {
  labels: string[]; series: { label: string; color: string; data: number[] }[]; height?: number;
}) {
  const totals = labels.map((_, i) => series.reduce((a, s) => a + (s.data[i] ?? 0), 0));
  const max = Math.max(...totals, 1);
  if (!labels.length) return <Empty height={height} />;
  return (
    <div>
      <div className="flex items-end gap-1.5" style={{ height }}>
        {labels.map((lbl, i) => (
          <div key={i} className="flex flex-1 flex-col-reverse items-stretch" title={`${lbl}: ${totals[i]}`}>
            {series.map((s, si) => {
              const v = s.data[i] ?? 0;
              if (v <= 0) return null;
              return <div key={si} style={{ height: `${(v / max) * (height - 18)}px`, background: s.color, opacity: 0.9 }} />;
            })}
            <span className="mt-1 truncate text-center text-[10px] text-muted-foreground">{lbl}</span>
          </div>
        ))}
      </div>
      <Legend series={series} />
    </div>
  );
}

function Legend({ series }: { series: { label: string; color: string }[] }) {
  return (
    <div className="mt-2 flex flex-wrap gap-3 text-xs text-muted-foreground">
      {series.map((s, i) => (
        <span key={i} className="flex items-center gap-1.5">
          <span className="h-2 w-2 rounded-sm" style={{ background: s.color }} /> {s.label}
        </span>
      ))}
    </div>
  );
}

function Empty({ height }: { height: number }) {
  return (
    <div className="flex items-center justify-center text-xs text-muted-foreground" style={{ height }}>
      No data yet
    </div>
  );
}
