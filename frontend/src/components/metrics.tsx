import type { CSSProperties, ComponentType, ReactNode } from "react";
import { cn } from "@/lib/utils";

type IconType = ComponentType<{ className?: string; style?: CSSProperties }>;

/** Severity hexagon glyph — color + shape + (optional) label, so severity is
 *  never encoded by color alone (CrowdStrike hexagon + Defender accessibility). */
export type Severity = "critical" | "high" | "medium" | "low" | "info" | string;

const SEV_VAR: Record<string, string> = {
  critical: "var(--sev-critical)",
  high: "var(--sev-high)",
  medium: "var(--sev-medium)",
  low: "var(--sev-low)",
  info: "var(--sev-info)",
};

export function SeverityGlyph({ severity, label = true, size = 14 }: {
  severity: Severity; label?: boolean; size?: number;
}) {
  const color = SEV_VAR[String(severity).toLowerCase()] ?? "var(--sev-info)";
  return (
    <span className="inline-flex items-center gap-1.5 whitespace-nowrap">
      <svg width={size} height={size} viewBox="0 0 24 24" aria-hidden>
        <path
          d="M12 2l8.66 5v10L12 22l-8.66-5V7z"
          fill={color}
          fillOpacity={0.22}
          stroke={color}
          strokeWidth={2}
        />
      </svg>
      {label && (
        <span className="text-xs font-medium capitalize" style={{ color }}>
          {severity}
        </span>
      )}
    </span>
  );
}

/** Tiny inline sparkline (TradingView/Grafana stat background). */
export function Sparkline({ data, color = "var(--iris)", width = 96, height = 28 }: {
  data: number[]; color?: string; width?: number; height?: number;
}) {
  if (!data.length) return null;
  const max = Math.max(...data), min = Math.min(...data);
  const span = max - min || 1;
  const step = width / Math.max(1, data.length - 1);
  const pts = data.map((v, i) => `${i * step},${height - ((v - min) / span) * (height - 4) - 2}`);
  return (
    <svg width={width} height={height} className="overflow-visible" aria-hidden>
      <polyline points={pts.join(" ")} fill="none" stroke={color} strokeWidth={1.5}
        strokeLinejoin="round" strokeLinecap="round" />
    </svg>
  );
}

export function DeltaPill({ value, invert = false }: { value: number; invert?: boolean }) {
  if (value === 0) return <span className="text-[11px] text-muted-foreground">0%</span>;
  const up = value > 0;
  // For most ops metrics "up" = worse (red); invert for metrics where up is good.
  const bad = invert ? !up : up;
  return (
    <span
      className="inline-flex items-center gap-0.5 text-[11px] font-semibold tabular-nums"
      style={{ color: bad ? "var(--sev-critical)" : "var(--sev-low)" }}
    >
      <span style={{ fontSize: 8, lineHeight: 1 }}>{up ? "▲" : "▼"}</span>
      {Math.abs(value)}%
    </span>
  );
}

/** Premium KPI card: micro label, thin hero numeral, delta pill, sparkline bg.
 *  (CrowdStrike numerals + Grafana stat sparkline + Sentinel/Splunk deltas). */
export function StatCard({ label, value, delta, deltaInvert, accent = "var(--iris)", spark, icon: Icon, hint }: {
  label: string;
  value: ReactNode;
  delta?: number;
  deltaInvert?: boolean;
  accent?: string;
  spark?: number[];
  icon?: IconType;
  hint?: string;
}) {
  return (
    <div className="relative overflow-hidden rounded-lg border border-border bg-card p-4 shadow-e1">
      <div className="flex items-center justify-between">
        <span className="label-micro">{label}</span>
        {Icon && <Icon className="h-4 w-4" style={{ color: accent }} />}
      </div>
      <div className="mt-2 flex items-end justify-between gap-2">
        <div className="kpi-hero text-3xl text-foreground">{value}</div>
        {delta !== undefined && <DeltaPill value={delta} invert={deltaInvert} />}
      </div>
      {hint && <div className="mt-1 text-xs text-muted-foreground">{hint}</div>}
      {spark && (
        <div className="mt-3 -mb-1">
          <Sparkline data={spark} color={accent} width={220} height={28} />
        </div>
      )}
      <div className="pointer-events-none absolute inset-x-0 bottom-0 h-0.5" style={{ background: accent, opacity: 0.5 }} />
    </div>
  );
}

/** Splunk-style Key Indicators strip — a row of compact KPIs with deltas. */
export function KeyIndicator({ label, value, delta, tone = "default" }: {
  label: string; value: ReactNode; delta?: number; tone?: "default" | "critical" | "warning" | "ok";
}) {
  const toneColor =
    tone === "critical" ? "var(--sev-critical)" :
    tone === "warning" ? "var(--sev-high)" :
    tone === "ok" ? "var(--sev-low)" : "var(--iris)";
  return (
    <div className="flex min-w-[120px] flex-1 flex-col gap-1 rounded-lg border border-border bg-card px-3 py-2.5">
      <span className="label-micro truncate">{label}</span>
      <div className="flex items-baseline gap-2">
        <span className="kpi-hero text-2xl" style={{ color: toneColor }}>{value}</span>
        {delta !== undefined && <DeltaPill value={delta} />}
      </div>
    </div>
  );
}

export function KeyIndicatorStrip({ children }: { children: ReactNode }) {
  return <div className="flex flex-wrap gap-3">{children}</div>;
}

/** Status banner (Datadog APM "OK: 7 monitors"). */
export function StatusBanner({ tone, children }: {
  tone: "ok" | "warning" | "critical"; children: ReactNode;
}) {
  const color =
    tone === "critical" ? "var(--sev-critical)" :
    tone === "warning" ? "var(--sev-high)" : "var(--sev-low)";
  return (
    <div
      className={cn("flex items-center gap-2 rounded-md border px-3 py-2 text-sm font-medium")}
      style={{
        color,
        borderColor: `color-mix(in srgb, ${color} 40%, transparent)`,
        background: `color-mix(in srgb, ${color} 12%, transparent)`,
      }}
    >
      <span className="h-2 w-2 rounded-full" style={{ background: color }} />
      {children}
    </div>
  );
}
