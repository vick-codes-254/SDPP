/** Hexagon hostmap — fleet/site/camera health at a glance.
 *  Inspired by Datadog's hexagonal hostmap and Grafana's hexbin status grid. */

export type HexStatus = "ok" | "warn" | "crit" | "idle";

const COLOR: Record<HexStatus, string> = {
  ok: "var(--sev-low)",
  warn: "var(--sev-high)",
  crit: "var(--sev-critical)",
  idle: "var(--muted-foreground)",
};

export interface HexNode {
  label: string;
  status: HexStatus;
  meta?: string;
}

export function HexHostmap({ nodes, legend = true }: { nodes: HexNode[]; legend?: boolean }) {
  return (
    <div>
      <div className="flex flex-wrap gap-1.5">
        {nodes.map((n, i) => (
          <div
            key={i}
            title={`${n.label}${n.meta ? ` — ${n.meta}` : ""} (${n.status})`}
            className="group relative h-10 w-[38px] cursor-pointer transition-transform hover:scale-110"
            style={{
              clipPath: "polygon(50% 0, 100% 25%, 100% 75%, 50% 100%, 0 75%, 0 25%)",
              background: `color-mix(in srgb, ${COLOR[n.status]} ${n.status === "idle" ? 22 : 80}%, transparent)`,
            }}
          >
            <span className="absolute inset-0 flex items-center justify-center text-[9px] font-semibold text-black/70">
              {n.label.slice(0, 3).toUpperCase()}
            </span>
          </div>
        ))}
        {nodes.length === 0 && <p className="text-sm text-muted-foreground">No nodes.</p>}
      </div>
      {legend && nodes.length > 0 && (
        <div className="mt-3 flex flex-wrap gap-3 text-xs text-muted-foreground">
          {(["ok", "warn", "crit", "idle"] as HexStatus[]).map((s) => (
            <span key={s} className="flex items-center gap-1.5">
              <span className="h-2.5 w-2.5 rounded-sm" style={{ background: COLOR[s] }} />
              {s === "ok" ? "Healthy" : s === "warn" ? "Degraded" : s === "crit" ? "Offline" : "Idle"}
            </span>
          ))}
        </div>
      )}
    </div>
  );
}
