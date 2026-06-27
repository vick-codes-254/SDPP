import { Check, ChevronDown, RefreshCw, Search, X } from "lucide-react";
import {
  useEffect, useMemo, useRef, useState, type ComponentType, type ReactNode,
} from "react";
import { SeverityGlyph } from "@/components/metrics";
import { useAuth } from "@/context/AuthContext";
import { api } from "@/lib/api";
import { cn } from "@/lib/utils";

export type TRow = Record<string, unknown>;

export interface TriageColumn {
  key: string;
  label: string;
  render?: (row: TRow) => ReactNode;
  /** Returns a CSS color to subtly tint this cell (CrowdStrike attribute cells). */
  tint?: (row: TRow) => string | undefined;
  mono?: boolean;
  width?: string;
}

export interface TriageFilter {
  key: string;
  label: string;
  options: { value: string; label: string }[];
}

export interface TriageConfig {
  title: string;
  icon?: ComponentType<{ className?: string }>;
  description?: string;
  /** Build the GET path for the row list. */
  list: (orgId: string) => string;
  columns: TriageColumn[];
  filters?: TriageFilter[];
  searchKeys?: string[];
  headerActions?: (reload: () => void) => ReactNode;
  renderDrawer?: (row: TRow, reload: () => void, close: () => void) => ReactNode;
}

/** Multi-select filter chip with popover checklist (CrowdStrike filter bar). */
function FilterChip({ filter, selected, onToggle, onClear }: {
  filter: TriageFilter; selected: Set<string>;
  onToggle: (v: string) => void; onClear: () => void;
}) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const h = (e: MouseEvent) => { if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false); };
    document.addEventListener("mousedown", h);
    return () => document.removeEventListener("mousedown", h);
  }, []);
  const count = selected.size;
  return (
    <div className="relative" ref={ref}>
      <button
        onClick={() => setOpen((o) => !o)}
        className={cn(
          "flex h-8 items-center gap-1.5 rounded-md border px-2.5 text-xs font-medium transition-colors",
          count ? "border-primary/50 bg-primary/10 text-primary" : "border-border text-muted-foreground hover:bg-accent hover:text-foreground",
        )}
      >
        {filter.label}{count > 0 && <span className="rounded bg-primary/20 px-1">{count}</span>}
        <ChevronDown className="h-3 w-3" />
      </button>
      {open && (
        <div className="glass animate-pop-in absolute left-0 top-9 z-30 max-h-64 w-52 overflow-y-auto rounded-lg p-1">
          {count > 0 && (
            <button onClick={onClear} className="flex w-full items-center gap-2 rounded px-2 py-1.5 text-xs text-muted-foreground hover:bg-accent">
              <X className="h-3 w-3" /> Clear
            </button>
          )}
          {filter.options.map((o) => {
            const on = selected.has(o.value);
            return (
              <button key={o.value} onClick={() => onToggle(o.value)}
                className="flex w-full items-center gap-2 rounded px-2 py-1.5 text-left text-xs hover:bg-accent">
                <span className={cn("flex h-4 w-4 items-center justify-center rounded border", on ? "border-primary bg-primary text-primary-foreground" : "border-border")}>
                  {on && <Check className="h-3 w-3" />}
                </span>
                <span className="capitalize">{o.label}</span>
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}

export function TriageTable(cfg: TriageConfig) {
  const { user } = useAuth();
  const orgId = (user?.organization_id as string | undefined) ?? "";
  const [rows, setRows] = useState<TRow[]>([]);
  const [sel, setSel] = useState<Record<string, Set<string>>>({});
  const [q, setQ] = useState("");
  const [checked, setChecked] = useState<Set<string>>(new Set());
  const [drawer, setDrawer] = useState<TRow | null>(null);
  const [loading, setLoading] = useState(false);

  const reload = () => {
    setLoading(true);
    api.get<TRow[]>(cfg.list(orgId)).then(setRows).catch(() => setRows([])).finally(() => setLoading(false));
  };
  useEffect(reload, [cfg.title, orgId]);

  const filtered = useMemo(() => {
    const t = q.trim().toLowerCase();
    return rows.filter((r) => {
      for (const [k, set] of Object.entries(sel)) {
        if (set.size && !set.has(String(r[k]))) return false;
      }
      if (t) {
        const keys = cfg.searchKeys ?? cfg.columns.map((c) => c.key);
        if (!keys.some((k) => String(r[k] ?? "").toLowerCase().includes(t))) return false;
      }
      return true;
    });
  }, [rows, sel, q, cfg]);

  const toggleFilter = (fk: string, v: string) =>
    setSel((s) => {
      const next = new Set(s[fk] ?? []);
      next.has(v) ? next.delete(v) : next.add(v);
      return { ...s, [fk]: next };
    });

  const Icon = cfg.icon;
  const allChecked = filtered.length > 0 && filtered.every((r) => checked.has(String(r.id)));

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="flex items-center gap-2 text-2xl font-semibold tracking-tight">
            {Icon && <Icon className="h-6 w-6 text-primary" />} {cfg.title}
          </h1>
          {cfg.description && <p className="mt-1 text-sm text-muted-foreground">{cfg.description}</p>}
        </div>
        <div className="flex items-center gap-2">{cfg.headerActions?.(reload)}</div>
      </div>

      {/* Result count + filter chip bar (CrowdStrike) */}
      <div className="text-sm text-muted-foreground">
        <span className="font-medium text-foreground">{filtered.length}</span> results
        <span className="text-muted-foreground"> ({rows.length} total)</span>
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <div className="flex h-8 items-center gap-1.5 rounded-md border border-border bg-background/60 px-2.5">
          <Search className="h-3.5 w-3.5 text-muted-foreground" />
          <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search…"
            className="h-full w-44 bg-transparent text-xs outline-none placeholder:text-muted-foreground" />
        </div>
        {cfg.filters?.map((f) => (
          <FilterChip key={f.key} filter={f} selected={sel[f.key] ?? new Set()}
            onToggle={(v) => toggleFilter(f.key, v)}
            onClear={() => setSel((s) => ({ ...s, [f.key]: new Set() }))} />
        ))}
        <button onClick={reload} className="ml-auto flex h-8 items-center gap-1.5 rounded-md border border-border px-2.5 text-xs text-muted-foreground hover:bg-accent hover:text-foreground">
          <RefreshCw className={cn("h-3.5 w-3.5", loading && "animate-spin")} /> Refresh
        </button>
      </div>

      {/* Dense table */}
      <div className="overflow-hidden rounded-lg border border-border">
        <table className="w-full text-sm">
          <thead className="sticky top-0 z-10 bg-card">
            <tr className="border-b border-border text-left">
              <th className="w-10 px-3 py-2">
                <input type="checkbox" checked={allChecked}
                  onChange={(e) => setChecked(e.target.checked ? new Set(filtered.map((r) => String(r.id))) : new Set())} />
              </th>
              {cfg.columns.map((c) => (
                <th key={c.key} className="label-micro px-3 py-2" style={{ width: c.width }}>{c.label}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {filtered.map((row) => {
              const id = String(row.id);
              return (
                <tr key={id}
                  onClick={() => setDrawer(row)}
                  className={cn("cursor-pointer border-b border-border/50 transition-colors hover:bg-accent/60",
                    drawer && String(drawer.id) === id && "bg-primary/10")}>
                  <td className="px-3 py-1.5" onClick={(e) => e.stopPropagation()}>
                    <input type="checkbox" checked={checked.has(id)}
                      onChange={() => setChecked((s) => { const n = new Set(s); n.has(id) ? n.delete(id) : n.add(id); return n; })} />
                  </td>
                  {cfg.columns.map((c) => {
                    const tint = c.tint?.(row);
                    return (
                      <td key={c.key}
                        className={cn("px-3 py-1.5 align-middle", c.mono && "mono text-xs")}
                        style={tint ? { background: `color-mix(in srgb, ${tint} 12%, transparent)`, boxShadow: `inset 2px 0 0 ${tint}` } : undefined}>
                        {c.render ? c.render(row) : String(row[c.key] ?? "—")}
                      </td>
                    );
                  })}
                </tr>
              );
            })}
            {filtered.length === 0 && (
              <tr><td colSpan={cfg.columns.length + 1} className="px-3 py-10 text-center text-muted-foreground">
                {loading ? "Loading…" : "No results"}
              </td></tr>
            )}
          </tbody>
        </table>
      </div>

      {/* Right Context Drawer / investigate flyout (CrowdStrike) */}
      {drawer && cfg.renderDrawer && (
        <div className="fixed inset-0 z-50 flex justify-end" onMouseDown={() => setDrawer(null)}>
          <div className="absolute inset-0 bg-black/40" />
          <aside className="animate-pop-in relative h-full w-full max-w-md overflow-y-auto border-l border-border bg-popover shadow-e3"
            onMouseDown={(e) => e.stopPropagation()}>
            <div className="sticky top-0 z-10 flex items-center justify-between border-b border-border bg-popover px-4 py-3">
              <span className="text-sm font-semibold">Details</span>
              <button onClick={() => setDrawer(null)} className="rounded p-1 text-muted-foreground hover:bg-accent">
                <X className="h-4 w-4" />
              </button>
            </div>
            <div className="p-4">{cfg.renderDrawer(drawer, reload, () => setDrawer(null))}</div>
          </aside>
        </div>
      )}
    </div>
  );
}

/** Convenience severity cell using the hexagon glyph. */
export function sevCell(key = "severity") {
  return (row: TRow) => <SeverityGlyph severity={String(row[key] ?? "info")} />;
}
