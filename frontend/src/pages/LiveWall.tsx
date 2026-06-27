import { ChevronRight, LayoutGrid, Maximize2, Search, Video, VideoOff } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { useAuth } from "@/context/AuthContext";
import { api } from "@/lib/api";
import { cn } from "@/lib/utils";

type Dict = Record<string, unknown>;
const num = (v: unknown) => (typeof v === "number" ? v : Number(v ?? 0));

/** Deterministic gradient per camera so the wall reads like distinct feeds. */
function feedBg(id: string) {
  let h = 0;
  for (const ch of id) h = (h * 31 + ch.charCodeAt(0)) % 360;
  return `linear-gradient(135deg, hsl(${h} 24% 30%), hsl(${(h + 38) % 360} 30% 15%))`;
}

const DENSITY: Record<string, string> = {
  comfortable: "grid-cols-1 sm:grid-cols-2 lg:grid-cols-3",
  standard: "grid-cols-2 sm:grid-cols-3 lg:grid-cols-4",
  dense: "grid-cols-2 sm:grid-cols-4 lg:grid-cols-5",
};

function CamTile({ cam }: { cam: Dict }) {
  const id = String(cam.id);
  const online = cam.status === "online";
  const recording = Boolean(cam.is_recording);
  return (
    <div className="group relative aspect-video cursor-pointer overflow-hidden rounded-lg border border-border bg-black transition-transform hover:z-10 hover:scale-[1.015] hover:shadow-e2">
      {online ? (
        <div className="absolute inset-0" style={{ background: feedBg(id) }}>
          <div className="absolute inset-0 flex items-center justify-center">
            <Video className="h-8 w-8 text-white/15" />
          </div>
          {/* subtle scanlines for a "feed" texture */}
          <div className="absolute inset-0 opacity-[0.06]"
            style={{ backgroundImage: "repeating-linear-gradient(0deg, #fff 0 1px, transparent 1px 3px)" }} />
        </div>
      ) : (
        <div className="absolute inset-0 flex flex-col items-center justify-center gap-1 bg-zinc-900 text-zinc-500">
          <VideoOff className="h-7 w-7" />
          <span className="text-[10px] uppercase tracking-wide">Signal lost</span>
        </div>
      )}

      {recording && (
        <span className="absolute right-2 top-2 flex items-center gap-1 rounded bg-black/55 px-1.5 py-0.5 text-[10px] font-semibold text-red-400 backdrop-blur-sm">
          <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-red-500" /> REC
        </span>
      )}

      {/* Verkada-style name bar */}
      <div className="absolute inset-x-0 bottom-0 flex items-center gap-1.5 bg-gradient-to-t from-black/80 via-black/40 to-transparent px-2 py-1.5">
        <span className={cn("h-1.5 w-1.5 shrink-0 rounded-full", online ? "bg-emerald-400" : "bg-zinc-500")} />
        <span className="truncate text-xs font-medium text-white">{String(cam.name)}</span>
        <ChevronRight className="ml-auto h-3.5 w-3.5 shrink-0 text-white/60 opacity-0 transition-opacity group-hover:opacity-100" />
      </div>
    </div>
  );
}

export function LiveWall() {
  const { user } = useAuth();
  const org = (user?.organization_id as string | undefined) ?? "";
  const [cams, setCams] = useState<Dict[]>([]);
  const [sites, setSites] = useState<Dict[]>([]);
  const [zones, setZones] = useState<Dict[]>([]);
  const [health, setHealth] = useState<Dict | null>(null);
  const [site, setSite] = useState<string>("all");
  const [density, setDensity] = useState<keyof typeof DENSITY>("standard");
  const [q, setQ] = useState("");

  useEffect(() => {
    if (!org) return;
    const g = <T,>(p: string, fb: T) => api.get<T>(p).catch(() => fb);
    g<Dict[]>(`/cameras?organization_id=${org}`, []).then(setCams);
    g<Dict[]>(`/sites?organization_id=${org}`, []).then(setSites);
    g<Dict[]>(`/sites/zones/list?organization_id=${org}`, []).then(setZones);
    g<Dict>(`/cameras/health?organization_id=${org}`, {}).then(setHealth);
  }, [org]);

  const zoneName = useMemo(() => {
    const m = new Map<string, string>();
    for (const z of zones) m.set(String(z.id), String(z.name));
    return m;
  }, [zones]);

  // Group cameras by site → zone, honouring the active site + search filters.
  const groups = useMemo(() => {
    const ql = q.trim().toLowerCase();
    const visibleSites = site === "all" ? sites : sites.filter((s) => String(s.id) === site);
    const out: { key: string; site: string; area: string; cams: Dict[] }[] = [];
    for (const s of visibleSites) {
      const sid = String(s.id);
      const mine = cams.filter((c) =>
        String(c.site_id) === sid && (!ql || String(c.name).toLowerCase().includes(ql)));
      if (!mine.length) continue;
      const byZone = new Map<string, Dict[]>();
      for (const c of mine) {
        const zk = c.zone_id ? String(c.zone_id) : "_";
        (byZone.get(zk) ?? byZone.set(zk, []).get(zk)!).push(c);
      }
      for (const [zk, list] of byZone) {
        out.push({
          key: `${sid}:${zk}`,
          site: String(s.name),
          area: zk === "_" ? "Unassigned" : (zoneName.get(zk) ?? "Area"),
          cams: list,
        });
      }
    }
    return out;
  }, [cams, sites, site, zoneName, q]);

  const totalVisible = groups.reduce((a, g) => a + g.cams.length, 0);

  return (
    <div className="space-y-4">
      {/* Toolbar */}
      <div className="flex flex-wrap items-center gap-3">
        <h1 className="text-2xl font-semibold tracking-tight">Live Monitoring</h1>
        {health && (
          <span className="rounded-full border border-border bg-card px-2.5 py-1 text-xs text-muted-foreground">
            <span className="font-medium text-emerald-400">{num(health.online)}</span>/{num(health.total)} online · {num(health.recording)} recording
          </span>
        )}
        <div className="ml-auto flex items-center gap-2">
          <div className="relative">
            <Search className="pointer-events-none absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search cameras"
              className="h-9 w-48 rounded-md border border-border bg-card pl-8 pr-3 text-sm outline-none focus:border-primary" />
          </div>
          <div className="flex rounded-md border border-border p-0.5">
            {(["comfortable", "standard", "dense"] as const).map((dz) => (
              <button key={dz} onClick={() => setDensity(dz)} title={dz}
                className={cn("rounded px-2 py-1 text-[11px] font-medium capitalize transition-colors",
                  density === dz ? "bg-primary/15 text-primary" : "text-muted-foreground hover:text-foreground")}>
                {dz === "comfortable" ? <Maximize2 className="h-3.5 w-3.5" /> : dz === "standard" ? <LayoutGrid className="h-3.5 w-3.5" /> : <span className="text-[13px]">▦</span>}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Site pills */}
      <div className="flex flex-wrap gap-2">
        <SitePill active={site === "all"} onClick={() => setSite("all")}>All Sites</SitePill>
        {sites.map((s) => (
          <SitePill key={String(s.id)} active={site === String(s.id)} onClick={() => setSite(String(s.id))}>
            {String(s.name)}
          </SitePill>
        ))}
      </div>

      {totalVisible === 0 ? (
        <p className="py-12 text-center text-muted-foreground">
          {cams.length === 0 ? "No cameras registered. Add cameras under Physical Security → Cameras." : "No cameras match the current filter."}
        </p>
      ) : (
        <div className="space-y-6">
          {groups.map((g) => (
            <section key={g.key}>
              <h2 className="mb-2 flex items-center gap-1.5 text-sm font-semibold text-foreground">
                {g.site}
                <ChevronRight className="h-4 w-4 text-muted-foreground" />
                <span className="text-muted-foreground">{g.area}</span>
                <span className="ml-1.5 text-xs font-normal text-muted-foreground">({g.cams.length})</span>
              </h2>
              <div className={cn("grid gap-3", DENSITY[density])}>
                {g.cams.map((c) => <CamTile key={String(c.id)} cam={c} />)}
              </div>
            </section>
          ))}
        </div>
      )}
    </div>
  );
}

function SitePill({ active, onClick, children }: { active: boolean; onClick: () => void; children: React.ReactNode }) {
  return (
    <button onClick={onClick}
      className={cn("rounded-full border px-3 py-1 text-sm transition-colors",
        active ? "border-primary bg-primary/15 text-primary" : "border-border bg-card text-muted-foreground hover:text-foreground")}>
      {children}
    </button>
  );
}
