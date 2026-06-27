import {
  Bell, Building2, Car, CreditCard, DoorClosed, Gauge, LayoutDashboard, Lock,
  Megaphone, Moon, Network, Radar, Radio, ScanFace, Search, ShieldAlert, Siren,
  SlidersHorizontal, ToggleLeft, UserCheck, Users, Video, Workflow, Zap,
} from "lucide-react";
import { useEffect, useMemo, useRef, useState, type ComponentType } from "react";
import { useNavigate } from "react-router-dom";

type Cmd = {
  id: string;
  label: string;
  group: string;
  icon: ComponentType<{ className?: string }>;
  hint?: string;
  run: (nav: ReturnType<typeof useNavigate>) => void;
};

const go = (to: string) => (nav: ReturnType<typeof useNavigate>) => nav(to);

const NAV: Array<[string, string, ComponentType<{ className?: string }>]> = [
  ["/", "Dashboard", LayoutDashboard],
  ["/live", "Live Monitoring", Radio],
  ["/threats", "Threat Center", ShieldAlert],
  ["/incidents", "Incident Center", Siren],
  ["/alerts", "Alert Center", Bell],
  ["/emergency", "Emergency Response", Siren],
  ["/detections", "AI Detections", ScanFace],
  ["/analytics", "Analytics & BI", Gauge],
  ["/soc", "SOC / Security Events", ShieldAlert],
  ["/sites", "Sites", Building2],
  ["/cameras", "Cameras", Video],
  ["/access", "Access Control", DoorClosed],
  ["/visitors", "Visitors", Users],
  ["/vehicles", "Vehicles / ANPR", Car],
  ["/patrols", "Patrols", Radar],
  ["/guards", "Guards", UserCheck],
  ["/organizations", "Organizations", Building2],
  ["/billing", "Billing", CreditCard],
  ["/workflows", "Workflow Automation", Workflow],
  ["/comms", "Communication", Megaphone],
  ["/integrations", "Integrations", Network],
  ["/settings", "Settings & Feature Flags", ToggleLeft],
];

function buildCommands(): Cmd[] {
  const navCmds: Cmd[] = NAV.map(([to, label, icon]) => ({
    id: `nav:${to}`, label, group: "Navigate", icon, hint: to, run: go(to),
  }));
  const actions: Cmd[] = [
    { id: "act:lockdown", label: "Trigger Lockdown", group: "Actions", icon: Lock,
      hint: "emergency", run: go("/emergency") },
    { id: "act:theme", label: "Toggle theme (Obsidian / Daylight)", group: "Actions", icon: Moon,
      run: () => document.dispatchEvent(new CustomEvent("siq:toggle-theme")) },
    { id: "act:density", label: "Toggle density (Cozy / Compact)", group: "Actions", icon: SlidersHorizontal,
      run: () => document.dispatchEvent(new CustomEvent("siq:toggle-density")) },
    { id: "act:live", label: "Toggle live mode", group: "Actions", icon: Zap,
      run: () => document.dispatchEvent(new CustomEvent("siq:toggle-live")) },
  ];
  return [...navCmds, ...actions];
}

export function CommandPalette() {
  const nav = useNavigate();
  const [open, setOpen] = useState(false);
  const [q, setQ] = useState("");
  const [active, setActive] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const commands = useMemo(buildCommands, []);

  const results = useMemo(() => {
    const t = q.trim().toLowerCase();
    if (!t) return commands;
    return commands.filter((c) =>
      c.label.toLowerCase().includes(t) || c.group.toLowerCase().includes(t) || (c.hint ?? "").includes(t),
    );
  }, [q, commands]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setOpen((o) => !o);
      }
      if (e.key === "Escape") setOpen(false);
    };
    const onOpen = () => setOpen(true);
    document.addEventListener("keydown", onKey);
    document.addEventListener("siq:command-open", onOpen);
    return () => {
      document.removeEventListener("keydown", onKey);
      document.removeEventListener("siq:command-open", onOpen);
    };
  }, []);

  useEffect(() => {
    if (open) {
      setQ(""); setActive(0);
      setTimeout(() => inputRef.current?.focus(), 20);
    }
  }, [open]);

  if (!open) return null;

  const exec = (c: Cmd) => { setOpen(false); c.run(nav); };

  let lastGroup = "";
  return (
    <div className="fixed inset-0 z-[100] flex items-start justify-center pt-[12vh]"
      onMouseDown={() => setOpen(false)}>
      <div className="absolute inset-0 bg-black/50 backdrop-blur-[2px]" />
      <div
        className="glass animate-pop-in relative w-full max-w-xl overflow-hidden rounded-xl"
        onMouseDown={(e) => e.stopPropagation()}
        role="dialog" aria-label="Command palette"
        onKeyDown={(e) => {
          if (e.key === "ArrowDown") { e.preventDefault(); setActive((a) => Math.min(a + 1, results.length - 1)); }
          if (e.key === "ArrowUp") { e.preventDefault(); setActive((a) => Math.max(a - 1, 0)); }
          if (e.key === "Enter" && results[active]) { e.preventDefault(); exec(results[active]); }
        }}
      >
        <div className="flex items-center gap-2 border-b border-border px-4">
          <Search className="h-4 w-4 text-muted-foreground" />
          <input
            ref={inputRef}
            value={q}
            onChange={(e) => { setQ(e.target.value); setActive(0); }}
            placeholder="Search pages and actions…"
            className="h-12 flex-1 bg-transparent text-sm outline-none placeholder:text-muted-foreground"
          />
          <kbd className="rounded border border-border px-1.5 py-0.5 text-[10px] text-muted-foreground">ESC</kbd>
        </div>
        <div className="max-h-[50vh] overflow-y-auto p-2">
          {results.length === 0 && (
            <div className="px-3 py-6 text-center text-sm text-muted-foreground">No matches</div>
          )}
          {results.map((c, i) => {
            const header = c.group !== lastGroup ? c.group : null;
            lastGroup = c.group;
            const Icon = c.icon;
            return (
              <div key={c.id}>
                {header && <div className="label-micro px-3 pb-1 pt-2">{header}</div>}
                <button
                  onMouseEnter={() => setActive(i)}
                  onClick={() => exec(c)}
                  className={`flex w-full items-center gap-3 rounded-md px-3 py-2 text-left text-sm transition-colors ${
                    i === active ? "bg-primary/15 text-primary" : "text-foreground hover:bg-accent"
                  }`}
                >
                  <Icon className="h-4 w-4 shrink-0 opacity-80" />
                  <span className="flex-1">{c.label}</span>
                  {c.hint && <span className="mono text-[11px] text-muted-foreground">{c.hint}</span>}
                </button>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
