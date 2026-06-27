import {
  Activity,
  Bell,
  Bug,
  Building2,
  Car,
  ChevronsUpDown,
  Clock,
  Command,
  CreditCard,
  DoorClosed,
  FileLock2,
  FolderLock,
  Gauge,
  LayoutDashboard,
  Lock,
  LogOut,
  Megaphone,
  Moon,
  Network,
  Radar,
  Radio,
  ScanFace,
  ScrollText,
  Search,
  Server,
  ShieldAlert,
  ShieldCheck,
  Siren,
  SlidersHorizontal,
  Sun,
  ToggleLeft,
  UserCheck,
  UserCog,
  Users,
  Users2,
  Video,
  Workflow,
  Zap,
} from "lucide-react";
import { useEffect, useState } from "react";
import { NavLink, Outlet, useNavigate } from "react-router-dom";
import { CommandPalette } from "@/components/CommandPalette";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { useAuth } from "@/context/AuthContext";
import { cn } from "@/lib/utils";

const NAV_GROUPS = [
  {
    title: "Overview",
    items: [
      { to: "/", label: "Mission Control", icon: LayoutDashboard, end: true },
      { to: "/overview", label: "Executive Overview", icon: Gauge },
    ],
  },
  {
    title: "Security Operations",
    items: [
      { to: "/live", label: "Live Monitoring", icon: Radio },
      { to: "/threats", label: "Threat Center", icon: ShieldAlert },
      { to: "/incidents", label: "Incident Center", icon: Siren },
      { to: "/alerts", label: "Alert Center", icon: Bell },
      { to: "/emergency", label: "Emergency", icon: Siren },
    ],
  },
  {
    title: "AI Intelligence",
    items: [
      { to: "/detections", label: "AI Detections", icon: ScanFace },
      { to: "/analytics", label: "Analytics & BI", icon: Gauge },
    ],
  },
  {
    title: "Physical Security",
    items: [
      { to: "/sites", label: "Sites", icon: Building2 },
      { to: "/cameras", label: "Cameras", icon: Video },
      { to: "/access", label: "Access Control", icon: DoorClosed },
      { to: "/visitors", label: "Visitors", icon: Users2 },
      { to: "/vehicles", label: "Vehicles / ANPR", icon: Car },
      { to: "/patrols", label: "Patrols", icon: Radar },
      { to: "/guards", label: "Guards", icon: UserCheck },
    ],
  },
  {
    title: "Cyber Security",
    items: [
      { to: "/soc", label: "SOC / Security Events", icon: ShieldAlert },
      { to: "/assets", label: "Assets", icon: Server },
      { to: "/discovery", label: "Network Discovery", icon: Radar },
      { to: "/vulnerabilities", label: "Vulnerabilities", icon: Bug },
      { to: "/audit", label: "Audit Logs", icon: ScrollText },
    ],
  },
  {
    title: "Encryption & Security",
    items: [
      { to: "/files", label: "File Vault", icon: FileLock2 },
      { to: "/evidence", label: "Evidence", icon: FolderLock },
      { to: "/compliance", label: "Compliance", icon: ShieldCheck },
    ],
  },
  {
    title: "Administration",
    items: [
      { to: "/organizations", label: "Organizations", icon: Building2 },
      { to: "/users", label: "Users", icon: Users },
      { to: "/billing", label: "Billing", icon: CreditCard },
      { to: "/workflows", label: "Workflow Automation", icon: Workflow },
      { to: "/comms", label: "Communication", icon: Megaphone },
      { to: "/integrations", label: "Integrations", icon: Network },
      { to: "/settings", label: "Settings", icon: ToggleLeft },
    ],
  },
];

const TIME_RANGES = ["Last 1 hour", "Last 24 hours", "Last 7 days", "Last 30 days"];

function OpsBar({ onLockdown }: { onLockdown: () => void }) {
  const [dark, setDark] = useState(() => document.documentElement.classList.contains("dark"));
  const [compact, setCompact] = useState(() => document.documentElement.dataset.density === "compact");
  const [live, setLive] = useState(true);
  const [rangeIdx, setRangeIdx] = useState(1);

  const applyTheme = (d: boolean) => {
    document.documentElement.classList.toggle("dark", d);
    localStorage.setItem("siq-theme", d ? "obsidian" : "daylight");
    setDark(d);
  };
  const applyDensity = (c: boolean) => {
    document.documentElement.dataset.density = c ? "compact" : "cozy";
    localStorage.setItem("siq-density", c ? "compact" : "cozy");
    setCompact(c);
  };

  useEffect(() => {
    const t = () => applyTheme(!document.documentElement.classList.contains("dark"));
    const d = () => applyDensity(document.documentElement.dataset.density !== "compact");
    const l = () => setLive((v) => !v);
    document.addEventListener("siq:toggle-theme", t);
    document.addEventListener("siq:toggle-density", d);
    document.addEventListener("siq:toggle-live", l);
    return () => {
      document.removeEventListener("siq:toggle-theme", t);
      document.removeEventListener("siq:toggle-density", d);
      document.removeEventListener("siq:toggle-live", l);
    };
  }, []);

  const iconBtn = "flex h-8 w-8 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-accent hover:text-foreground";

  return (
    <header className="glass sticky top-0 z-40 flex h-14 items-center gap-3 px-4" style={{ boxShadow: "none", borderTop: "none", borderLeft: "none", borderRight: "none" }}>
      <div className="flex items-center gap-2 pr-2">
        <div className="flex h-7 w-7 items-center justify-center rounded-md bg-primary/15">
          <Activity className="h-4 w-4 text-primary" />
        </div>
        <div className="leading-none">
          <div className="text-sm font-semibold">SentinelIQ</div>
          <div className="text-[10px] uppercase tracking-wider text-muted-foreground">Unified Security</div>
        </div>
      </div>

      {/* Command / search trigger */}
      <button
        onClick={() => document.dispatchEvent(new CustomEvent("siq:command-open"))}
        className="group flex h-9 max-w-md flex-1 items-center gap-2 rounded-md border border-border bg-background/60 px-3 text-sm text-muted-foreground transition-colors hover:border-border-strong hover:text-foreground"
      >
        <Search className="h-4 w-4" />
        <span className="flex-1 text-left">Search assets, incidents, actions…</span>
        <kbd className="flex items-center gap-0.5 rounded border border-border px-1.5 py-0.5 text-[10px]">
          <Command className="h-2.5 w-2.5" />K
        </kbd>
      </button>

      <div className="ml-auto flex items-center gap-1.5">
        {/* Time range (cycles presets) */}
        <button
          onClick={() => setRangeIdx((i) => (i + 1) % TIME_RANGES.length)}
          className="flex h-8 items-center gap-1.5 rounded-md border border-border px-2.5 text-xs text-muted-foreground transition-colors hover:bg-accent hover:text-foreground"
        >
          <Clock className="h-3.5 w-3.5" />
          {TIME_RANGES[rangeIdx]}
        </button>

        <button
          onClick={() => setLive((v) => !v)}
          title="Live mode"
          className={cn("flex h-8 items-center gap-1.5 rounded-md border px-2.5 text-xs font-medium transition-colors",
            live ? "border-transparent text-[color:var(--sev-low)]" : "border-border text-muted-foreground hover:bg-accent")}
          style={live ? { background: "color-mix(in srgb, var(--sev-low) 14%, transparent)" } : undefined}
        >
          <Zap className={cn("h-3.5 w-3.5", live && "animate-sev-pulse")} /> {live ? "Live" : "Paused"}
        </button>

        <button className={iconBtn} title="Density" onClick={() => applyDensity(!compact)}>
          <SlidersHorizontal className="h-4 w-4" />
        </button>
        <button className={iconBtn} title="Theme" onClick={() => applyTheme(!dark)}>
          {dark ? <Moon className="h-4 w-4" /> : <Sun className="h-4 w-4" />}
        </button>
        <button className={cn(iconBtn, "relative")} title="Notifications">
          <Bell className="h-4 w-4" />
          <span className="absolute right-1.5 top-1.5 h-1.5 w-1.5 rounded-full" style={{ background: "var(--sev-critical)" }} />
        </button>

        <button
          onClick={onLockdown}
          className="ml-1 flex h-8 items-center gap-1.5 rounded-md px-3 text-xs font-semibold text-white transition-transform hover:scale-[1.02]"
          style={{ background: "var(--sev-critical)" }}
        >
          <Lock className="h-3.5 w-3.5" /> Lockdown
        </button>
      </div>
    </header>
  );
}

function LockdownSheet({ open, onClose }: { open: boolean; onClose: () => void }) {
  const navigate = useNavigate();
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-[90] flex items-center justify-center" onMouseDown={onClose}>
      <div className="absolute inset-0 bg-black/60 backdrop-blur-[2px]" />
      <div className="glass animate-pop-in relative w-full max-w-md rounded-xl p-6" onMouseDown={(e) => e.stopPropagation()}>
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-lg" style={{ background: "color-mix(in srgb, var(--sev-critical) 18%, transparent)" }}>
            <Lock className="h-5 w-5" style={{ color: "var(--sev-critical)" }} />
          </div>
          <div>
            <h2 className="text-lg font-semibold">Initiate Lockdown</h2>
            <p className="text-sm text-muted-foreground">Lock all access points and broadcast an emergency.</p>
          </div>
        </div>
        <p className="mt-4 rounded-md border border-border bg-background/50 p-3 text-sm text-muted-foreground">
          This is a high-impact action. You'll choose scope and confirm on the Emergency console.
        </p>
        <div className="mt-5 flex justify-end gap-2">
          <button onClick={onClose} className="rounded-md border border-border px-4 py-2 text-sm hover:bg-accent">Cancel</button>
          <button
            onClick={() => { onClose(); navigate("/emergency"); }}
            className="rounded-md px-4 py-2 text-sm font-semibold text-white"
            style={{ background: "var(--sev-critical)" }}
          >
            Open Emergency Console
          </button>
        </div>
      </div>
    </div>
  );
}

export function Layout() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const [lockOpen, setLockOpen] = useState(false);

  const onLogout = async () => {
    await logout();
    navigate("/login");
  };

  return (
    <div className="flex h-screen flex-col bg-background">
      <OpsBar onLockdown={() => setLockOpen(true)} />
      <div className="flex flex-1 overflow-hidden">
        <aside className="flex w-60 flex-col border-r border-border bg-card/30">
          <nav className="flex-1 space-y-4 overflow-y-auto px-3 py-4">
            {NAV_GROUPS.map((group) => (
              <div key={group.title} className="space-y-0.5">
                <div className="label-micro px-3 pb-1 text-muted-foreground/60">{group.title}</div>
                {group.items.map((item) => {
                  const { to, label, icon: Icon } = item;
                  const end = "end" in item ? item.end : undefined;
                  return (
                    <NavLink
                      key={to}
                      to={to}
                      end={end}
                      className={({ isActive }) =>
                        cn(
                          "group relative flex items-center gap-3 rounded-md px-3 py-1.5 text-sm font-medium transition-colors",
                          isActive ? "bg-primary/15 text-primary" : "text-muted-foreground hover:bg-accent hover:text-foreground",
                        )
                      }
                    >
                      {({ isActive }) => (
                        <>
                          {isActive && <span className="absolute left-0 top-1/2 h-4 w-0.5 -translate-y-1/2 rounded-full bg-primary" />}
                          <Icon className="h-4 w-4 shrink-0" />
                          {label}
                        </>
                      )}
                    </NavLink>
                  );
                })}
              </div>
            ))}
          </nav>
          <div className="border-t border-border p-3">
            <DropdownMenu>
              <DropdownMenuTrigger className="flex w-full items-center gap-3 rounded-md px-2 py-2 text-left text-sm outline-none transition-colors hover:bg-accent focus-visible:ring-2 focus-visible:ring-ring">
                <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-primary/15 text-sm font-semibold uppercase text-primary">
                  {user?.username?.[0] ?? "?"}
                </span>
                <span className="min-w-0 flex-1">
                  <span className="block truncate font-medium">{user?.username}</span>
                  <span className="block truncate text-xs text-muted-foreground">{user?.email}</span>
                </span>
                <ChevronsUpDown className="h-4 w-4 shrink-0 text-muted-foreground" />
              </DropdownMenuTrigger>
              <DropdownMenuContent side="top" align="start" className="w-56">
                <DropdownMenuLabel>
                  <div className="truncate">{user?.full_name ?? user?.username}</div>
                  <div className="truncate text-xs font-normal text-muted-foreground">{user?.email}</div>
                </DropdownMenuLabel>
                <DropdownMenuSeparator />
                <DropdownMenuItem disabled>
                  <UserCog />
                  {user?.is_superuser ? "Super administrator" : `${user?.permissions.length ?? 0} permissions`}
                </DropdownMenuItem>
                <DropdownMenuSeparator />
                <DropdownMenuItem destructive onSelect={onLogout}>
                  <LogOut /> Sign out
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        </aside>
        <main className="flex-1 overflow-auto">
          <div className="mx-auto max-w-[1600px] p-6 lg:p-8">
            <Outlet />
          </div>
        </main>
      </div>
      <CommandPalette />
      <LockdownSheet open={lockOpen} onClose={() => setLockOpen(false)} />
    </div>
  );
}
