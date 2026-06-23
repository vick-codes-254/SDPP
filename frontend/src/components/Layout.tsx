import { Activity, FileLock2, LayoutDashboard, LogOut, ScrollText, ShieldCheck } from "lucide-react";
import { NavLink, Outlet, useNavigate } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { useAuth } from "@/context/AuthContext";
import { cn } from "@/lib/utils";

const NAV = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard, end: true },
  { to: "/files", label: "File Vault", icon: FileLock2 },
  { to: "/audit", label: "Audit Trail", icon: ScrollText },
  { to: "/compliance", label: "Compliance", icon: ShieldCheck },
];

export function Layout() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  const onLogout = async () => {
    await logout();
    navigate("/login");
  };

  return (
    <div className="flex min-h-screen">
      <aside className="flex w-64 flex-col border-r bg-card/50">
        <div className="flex items-center gap-2 px-6 py-5">
          <Activity className="h-6 w-6 text-primary" />
          <span className="text-lg font-semibold">SDPP</span>
        </div>
        <nav className="flex-1 space-y-1 px-3">
          {NAV.map(({ to, label, icon: Icon, end }) => (
            <NavLink
              key={to}
              to={to}
              end={end}
              className={({ isActive }) =>
                cn(
                  "flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors",
                  isActive ? "bg-primary/15 text-primary" : "text-muted-foreground hover:bg-accent",
                )
              }
            >
              <Icon className="h-4 w-4" />
              {label}
            </NavLink>
          ))}
        </nav>
        <div className="border-t p-4">
          <div className="mb-2 text-sm">
            <div className="font-medium">{user?.username}</div>
            <div className="truncate text-xs text-muted-foreground">{user?.email}</div>
          </div>
          <Button variant="outline" size="sm" className="w-full" onClick={onLogout}>
            <LogOut className="h-4 w-4" /> Sign out
          </Button>
        </div>
      </aside>
      <main className="flex-1 overflow-auto">
        <div className="mx-auto max-w-6xl p-8">
          <Outlet />
        </div>
      </main>
    </div>
  );
}
