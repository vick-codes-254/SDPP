import {
  AlertTriangle,
  Database,
  FileLock2,
  HeartPulse,
  KeyRound,
  ShieldAlert,
} from "lucide-react";
import { useEffect, useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { api } from "@/lib/api";
import type { Dashboard as DashboardData } from "@/lib/types";
import { formatBytes } from "@/lib/utils";

function Stat({ icon: Icon, label, value, accent }: {
  icon: typeof FileLock2; label: string; value: string | number; accent?: string;
}) {
  return (
    <Card>
      <CardHeader className="flex-row items-center justify-between space-y-0 pb-2">
        <CardTitle>{label}</CardTitle>
        <Icon className={`h-4 w-4 ${accent ?? "text-muted-foreground"}`} />
      </CardHeader>
      <CardContent>
        <div className="text-2xl font-semibold">{value}</div>
      </CardContent>
    </Card>
  );
}

export function Dashboard() {
  const [data, setData] = useState<DashboardData | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.get<DashboardData>("/security-dashboard").then(setData).catch((e) => setError(e.message));
  }, []);

  if (error) return <p className="text-destructive">{error}</p>;
  if (!data) return <p className="text-muted-foreground">Loading…</p>;

  const health = data.encryption_health_score;
  const healthVariant = health >= 90 ? "success" : health >= 70 ? "warning" : "destructive";

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-semibold">Security Dashboard</h1>
        <Badge variant={healthVariant}>Encryption health {health}%</Badge>
      </div>

      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        <Stat icon={FileLock2} label="Encrypted files" value={data.encrypted_files} accent="text-primary" />
        <Stat icon={Database} label="Storage used" value={formatBytes(data.storage_usage_bytes)} />
        <Stat icon={KeyRound} label="Key rotations" value={data.key_rotations} />
        <Stat icon={HeartPulse} label="Health score" value={`${health}%`} accent="text-emerald-400" />
        <Stat icon={ShieldAlert} label="Integrity violations" value={data.integrity_violations} accent="text-amber-400" />
        <Stat icon={AlertTriangle} label="Failed decryptions" value={data.failed_decryptions} accent="text-amber-400" />
        <Stat icon={AlertTriangle} label="Open alerts" value={data.open_alerts} accent="text-amber-400" />
        <Stat icon={ShieldAlert} label="Critical alerts" value={data.critical_alerts} accent="text-destructive" />
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Recent events</CardTitle>
        </CardHeader>
        <CardContent>
          <table className="w-full text-sm">
            <thead className="text-left text-muted-foreground">
              <tr>
                <th className="pb-2">Seq</th>
                <th className="pb-2">Event</th>
                <th className="pb-2">Outcome</th>
                <th className="pb-2">Actor</th>
                <th className="pb-2">When</th>
              </tr>
            </thead>
            <tbody>
              {data.recent_events.map((e, i) => (
                <tr key={i} className="border-t border-border/50">
                  <td className="py-1.5">{String(e.seq ?? "")}</td>
                  <td className="py-1.5">{String(e.event_type ?? "")}</td>
                  <td className="py-1.5">
                    <Badge variant={e.outcome === "success" ? "success" : "destructive"}>
                      {String(e.outcome ?? "")}
                    </Badge>
                  </td>
                  <td className="py-1.5">{String(e.actor ?? "—")}</td>
                  <td className="py-1.5 text-muted-foreground">{String(e.at ?? "")}</td>
                </tr>
              ))}
              {data.recent_events.length === 0 && (
                <tr>
                  <td colSpan={5} className="py-3 text-center text-muted-foreground">
                    No events yet
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </CardContent>
      </Card>
    </div>
  );
}
