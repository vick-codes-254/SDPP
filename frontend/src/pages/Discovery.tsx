import { Play, Plus, Radar } from "lucide-react";
import { useEffect, useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { api } from "@/lib/api";
import type { DiscoveryScan } from "@/lib/types";

const statusVariant = (s: string) =>
  s === "completed" ? "success" : s === "failed" ? "destructive" : "muted";

export function Discovery() {
  const [scans, setScans] = useState<DiscoveryScan[]>([]);
  const [form, setForm] = useState({ name: "", targets: "127.0.0.1", ports: "22,80,443,3389,5432" });
  const [msg, setMsg] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const refresh = () => api.get<DiscoveryScan[]>("/discovery/scans").then(setScans).catch((e) => setMsg(e.message));
  useEffect(() => void refresh(), []);

  const create = async () => {
    if (!form.name.trim()) return;
    setMsg(null);
    try {
      await api.post("/discovery/scans", {
        name: form.name,
        targets: form.targets.split(",").map((t) => t.trim()).filter(Boolean),
        ports: form.ports.split(",").map((p) => parseInt(p.trim(), 10)).filter((n) => !Number.isNaN(n)),
      });
      setForm({ ...form, name: "" });
      await refresh();
    } catch (e) {
      setMsg(e instanceof Error ? e.message : "Create failed");
    }
  };

  const run = async (s: DiscoveryScan) => {
    setBusy(true);
    setMsg(null);
    try {
      const done = await api.post<DiscoveryScan>(`/discovery/scans/${s.id}/run`);
      setMsg(`Scan "${done.name}" finished: ${done.hosts_found} live host(s).`);
      await refresh();
    } catch (e) {
      setMsg(e instanceof Error ? e.message : "Scan failed");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-6">
      <h1 className="flex items-center gap-2 text-2xl font-semibold">
        <Radar className="h-6 w-6 text-primary" /> Network Discovery
      </h1>
      <p className="text-sm text-muted-foreground">
        Safe TCP-connect discovery of <strong>explicitly listed</strong> targets only. No exploitation, no subnet sweeps.
      </p>

      <Card>
        <CardHeader><CardTitle>New scan</CardTitle></CardHeader>
        <CardContent className="grid gap-3 md:grid-cols-6">
          <input className="h-9 rounded-md border border-input bg-transparent px-3 text-sm md:col-span-2"
            placeholder="Scan name" value={form.name}
            onChange={(e) => setForm({ ...form, name: e.target.value })} />
          <input className="h-9 rounded-md border border-input bg-transparent px-3 text-sm md:col-span-2"
            placeholder="Targets (IP/CIDR/host, comma-sep)" value={form.targets}
            onChange={(e) => setForm({ ...form, targets: e.target.value })} />
          <input className="h-9 rounded-md border border-input bg-transparent px-3 text-sm"
            placeholder="Ports" value={form.ports}
            onChange={(e) => setForm({ ...form, ports: e.target.value })} />
          <Button onClick={create}><Plus className="h-4 w-4" /> Create</Button>
          {msg && <span className="text-sm text-muted-foreground md:col-span-6">{msg}</span>}
        </CardContent>
      </Card>

      <Card>
        <CardHeader><CardTitle>Scans ({scans.length})</CardTitle></CardHeader>
        <CardContent>
          <table className="w-full text-sm">
            <thead className="text-left text-muted-foreground">
              <tr><th className="pb-2">Name</th><th className="pb-2">Targets</th><th className="pb-2">Status</th>
                <th className="pb-2">Hosts found</th><th className="pb-2 text-right">Run</th></tr>
            </thead>
            <tbody>
              {scans.map((s) => (
                <tr key={s.id} className="border-t border-border/50">
                  <td className="py-2 font-medium">{s.name}</td>
                  <td className="py-2 text-muted-foreground">{s.targets.join(", ")}</td>
                  <td className="py-2"><Badge variant={statusVariant(s.status)}>{s.status}</Badge></td>
                  <td className="py-2">{s.hosts_found}</td>
                  <td className="py-2 text-right">
                    <Button size="sm" variant="outline" disabled={busy} onClick={() => run(s)}>
                      <Play className="h-3.5 w-3.5" /> Run
                    </Button>
                  </td>
                </tr>
              ))}
              {scans.length === 0 && (
                <tr><td colSpan={5} className="py-3 text-center text-muted-foreground">No scans yet</td></tr>
              )}
            </tbody>
          </table>
        </CardContent>
      </Card>
    </div>
  );
}
