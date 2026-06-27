import { Plus, Server } from "lucide-react";
import { useEffect, useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { api } from "@/lib/api";
import type { Asset } from "@/lib/types";

const TYPES = ["server", "workstation", "network_device", "firewall", "database", "application", "iot", "host"];
const CRITS = ["low", "medium", "high", "critical"];
const critVariant = (c: string) =>
  c === "critical" ? "destructive" : c === "high" ? "warning" : "muted";

export function Assets() {
  const [assets, setAssets] = useState<Asset[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [form, setForm] = useState({ name: "", asset_type: "server", ip_address: "", criticality: "medium", software: "" });
  const [busy, setBusy] = useState(false);

  const refresh = () => api.get<Asset[]>("/assets").then(setAssets).catch((e) => setError(e.message));
  useEffect(() => void refresh(), []);

  const create = async () => {
    if (!form.name.trim()) return;
    setBusy(true);
    setError(null);
    try {
      const software = form.software
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean)
        .map((s) => {
          const [name, version] = s.split(":").map((x) => x.trim());
          return { name, version: version || null };
        });
      await api.post("/assets", {
        name: form.name,
        asset_type: form.asset_type,
        ip_address: form.ip_address || null,
        criticality: form.criticality,
        software,
      });
      setForm({ name: "", asset_type: "server", ip_address: "", criticality: "medium", software: "" });
      await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Create failed");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-6">
      <h1 className="flex items-center gap-2 text-2xl font-semibold">
        <Server className="h-6 w-6 text-primary" /> Asset Inventory
      </h1>

      <Card>
        <CardHeader><CardTitle>Register asset</CardTitle></CardHeader>
        <CardContent className="grid gap-3 md:grid-cols-6">
          <input
            className="h-9 rounded-md border border-input bg-transparent px-3 text-sm md:col-span-2"
            placeholder="Name" value={form.name}
            onChange={(e) => setForm({ ...form, name: e.target.value })}
          />
          <Select value={form.asset_type} onValueChange={(v) => setForm({ ...form, asset_type: v })}>
            <SelectTrigger><SelectValue /></SelectTrigger>
            <SelectContent>
              {TYPES.map((t) => <SelectItem key={t} value={t}>{t}</SelectItem>)}
            </SelectContent>
          </Select>
          <input
            className="h-9 rounded-md border border-input bg-transparent px-3 text-sm"
            placeholder="IP address" value={form.ip_address}
            onChange={(e) => setForm({ ...form, ip_address: e.target.value })}
          />
          <Select value={form.criticality} onValueChange={(v) => setForm({ ...form, criticality: v })}>
            <SelectTrigger><SelectValue /></SelectTrigger>
            <SelectContent>
              {CRITS.map((c) => <SelectItem key={c} value={c}>{c}</SelectItem>)}
            </SelectContent>
          </Select>
          <Button onClick={create} disabled={busy}><Plus className="h-4 w-4" /> Add</Button>
          <input
            className="h-9 rounded-md border border-input bg-transparent px-3 text-sm md:col-span-6"
            placeholder="Software (e.g. openssl:3.0.2, log4j:2.14.1) — used for vulnerability matching"
            value={form.software}
            onChange={(e) => setForm({ ...form, software: e.target.value })}
          />
          {error && <span className="text-sm text-destructive md:col-span-6">{error}</span>}
        </CardContent>
      </Card>

      <Card>
        <CardHeader><CardTitle>Assets ({assets.length})</CardTitle></CardHeader>
        <CardContent>
          <table className="w-full text-sm">
            <thead className="text-left text-muted-foreground">
              <tr><th className="pb-2">Name</th><th className="pb-2">Type</th><th className="pb-2">IP</th>
                <th className="pb-2">Criticality</th><th className="pb-2">Software</th><th className="pb-2">Status</th></tr>
            </thead>
            <tbody>
              {assets.map((a) => (
                <tr key={a.id} className="border-t border-border/50">
                  <td className="py-2 font-medium">{a.name}</td>
                  <td className="py-2">{a.asset_type}</td>
                  <td className="py-2">{a.ip_address ?? "—"}</td>
                  <td className="py-2"><Badge variant={critVariant(a.criticality)}>{a.criticality}</Badge></td>
                  <td className="py-2 text-muted-foreground">{a.software.map((s) => s.name).join(", ") || "—"}</td>
                  <td className="py-2">{a.status}</td>
                </tr>
              ))}
              {assets.length === 0 && (
                <tr><td colSpan={6} className="py-3 text-center text-muted-foreground">No assets yet</td></tr>
              )}
            </tbody>
          </table>
        </CardContent>
      </Card>
    </div>
  );
}
