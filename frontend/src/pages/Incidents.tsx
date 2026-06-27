import { Plus, Siren } from "lucide-react";
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
import type { Incident } from "@/lib/types";

const SEVS = ["low", "medium", "high", "critical"];
const STATUSES = ["open", "investigating", "contained", "resolved", "closed"];
const sevVariant = (s: string) =>
  s === "critical" ? "destructive" : s === "high" ? "warning" : "muted";
const statusVariant = (s: string) =>
  s === "resolved" || s === "closed" ? "success" : s === "open" ? "warning" : "muted";

export function Incidents() {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [form, setForm] = useState({ title: "", severity: "medium", description: "" });
  const [error, setError] = useState<string | null>(null);

  const refresh = () => api.get<Incident[]>("/incidents").then(setIncidents).catch((e) => setError(e.message));
  useEffect(() => void refresh(), []);

  const create = async () => {
    if (!form.title.trim()) return;
    try {
      await api.post("/incidents", { title: form.title, severity: form.severity, description: form.description || null });
      setForm({ title: "", severity: "medium", description: "" });
      await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Create failed");
    }
  };

  const setStatus = async (inc: Incident, status: string) => {
    await api.post(`/incidents/${inc.id}/status`, { status });
    await refresh();
  };

  return (
    <div className="space-y-6">
      <h1 className="flex items-center gap-2 text-2xl font-semibold">
        <Siren className="h-6 w-6 text-primary" /> Incident Management
      </h1>

      <Card>
        <CardHeader><CardTitle>Declare incident</CardTitle></CardHeader>
        <CardContent className="grid gap-3 md:grid-cols-6">
          <input
            className="h-9 rounded-md border border-input bg-transparent px-3 text-sm md:col-span-2"
            placeholder="Title" value={form.title}
            onChange={(e) => setForm({ ...form, title: e.target.value })}
          />
          <Select value={form.severity} onValueChange={(v) => setForm({ ...form, severity: v })}>
            <SelectTrigger><SelectValue /></SelectTrigger>
            <SelectContent>{SEVS.map((s) => <SelectItem key={s} value={s}>{s}</SelectItem>)}</SelectContent>
          </Select>
          <input
            className="h-9 rounded-md border border-input bg-transparent px-3 text-sm md:col-span-2"
            placeholder="Description (encrypted)" value={form.description}
            onChange={(e) => setForm({ ...form, description: e.target.value })}
          />
          <Button onClick={create}><Plus className="h-4 w-4" /> Declare</Button>
          {error && <span className="text-sm text-destructive md:col-span-6">{error}</span>}
        </CardContent>
      </Card>

      <Card>
        <CardHeader><CardTitle>Incidents ({incidents.length})</CardTitle></CardHeader>
        <CardContent>
          <table className="w-full text-sm">
            <thead className="text-left text-muted-foreground">
              <tr><th className="pb-2">Title</th><th className="pb-2">Severity</th><th className="pb-2">Status</th>
                <th className="pb-2">Created</th><th className="pb-2 w-44">Set status</th></tr>
            </thead>
            <tbody>
              {incidents.map((i) => (
                <tr key={i.id} className="border-t border-border/50">
                  <td className="py-2 font-medium">{i.title}</td>
                  <td className="py-2"><Badge variant={sevVariant(i.severity)}>{i.severity}</Badge></td>
                  <td className="py-2"><Badge variant={statusVariant(i.status)}>{i.status}</Badge></td>
                  <td className="py-2 text-muted-foreground">{i.created_at.slice(0, 16).replace("T", " ")}</td>
                  <td className="py-2">
                    <Select value={i.status} onValueChange={(v) => setStatus(i, v)}>
                      <SelectTrigger><SelectValue /></SelectTrigger>
                      <SelectContent>{STATUSES.map((s) => <SelectItem key={s} value={s}>{s}</SelectItem>)}</SelectContent>
                    </Select>
                  </td>
                </tr>
              ))}
              {incidents.length === 0 && (
                <tr><td colSpan={5} className="py-3 text-center text-muted-foreground">No incidents</td></tr>
              )}
            </tbody>
          </table>
        </CardContent>
      </Card>
    </div>
  );
}
