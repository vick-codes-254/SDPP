import { ShieldCheck } from "lucide-react";
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
import type { AuditEntry } from "@/lib/types";

const PAGE_SIZES = ["50", "100", "200", "500"];

interface ChainResult {
  ok: boolean;
  entries_checked: number;
  detail: string;
}

export function AuditLog() {
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [chain, setChain] = useState<ChainResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [limit, setLimit] = useState("100");

  useEffect(() => {
    api
      .get<AuditEntry[]>(`/audit-logs?limit=${limit}`)
      .then(setEntries)
      .catch((e) => setError(e.message));
  }, [limit]);

  const verify = async () => {
    try {
      setChain(await api.get<ChainResult>("/audit-logs/verify"));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Verification failed");
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-semibold">Audit Trail</h1>
        <div className="flex items-center gap-3">
          {chain && (
            <Badge variant={chain.ok ? "success" : "destructive"}>
              {chain.ok ? `Chain intact (${chain.entries_checked})` : chain.detail}
            </Badge>
          )}
          <div className="w-32">
            <Select value={limit} onValueChange={setLimit}>
              <SelectTrigger aria-label="Rows per page">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {PAGE_SIZES.map((n) => (
                  <SelectItem key={n} value={n}>{n} rows</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <Button variant="outline" onClick={verify}>
            <ShieldCheck className="h-4 w-4" /> Verify chain
          </Button>
        </div>
      </div>

      {error && <p className="text-destructive">{error}</p>}

      <Card>
        <CardHeader><CardTitle>Immutable, hash-chained events</CardTitle></CardHeader>
        <CardContent>
          <table className="w-full text-sm">
            <thead className="text-left text-muted-foreground">
              <tr>
                <th className="pb-2">Seq</th><th className="pb-2">Event</th>
                <th className="pb-2">Outcome</th><th className="pb-2">Actor</th>
                <th className="pb-2">When</th><th className="pb-2">Hash</th>
              </tr>
            </thead>
            <tbody>
              {entries.map((e) => (
                <tr key={e.seq} className="border-t border-border/50">
                  <td className="py-1.5">{e.seq}</td>
                  <td className="py-1.5">{e.event_type}</td>
                  <td className="py-1.5">
                    <Badge variant={e.outcome === "success" ? "success" : e.outcome === "denied" ? "warning" : "destructive"}>
                      {e.outcome}
                    </Badge>
                  </td>
                  <td className="py-1.5">{e.actor_label ?? "—"}</td>
                  <td className="py-1.5 text-muted-foreground">{e.created_at}</td>
                  <td className="py-1.5 font-mono text-xs text-muted-foreground">{e.entry_hash.slice(0, 12)}…</td>
                </tr>
              ))}
            </tbody>
          </table>
        </CardContent>
      </Card>
    </div>
  );
}
