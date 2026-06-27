import { Bug, Play } from "lucide-react";
import { useEffect, useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { api } from "@/lib/api";
import type { Finding, VulnScan } from "@/lib/types";

const sevVariant = (s: string) =>
  s === "critical" ? "destructive" : s === "high" ? "warning" : s === "medium" ? "muted" : "muted";

export function Vulnerabilities() {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [scans, setScans] = useState<VulnScan[]>([]);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);

  const refresh = async () => {
    setFindings(await api.get<Finding[]>("/vulnerabilities/findings"));
    setScans(await api.get<VulnScan[]>("/vulnerabilities/scans"));
  };
  useEffect(() => void refresh().catch((e) => setMsg(e.message)), []);

  const runScan = async () => {
    setBusy(true);
    setMsg(null);
    try {
      const scan = await api.post<VulnScan>("/vulnerabilities/scans", { name: `Scan ${new Date().toISOString().slice(0, 16)}` });
      const done = await api.post<VulnScan>(`/vulnerabilities/scans/${scan.id}/run`);
      setMsg(`Scan complete: ${done.summary?.total_findings ?? 0} findings.`);
      await refresh();
    } catch (e) {
      setMsg(e instanceof Error ? e.message : "Scan failed");
    } finally {
      setBusy(false);
    }
  };

  const triage = async (f: Finding, status: string) => {
    await api.patch(`/vulnerabilities/findings/${f.id}`, { status });
    await refresh();
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="flex items-center gap-2 text-2xl font-semibold">
          <Bug className="h-6 w-6 text-primary" /> Vulnerability Scanner
        </h1>
        <Button onClick={runScan} disabled={busy}>
          <Play className="h-4 w-4" /> {busy ? "Scanning…" : "Run scan (all assets)"}
        </Button>
      </div>
      {msg && <p className="text-sm text-muted-foreground">{msg}</p>}

      <Card>
        <CardHeader><CardTitle>Findings ({findings.length})</CardTitle></CardHeader>
        <CardContent>
          <table className="w-full text-sm">
            <thead className="text-left text-muted-foreground">
              <tr><th className="pb-2">CVE</th><th className="pb-2">Severity</th><th className="pb-2">CVSS</th>
                <th className="pb-2">Software</th><th className="pb-2">Fix</th><th className="pb-2">Status</th><th /></tr>
            </thead>
            <tbody>
              {findings.map((f) => (
                <tr key={f.id} className="border-t border-border/50">
                  <td className="py-2 font-medium">{f.cve_id}</td>
                  <td className="py-2"><Badge variant={sevVariant(f.severity)}>{f.severity}</Badge></td>
                  <td className="py-2">{f.cvss_score ?? "—"}</td>
                  <td className="py-2">{f.affected_software} {f.affected_version}</td>
                  <td className="py-2 text-muted-foreground">{f.fixed_version ?? "—"}</td>
                  <td className="py-2">{f.status}</td>
                  <td className="py-2 text-right">
                    {f.status === "open" && (
                      <Button size="sm" variant="outline" onClick={() => triage(f, "remediated")}>
                        Mark remediated
                      </Button>
                    )}
                  </td>
                </tr>
              ))}
              {findings.length === 0 && (
                <tr><td colSpan={7} className="py-3 text-center text-muted-foreground">
                  No findings. Add assets with software, then run a scan.
                </td></tr>
              )}
            </tbody>
          </table>
        </CardContent>
      </Card>

      <Card>
        <CardHeader><CardTitle>Scan history</CardTitle></CardHeader>
        <CardContent className="space-y-1 text-sm">
          {scans.map((s) => (
            <div key={s.id} className="flex justify-between border-b border-border/50 py-1.5">
              <span>{s.name}</span>
              <span className="text-muted-foreground">
                {s.status} · {s.summary?.total_findings ?? 0} findings
              </span>
            </div>
          ))}
          {scans.length === 0 && <p className="text-muted-foreground">No scans yet</p>}
        </CardContent>
      </Card>
    </div>
  );
}
