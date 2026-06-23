import { FileText } from "lucide-react";
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
import type { ComplianceReport } from "@/lib/types";

const FRAMEWORKS = [
  { value: "owasp_asvs", label: "OWASP ASVS" },
  { value: "nist_csf", label: "NIST CSF" },
  { value: "nist_crypto", label: "NIST Crypto" },
  { value: "iso_27001", label: "ISO 27001" },
];

export function Compliance() {
  const [reports, setReports] = useState<ComplianceReport[]>([]);
  const [framework, setFramework] = useState("owasp_asvs");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const refresh = () =>
    api.get<ComplianceReport[]>("/compliance/reports").then(setReports).catch((e) => setError(e.message));
  useEffect(() => void refresh(), []);

  const generate = async () => {
    setBusy(true);
    setError(null);
    try {
      await api.post("/compliance/reports", { framework });
      await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Generation failed");
    } finally {
      setBusy(false);
    }
  };

  const scoreVariant = (s: number | null) =>
    s == null ? "muted" : s >= 90 ? "success" : s >= 70 ? "warning" : "destructive";

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold">Compliance</h1>

      <Card>
        <CardHeader><CardTitle>Generate report</CardTitle></CardHeader>
        <CardContent className="flex flex-wrap items-center gap-3">
          <div className="w-52">
            <Select value={framework} onValueChange={setFramework}>
              <SelectTrigger aria-label="Compliance framework">
                <SelectValue placeholder="Framework" />
              </SelectTrigger>
              <SelectContent>
                {FRAMEWORKS.map((f) => (
                  <SelectItem key={f.value} value={f.value}>{f.label}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <Button onClick={generate} disabled={busy}>
            <FileText className="h-4 w-4" /> {busy ? "Evaluating…" : "Generate"}
          </Button>
          {error && <span className="text-sm text-destructive">{error}</span>}
        </CardContent>
      </Card>

      <Card>
        <CardHeader><CardTitle>Reports</CardTitle></CardHeader>
        <CardContent>
          <table className="w-full text-sm">
            <thead className="text-left text-muted-foreground">
              <tr><th className="pb-2">Title</th><th className="pb-2">Framework</th><th className="pb-2">Score</th><th className="pb-2">Generated</th></tr>
            </thead>
            <tbody>
              {reports.map((r) => (
                <tr key={r.id} className="border-t border-border/50">
                  <td className="py-2 font-medium">{r.title}</td>
                  <td className="py-2">{r.framework}</td>
                  <td className="py-2"><Badge variant={scoreVariant(r.score)}>{r.score ?? "—"}%</Badge></td>
                  <td className="py-2 text-muted-foreground">{r.created_at}</td>
                </tr>
              ))}
              {reports.length === 0 && (
                <tr><td colSpan={4} className="py-3 text-center text-muted-foreground">No reports yet</td></tr>
              )}
            </tbody>
          </table>
        </CardContent>
      </Card>
    </div>
  );
}
