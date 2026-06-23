import { Download, ShieldCheck, Trash2, Upload } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { api } from "@/lib/api";
import type { FileItem } from "@/lib/types";
import { formatBytes } from "@/lib/utils";

const CATEGORIES = ["evidence", "document", "image", "video", "audio", "pdf", "backup", "log", "other"];

export function Files() {
  const [files, setFiles] = useState<FileItem[]>([]);
  const [category, setCategory] = useState("evidence");
  const [message, setMessage] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  const refresh = () => api.get<FileItem[]>("/files").then(setFiles).catch((e) => setMessage(e.message));
  useEffect(() => void refresh(), []);

  const onUpload = async (file: File) => {
    setBusy(true);
    setMessage(null);
    try {
      await api.upload("/files", file, { category });
      setMessage(`Encrypted and stored "${file.name}".`);
      await refresh();
    } catch (e) {
      setMessage(e instanceof Error ? e.message : "Upload failed");
    } finally {
      setBusy(false);
      if (inputRef.current) inputRef.current.value = "";
    }
  };

  const onDownload = async (f: FileItem) => {
    try {
      const blob = await api.download(`/files/${f.id}/download`);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = f.original_filename;
      a.click();
      URL.revokeObjectURL(url);
    } catch (e) {
      setMessage(e instanceof Error ? e.message : "Download failed");
    }
  };

  const onVerify = async (f: FileItem) => {
    try {
      const r = await api.post<{ result: string }>(`/files/${f.id}/verify-integrity`);
      setMessage(`Integrity for "${f.original_filename}": ${r.result.toUpperCase()}`);
    } catch (e) {
      setMessage(e instanceof Error ? e.message : "Verification failed");
      await refresh();
    }
  };

  const onDelete = async (f: FileItem, secure: boolean) => {
    if (!confirm(secure ? "Crypto-shred this file? This is irreversible." : "Delete this file?")) return;
    try {
      await api.del(`/files/${f.id}${secure ? "?secure=true" : ""}`);
      await refresh();
    } catch (e) {
      setMessage(e instanceof Error ? e.message : "Delete failed");
    }
  };

  const statusVariant = (s: string) =>
    s === "available" ? "success" : s === "quarantined" ? "destructive" : "muted";

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold">Secure File Vault</h1>

      <Card>
        <CardHeader><CardTitle>Upload &amp; encrypt</CardTitle></CardHeader>
        <CardContent className="flex flex-wrap items-center gap-3">
          <select
            className="h-9 rounded-md border border-input bg-transparent px-3 text-sm"
            value={category}
            onChange={(e) => setCategory(e.target.value)}
          >
            {CATEGORIES.map((c) => <option key={c} value={c}>{c}</option>)}
          </select>
          <input
            ref={inputRef}
            type="file"
            className="hidden"
            onChange={(e) => e.target.files?.[0] && onUpload(e.target.files[0])}
          />
          <Button onClick={() => inputRef.current?.click()} disabled={busy}>
            <Upload className="h-4 w-4" /> {busy ? "Encrypting…" : "Choose file"}
          </Button>
          {message && <span className="text-sm text-muted-foreground">{message}</span>}
        </CardContent>
      </Card>

      <Card>
        <CardHeader><CardTitle>Stored files</CardTitle></CardHeader>
        <CardContent>
          <table className="w-full text-sm">
            <thead className="text-left text-muted-foreground">
              <tr>
                <th className="pb-2">Name</th><th className="pb-2">Category</th>
                <th className="pb-2">Size</th><th className="pb-2">Status</th>
                <th className="pb-2 text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {files.map((f) => (
                <tr key={f.id} className="border-t border-border/50">
                  <td className="py-2 font-medium">{f.original_filename}</td>
                  <td className="py-2">{f.category}</td>
                  <td className="py-2">{formatBytes(f.size_bytes)}</td>
                  <td className="py-2"><Badge variant={statusVariant(f.status)}>{f.status}</Badge></td>
                  <td className="py-2">
                    <div className="flex justify-end gap-1">
                      <Button size="icon" variant="ghost" title="Download" onClick={() => onDownload(f)}>
                        <Download className="h-4 w-4" />
                      </Button>
                      <Button size="icon" variant="ghost" title="Verify integrity" onClick={() => onVerify(f)}>
                        <ShieldCheck className="h-4 w-4" />
                      </Button>
                      <Button size="icon" variant="ghost" title="Crypto-shred" onClick={() => onDelete(f, true)}>
                        <Trash2 className="h-4 w-4 text-destructive" />
                      </Button>
                    </div>
                  </td>
                </tr>
              ))}
              {files.length === 0 && (
                <tr><td colSpan={5} className="py-3 text-center text-muted-foreground">No files yet</td></tr>
              )}
            </tbody>
          </table>
        </CardContent>
      </Card>
    </div>
  );
}
