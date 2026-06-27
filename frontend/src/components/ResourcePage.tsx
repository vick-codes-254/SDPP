import { Plus } from "lucide-react";
import { useEffect, useMemo, useState, type ComponentType, type ReactNode } from "react";
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
import { useAuth } from "@/context/AuthContext";
import { api } from "@/lib/api";

export type Row = Record<string, unknown>;

export interface Column {
  key: string;
  label: string;
  render?: (row: Row) => ReactNode;
}

export interface Field {
  key: string;
  label: string;
  type?: "text" | "number" | "select" | "checkbox";
  options?: string[];
  /** Populate a select from a list endpoint (value=id, label from row). */
  optionsFrom?: { path: (orgId: string) => string; label: (row: Row) => string };
  required?: boolean;
  placeholder?: string;
  default?: string | number | boolean;
  span?: number; // grid columns to span
}

export interface ResourceConfig {
  title: string;
  icon?: ComponentType<{ className?: string }>;
  description?: string;
  list: (orgId: string) => string;
  create?: string;
  createLabel?: string;
  /** Add organization_id to the create body. */
  injectOrg?: boolean;
  columns: Column[];
  fields?: Field[];
  rowActions?: (row: Row, reload: () => void) => ReactNode;
  emptyText?: string;
}

const badge = (value: string) => {
  const v = value?.toLowerCase?.() ?? "";
  if (["critical", "failed", "offline", "blacklisted", "denied", "open", "active", "overdue"].includes(v))
    return "destructive";
  if (["high", "watchlisted", "degraded", "pending_approval", "pending", "sent"].includes(v)) return "warning";
  if (["online", "completed", "resolved", "paid", "checked_in", "granted", "delivered"].includes(v))
    return "success";
  return "muted";
};

export function statusCell(key: string): Column["render"] {
  return (row) => <Badge variant={badge(String(row[key] ?? "")) as never}>{String(row[key] ?? "—")}</Badge>;
}

export function ResourcePage(cfg: ResourceConfig) {
  const { user } = useAuth();
  const orgId = (user?.organization_id as string | undefined) ?? "";
  const [rows, setRows] = useState<Row[]>([]);
  const [msg, setMsg] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [refOpts, setRefOpts] = useState<Record<string, { value: string; label: string }[]>>({});

  const initialForm = useMemo(() => {
    const f: Record<string, unknown> = {};
    for (const fld of cfg.fields ?? []) f[fld.key] = fld.default ?? (fld.type === "checkbox" ? false : "");
    return f;
  }, [cfg.fields]);
  const [form, setForm] = useState<Record<string, unknown>>(initialForm);

  const reload = () => {
    api.get<Row[]>(cfg.list(orgId)).then(setRows).catch((e) => setMsg(e.message));
  };

  useEffect(() => {
    reload();
    // Load ref dropdowns.
    for (const fld of cfg.fields ?? []) {
      if (fld.optionsFrom) {
        const ff = fld;
        api
          .get<Row[]>(ff.optionsFrom!.path(orgId))
          .then((data) =>
            setRefOpts((p) => ({
              ...p,
              [ff.key]: data.map((r) => ({ value: String(r.id), label: ff.optionsFrom!.label(r) })),
            })),
          )
          .catch(() => undefined);
      }
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [cfg.title, orgId]);

  const submit = async () => {
    if (!cfg.create) return;
    setBusy(true);
    setMsg(null);
    try {
      const body: Record<string, unknown> = {};
      for (const fld of cfg.fields ?? []) {
        const v = form[fld.key];
        if (v === "" || v === undefined || v === null) continue;
        body[fld.key] = fld.type === "number" ? Number(v) : v;
      }
      if (cfg.injectOrg) body.organization_id = orgId;
      await api.post(cfg.create, body);
      setForm(initialForm);
      setMsg("Created.");
      reload();
    } catch (e) {
      setMsg(e instanceof Error ? e.message : "Create failed");
    } finally {
      setBusy(false);
    }
  };

  const Icon = cfg.icon;
  return (
    <div className="space-y-6">
      <div>
        <h1 className="flex items-center gap-2 text-2xl font-semibold">
          {Icon && <Icon className="h-6 w-6 text-primary" />} {cfg.title}
        </h1>
        {cfg.description && <p className="mt-1 text-sm text-muted-foreground">{cfg.description}</p>}
      </div>

      {cfg.create && cfg.fields && (
        <Card>
          <CardHeader><CardTitle>{cfg.createLabel ?? "Create"}</CardTitle></CardHeader>
          <CardContent className="grid gap-3 md:grid-cols-4">
            {cfg.fields.map((fld) => {
              const opts = fld.optionsFrom ? refOpts[fld.key] ?? [] : null;
              const spanStyle = fld.span ? { gridColumn: `span ${fld.span}` } : undefined;
              if (fld.type === "checkbox") {
                return (
                  <label key={fld.key} className="flex items-center gap-2 text-sm" style={spanStyle}>
                    <input
                      type="checkbox"
                      checked={Boolean(form[fld.key])}
                      onChange={(e) => setForm({ ...form, [fld.key]: e.target.checked })}
                    />
                    {fld.label}
                  </label>
                );
              }
              if (fld.type === "select" || opts) {
                const choices = opts ?? (fld.options ?? []).map((o) => ({ value: o, label: o }));
                return (
                  <div key={fld.key} style={spanStyle}>
                    <Select
                      value={String(form[fld.key] ?? "")}
                      onValueChange={(v) => setForm({ ...form, [fld.key]: v })}
                    >
                      <SelectTrigger><SelectValue placeholder={fld.label} /></SelectTrigger>
                      <SelectContent>
                        {choices.map((c) => (
                          <SelectItem key={c.value} value={c.value}>{c.label}</SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                );
              }
              return (
                <input
                  key={fld.key}
                  className="field"
                  style={spanStyle}
                  type={fld.type === "number" ? "number" : "text"}
                  placeholder={fld.placeholder ?? fld.label}
                  value={String(form[fld.key] ?? "")}
                  onChange={(e) => setForm({ ...form, [fld.key]: e.target.value })}
                />
              );
            })}
            <Button onClick={submit} disabled={busy} className="md:col-span-1">
              <Plus className="h-4 w-4" /> {cfg.createLabel ?? "Create"}
            </Button>
            {msg && <span className="text-sm text-muted-foreground md:col-span-4">{msg}</span>}
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader><CardTitle>{cfg.title} ({rows.length})</CardTitle></CardHeader>
        <CardContent className="overflow-x-auto p-0">
          <table className="data-table">
            <thead>
              <tr>
                {cfg.columns.map((c) => <th key={c.key}>{c.label}</th>)}
                {cfg.rowActions && <th className="text-right">Actions</th>}
              </tr>
            </thead>
            <tbody>
              {rows.map((row, i) => (
                <tr key={(row.id as string) ?? i}>
                  {cfg.columns.map((c) => (
                    <td key={c.key}>
                      {c.render ? c.render(row) : String(row[c.key] ?? "—")}
                    </td>
                  ))}
                  {cfg.rowActions && (
                    <td className="text-right">
                      <div className="flex justify-end gap-2">{cfg.rowActions(row, reload)}</div>
                    </td>
                  )}
                </tr>
              ))}
              {rows.length === 0 && (
                <tr>
                  <td colSpan={cfg.columns.length + 1} className="py-8 text-center text-muted-foreground">
                    {cfg.emptyText ?? "No records yet"}
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
