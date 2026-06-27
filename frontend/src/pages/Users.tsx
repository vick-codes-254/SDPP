import { Users as UsersIcon } from "lucide-react";
import { useEffect, useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { api } from "@/lib/api";

interface AdminUser {
  id: string;
  username: string;
  email: string;
  is_active: boolean;
  is_superuser: boolean;
  roles: string[];
}

export function Users() {
  const [users, setUsers] = useState<AdminUser[]>([]);
  const [error, setError] = useState<string | null>(null);

  const refresh = () => api.get<AdminUser[]>("/users").then(setUsers).catch((e) => setError(e.message));
  useEffect(() => void refresh(), []);

  const toggle = async (u: AdminUser) => {
    await api.post(`/users/${u.id}/active`, { active: !u.is_active });
    await refresh();
  };

  return (
    <div className="space-y-6">
      <h1 className="flex items-center gap-2 text-2xl font-semibold">
        <UsersIcon className="h-6 w-6 text-primary" /> User Management
      </h1>
      {error && <p className="text-destructive">{error}</p>}

      <Card>
        <CardHeader><CardTitle>Users ({users.length})</CardTitle></CardHeader>
        <CardContent>
          <table className="w-full text-sm">
            <thead className="text-left text-muted-foreground">
              <tr><th className="pb-2">Username</th><th className="pb-2">Email</th><th className="pb-2">Roles</th>
                <th className="pb-2">Active</th><th className="pb-2 text-right">Action</th></tr>
            </thead>
            <tbody>
              {users.map((u) => (
                <tr key={u.id} className="border-t border-border/50">
                  <td className="py-2 font-medium">
                    {u.username}{u.is_superuser && <Badge variant="warning" className="ml-2">admin</Badge>}
                  </td>
                  <td className="py-2 text-muted-foreground">{u.email}</td>
                  <td className="py-2">
                    <div className="flex flex-wrap gap-1">
                      {u.roles.length
                        ? u.roles.map((r) => <Badge key={r} variant="muted">{r}</Badge>)
                        : <span className="text-muted-foreground">none</span>}
                    </div>
                  </td>
                  <td className="py-2">
                    <Badge variant={u.is_active ? "success" : "destructive"}>
                      {u.is_active ? "active" : "disabled"}
                    </Badge>
                  </td>
                  <td className="py-2 text-right">
                    <Button size="sm" variant="outline" disabled={u.is_superuser} onClick={() => toggle(u)}>
                      {u.is_active ? "Disable" : "Enable"}
                    </Button>
                  </td>
                </tr>
              ))}
              {users.length === 0 && (
                <tr><td colSpan={5} className="py-3 text-center text-muted-foreground">No users</td></tr>
              )}
            </tbody>
          </table>
        </CardContent>
      </Card>
    </div>
  );
}
