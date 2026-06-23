import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import { api, clearTokens, isAuthenticated } from "@/lib/api";
import type { User } from "@/lib/types";

interface AuthState {
  user: User | null;
  loading: boolean;
  login: (identifier: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  hasPermission: (code: string) => boolean;
}

const AuthContext = createContext<AuthState | undefined>(undefined);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    (async () => {
      if (isAuthenticated()) {
        try {
          setUser(await api.get<User>("/auth/me"));
        } catch {
          clearTokens();
        }
      }
      setLoading(false);
    })();
  }, []);

  const login = async (identifier: string, password: string) => {
    await api.login(identifier, password);
    setUser(await api.get<User>("/auth/me"));
  };

  const logout = async () => {
    await api.logout();
    setUser(null);
  };

  const hasPermission = (code: string) =>
    !!user && (user.is_superuser || user.permissions.includes("system:admin") || user.permissions.includes(code));

  return (
    <AuthContext.Provider value={{ user, loading, login, logout, hasPermission }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}
