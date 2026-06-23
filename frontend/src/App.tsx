import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { Layout } from "@/components/Layout";
import { AuthProvider, useAuth } from "@/context/AuthContext";
import { AuditLog } from "@/pages/AuditLog";
import { Compliance } from "@/pages/Compliance";
import { Dashboard } from "@/pages/Dashboard";
import { Files } from "@/pages/Files";
import { Login } from "@/pages/Login";
import type { ReactNode } from "react";

function Protected({ children }: { children: ReactNode }) {
  const { user, loading } = useAuth();
  if (loading) return <div className="p-8 text-muted-foreground">Loading…</div>;
  return user ? <>{children}</> : <Navigate to="/login" replace />;
}

export default function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route
            element={
              <Protected>
                <Layout />
              </Protected>
            }
          >
            <Route path="/" element={<Dashboard />} />
            <Route path="/files" element={<Files />} />
            <Route path="/audit" element={<AuditLog />} />
            <Route path="/compliance" element={<Compliance />} />
          </Route>
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  );
}
