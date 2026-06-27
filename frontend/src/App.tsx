import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { Layout } from "@/components/Layout";
import { AuthProvider, useAuth } from "@/context/AuthContext";
import { Assets } from "@/pages/Assets";
import { AuditLog } from "@/pages/AuditLog";
import { AnalyticsBI } from "@/pages/Analytics";
import { LiveWall } from "@/pages/LiveWall";
import {
  Analytics,
  Billing,
  DetectionsTriage,
  Emergency,
  ExecutiveDashboard,
  LiveMonitoring,
  SOC,
} from "@/pages/bespoke";
import { Compliance } from "@/pages/Compliance";
import { Discovery } from "@/pages/Discovery";
import { Files } from "@/pages/Files";
import { Incidents } from "@/pages/Incidents";
import { Login } from "@/pages/Login";
import { MissionControl } from "@/pages/MissionControl";
import { ThreatCenter } from "@/pages/ThreatCenter";
import {
  AccessControl,
  AlertCenter,
  Cameras,
  Comms,
  Evidence,
  FeatureFlags,
  Guards,
  Integrations,
  Organizations,
  Patrols,
  Sites,
  Threats,
  Vehicles,
  Visitors,
  Workflows,
  Zones,
} from "@/pages/modules";
import { Users } from "@/pages/Users";
import { Vulnerabilities } from "@/pages/Vulnerabilities";
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
            <Route path="/" element={<MissionControl />} />
            <Route path="/overview" element={<ExecutiveDashboard />} />
            {/* Security operations */}
            <Route path="/live" element={<LiveWall />} />
            <Route path="/live/legacy" element={<LiveMonitoring />} />
            <Route path="/threats" element={<ThreatCenter />} />
            <Route path="/threats/intel" element={<Threats />} />
            <Route path="/incidents" element={<Incidents />} />
            <Route path="/alerts" element={<AlertCenter />} />
            <Route path="/emergency" element={<Emergency />} />
            {/* AI intelligence */}
            <Route path="/detections" element={<DetectionsTriage />} />
            <Route path="/analytics" element={<AnalyticsBI />} />
            <Route path="/analytics/legacy" element={<Analytics />} />
            {/* Physical security */}
            <Route path="/sites" element={<Sites />} />
            <Route path="/zones" element={<Zones />} />
            <Route path="/cameras" element={<Cameras />} />
            <Route path="/access" element={<AccessControl />} />
            <Route path="/visitors" element={<Visitors />} />
            <Route path="/vehicles" element={<Vehicles />} />
            <Route path="/patrols" element={<Patrols />} />
            <Route path="/guards" element={<Guards />} />
            {/* Cyber security */}
            <Route path="/soc" element={<SOC />} />
            <Route path="/assets" element={<Assets />} />
            <Route path="/discovery" element={<Discovery />} />
            <Route path="/vulnerabilities" element={<Vulnerabilities />} />
            <Route path="/audit" element={<AuditLog />} />
            {/* Encryption & security */}
            <Route path="/files" element={<Files />} />
            <Route path="/evidence" element={<Evidence />} />
            <Route path="/compliance" element={<Compliance />} />
            {/* Administration */}
            <Route path="/organizations" element={<Organizations />} />
            <Route path="/users" element={<Users />} />
            <Route path="/billing" element={<Billing />} />
            <Route path="/workflows" element={<Workflows />} />
            <Route path="/comms" element={<Comms />} />
            <Route path="/integrations" element={<Integrations />} />
            <Route path="/settings" element={<FeatureFlags />} />
          </Route>
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  );
}
