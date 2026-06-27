import {
  Bell,
  Building2,
  Car,
  DoorClosed,
  FolderLock,
  Megaphone,
  Network,
  Radar,
  ScanFace,
  ShieldAlert,
  ToggleLeft,
  UserCheck,
  Users2,
  Video,
  Workflow,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { ResourcePage, statusCell, type Row } from "@/components/ResourcePage";
import { api } from "@/lib/api";

const sitesRef = (key = "site_id", label = "Site") => ({
  key, label, optionsFrom: { path: (o: string) => `/sites?organization_id=${o}`, label: (r: Row) => String(r.name) },
});

// ── Organization & estate ───────────────────────────────────────
export const Organizations = () =>
  ResourcePage({
    title: "Organizations", icon: Building2, description: "Multi-tenant companies on the platform.",
    list: () => "/organizations", create: "/organizations", createLabel: "Add organization",
    columns: [
      { key: "name", label: "Name" }, { key: "slug", label: "Slug" },
      { key: "plan", label: "Plan" }, { key: "status", label: "Status", render: statusCell("status") },
    ],
    fields: [
      { key: "name", label: "Name", required: true, span: 2 },
      { key: "slug", label: "Slug (a-z0-9-)" },
      { key: "plan", label: "Plan", type: "select", options: ["trial", "starter", "professional", "enterprise"] },
    ],
  });

export const Sites = () =>
  ResourcePage({
    title: "Sites", icon: Building2, injectOrg: true,
    description: "Physical locations, buildings, zones, and checkpoints.",
    list: (o) => `/sites?organization_id=${o}`, create: "/sites", createLabel: "Add site",
    columns: [
      { key: "name", label: "Name" }, { key: "site_type", label: "Type" },
      { key: "status", label: "Status", render: statusCell("status") },
      { key: "city", label: "City" }, { key: "country", label: "Country" },
    ],
    fields: [
      { key: "name", label: "Name", required: true, span: 2 },
      { key: "code", label: "Code" },
      { key: "site_type", label: "Type", type: "select",
        options: ["office", "warehouse", "retail", "datacenter", "residential", "industrial", "campus", "hospital", "bank", "other"] },
      { key: "city", label: "City" }, { key: "country", label: "Country" },
      { key: "latitude", label: "Latitude", type: "number" },
      { key: "longitude", label: "Longitude", type: "number" },
    ],
  });

export const Zones = () =>
  ResourcePage({
    title: "Zones", icon: ShieldAlert, injectOrg: true,
    description: "Security zones within sites (restricted, perimeter, server room…).",
    list: (o) => `/sites/zones/list?organization_id=${o}`, create: "/sites/zones", createLabel: "Add zone",
    columns: [
      { key: "name", label: "Name" }, { key: "zone_type", label: "Type" },
      { key: "is_restricted", label: "Restricted", render: (r) => (r.is_restricted ? "Yes" : "No") },
    ],
    fields: [
      { key: "name", label: "Name", required: true, span: 2 },
      sitesRef(),
      { key: "zone_type", label: "Type", type: "select",
        options: ["general", "restricted", "perimeter", "entrance", "parking", "server_room", "emergency_exit", "high_security", "other"] },
      { key: "is_restricted", label: "Restricted", type: "checkbox" },
    ],
  });

// ── Physical security ───────────────────────────────────────────
export const Cameras = () =>
  ResourcePage({
    title: "Cameras", icon: Video, injectOrg: true,
    description: "Camera registry, RTSP config, recording state, and health.",
    list: (o) => `/cameras?organization_id=${o}`, create: "/cameras", createLabel: "Add camera",
    columns: [
      { key: "name", label: "Name" },
      { key: "status", label: "Status", render: statusCell("status") },
      { key: "is_recording", label: "Recording", render: (r) => (r.is_recording ? "● REC" : "—") },
      { key: "manufacturer", label: "Vendor" },
    ],
    fields: [
      { key: "name", label: "Name", required: true, span: 2 },
      sitesRef(),
      { key: "rtsp_url", label: "RTSP URL", span: 2 },
      { key: "manufacturer", label: "Manufacturer" },
      { key: "stream_quality", label: "Quality", type: "select", options: ["high", "medium", "low"] },
    ],
    rowActions: (row, reload) => (
      <>
        <Button size="sm" variant="outline"
          onClick={async () => { await api.post(`/cameras/${row.id}/heartbeat`, { online: true, recording: true }); reload(); }}>
          Online
        </Button>
        <Button size="sm" variant="outline"
          onClick={async () => { await api.post(`/cameras/${row.id}/heartbeat`, { online: false }); reload(); }}>
          Offline
        </Button>
      </>
    ),
  });

export const Guards = () =>
  ResourcePage({
    title: "Guards", icon: UserCheck, injectOrg: true,
    description: "Guard workforce, shifts, and live positions.",
    list: (o) => `/guards?organization_id=${o}`, create: "/guards", createLabel: "Add guard",
    columns: [
      { key: "employee_code", label: "Code" }, { key: "full_name", label: "Name" },
      { key: "status", label: "Status", render: statusCell("status") }, { key: "shift", label: "Shift" },
    ],
    fields: [
      { key: "employee_code", label: "Employee code", required: true },
      { key: "full_name", label: "Full name", required: true, span: 2 },
      { key: "phone", label: "Phone" },
      { key: "rank", label: "Rank" },
      { key: "shift", label: "Shift", type: "select", options: ["day", "night", "rotating"] },
      sitesRef(),
    ],
  });

export const Patrols = () =>
  ResourcePage({
    title: "Patrols", icon: Radar, injectOrg: true,
    description: "Scheduled patrol routes with checkpoint scans.",
    list: (o) => `/guards/patrols/list?organization_id=${o}`, create: "/guards/patrols", createLabel: "New patrol",
    columns: [
      { key: "route_name", label: "Route" },
      { key: "status", label: "Status", render: statusCell("status") },
      { key: "scheduled_start", label: "Scheduled", render: (r) => String(r.scheduled_start ?? "—").slice(0, 16) },
    ],
    fields: [
      { key: "route_name", label: "Route name", required: true, span: 2 },
      sitesRef(),
      { key: "guard_id", label: "Guard",
        optionsFrom: { path: (o) => `/guards?organization_id=${o}`, label: (r) => String(r.employee_code) } },
    ],
    rowActions: (row, reload) => (
      <Button size="sm" variant="outline"
        onClick={async () => { await api.post(`/guards/patrols/${row.id}/complete`); reload(); }}>
        Complete
      </Button>
    ),
  });

export const Visitors = () =>
  ResourcePage({
    title: "Visitors", icon: Users2, injectOrg: true,
    description: "Visitor registration, approval, badges, and blacklist enforcement.",
    list: (o) => `/visitors?organization_id=${o}`, create: "/visitors", createLabel: "Register visitor",
    columns: [
      { key: "full_name", label: "Name" }, { key: "company", label: "Company" },
      { key: "host_name", label: "Host" },
      { key: "status", label: "Status", render: statusCell("status") },
      { key: "badge_code", label: "Badge" },
    ],
    fields: [
      { key: "full_name", label: "Full name", required: true, span: 2 },
      { key: "company", label: "Company" }, { key: "host_name", label: "Host" },
      { key: "purpose", label: "Purpose", span: 2 }, { key: "phone", label: "Phone" },
    ],
    rowActions: (row, reload) => (
      <>
        <Button size="sm" variant="outline"
          onClick={async () => { await api.post(`/visitors/${row.id}/status`, { status: "checked_in" }); reload(); }}>
          Check in
        </Button>
        <Button size="sm" variant="outline"
          onClick={async () => { await api.post(`/visitors/${row.id}/status`, { status: "checked_out" }); reload(); }}>
          Out
        </Button>
      </>
    ),
  });

export const Vehicles = () =>
  ResourcePage({
    title: "Vehicles & ANPR", icon: Car, injectOrg: true,
    description: "Vehicle registry and number-plate watchlists.",
    list: (o) => `/vehicles?organization_id=${o}`, create: "/vehicles", createLabel: "Add vehicle",
    columns: [
      { key: "plate", label: "Plate" }, { key: "make", label: "Make" }, { key: "model", label: "Model" },
      { key: "status", label: "Status", render: statusCell("status") },
      { key: "is_watchlisted", label: "Watchlist", render: (r) => (r.is_watchlisted ? "⚠ Yes" : "No") },
    ],
    fields: [
      { key: "plate", label: "Plate", required: true },
      { key: "make", label: "Make" }, { key: "model", label: "Model" }, { key: "color", label: "Color" },
      { key: "is_watchlisted", label: "Watchlisted", type: "checkbox" },
      { key: "watch_reason", label: "Watch reason", span: 2 },
    ],
  });

export const AccessControl = () =>
  ResourcePage({
    title: "Access Control", icon: DoorClosed, injectOrg: true,
    description: "Doors, turnstiles, gates and their lock state.",
    list: (o) => `/access/points?organization_id=${o}`, create: "/access/points", createLabel: "Add access point",
    columns: [
      { key: "name", label: "Name" }, { key: "point_type", label: "Type" }, { key: "method", label: "Method" },
      { key: "is_locked", label: "Locked", render: (r) => (r.is_locked ? "🔒 Locked" : "🔓 Open") },
    ],
    fields: [
      { key: "name", label: "Name", required: true, span: 2 },
      sitesRef(),
      { key: "point_type", label: "Type", type: "select", options: ["door", "turnstile", "gate", "barrier", "elevator"] },
      { key: "method", label: "Method", type: "select", options: ["rfid", "smart_card", "qr", "biometric", "fingerprint", "face", "pin"] },
      { key: "is_locked", label: "Locked", type: "checkbox", default: true },
    ],
  });

// ── AI intelligence ─────────────────────────────────────────────
export const Detections = () =>
  ResourcePage({
    title: "AI Detections", icon: ScanFace, injectOrg: true,
    description: "AI detection events (person/weapon/fire/intrusion…) scored by the risk engine.",
    list: (o) => `/detections?organization_id=${o}`, create: "/detections/ingest", createLabel: "Ingest",
    columns: [
      { key: "detection_type", label: "Type" },
      { key: "severity", label: "Severity", render: statusCell("severity") },
      { key: "confidence", label: "Confidence" },
      { key: "status", label: "Status" },
      { key: "detected_at", label: "When", render: (r) => String(r.detected_at ?? "").slice(0, 16) },
    ],
    fields: [
      { key: "detection_type", label: "Type", type: "select", required: true,
        options: ["person", "weapon", "fire", "smoke", "intrusion", "perimeter_breach", "loitering", "tailgating", "unknown_person", "vehicle", "abandoned_object", "crowd"] },
      { key: "confidence", label: "Confidence 0-1", type: "number", default: 0.9 },
      { key: "camera_id", label: "Camera",
        optionsFrom: { path: (o) => `/cameras?organization_id=${o}`, label: (r) => String(r.name) } },
    ],
  });

export const Threats = () =>
  ResourcePage({
    title: "Threat Intelligence", icon: ShieldAlert,
    description: "Correlated threats with risk scoring; escalate to an incident.",
    list: (o) => `/detections/threats/list?organization_id=${o}`,
    columns: [
      { key: "title", label: "Threat" },
      { key: "risk_level", label: "Risk", render: statusCell("risk_level") },
      { key: "score", label: "Score" },
      { key: "detection_count", label: "Detections" },
      { key: "status", label: "Status", render: statusCell("status") },
    ],
    rowActions: (row, reload) =>
      row.status !== "escalated" ? (
        <Button size="sm" variant="outline"
          onClick={async () => { await api.post(`/detections/threats/${row.id}/escalate`); reload(); }}>
          Escalate
        </Button>
      ) : <span className="text-xs text-muted-foreground">escalated</span>,
  });

// ── SecOps ──────────────────────────────────────────────────────
export const AlertCenter = () =>
  ResourcePage({
    title: "Alert Channels", icon: Bell, injectOrg: true,
    description: "Multi-channel delivery (email/SMS/WhatsApp/push) for alerts & emergencies.",
    list: (o) => `/notifications/channels?organization_id=${o}`, create: "/notifications/channels", createLabel: "Add channel",
    columns: [
      { key: "name", label: "Name" }, { key: "channel", label: "Channel" },
      { key: "target", label: "Target" }, { key: "min_severity", label: "Min severity" },
    ],
    fields: [
      { key: "name", label: "Name", required: true, span: 2 },
      { key: "channel", label: "Channel", type: "select", options: ["email", "sms", "whatsapp", "push", "webhook"] },
      { key: "target", label: "Target (email/phone/url)", span: 2 },
      { key: "min_severity", label: "Min severity", type: "select", options: ["low", "medium", "high", "critical"] },
    ],
  });

export const Evidence = () =>
  ResourcePage({
    title: "Evidence", icon: FolderLock, injectOrg: true,
    description: "Evidence items with SHA-256 integrity and chain of custody.",
    list: (o) => `/evidence?organization_id=${o}`, create: "/evidence", createLabel: "Register evidence",
    columns: [
      { key: "title", label: "Title" }, { key: "evidence_type", label: "Type" },
      { key: "status", label: "Status", render: statusCell("status") },
      { key: "collected_at", label: "Collected", render: (r) => String(r.collected_at ?? "").slice(0, 16) },
    ],
    fields: [
      { key: "title", label: "Title", required: true, span: 2 },
      { key: "evidence_type", label: "Type", type: "select", options: ["video", "image", "document", "audio", "physical", "other"] },
      { key: "source", label: "Source" },
      { key: "sha256", label: "SHA-256 hash", span: 2 },
    ],
  });

// ── Collaboration & automation ──────────────────────────────────
export const Comms = () =>
  ResourcePage({
    title: "Communication", icon: Megaphone, injectOrg: true,
    description: "Broadcast announcements to teams.",
    list: (o) => `/comms/announcements?organization_id=${o}`, create: "/comms/announcements", createLabel: "Announce",
    columns: [
      { key: "title", label: "Title" }, { key: "audience", label: "Audience" },
      { key: "created_at", label: "When", render: (r) => String(r.created_at ?? "").slice(0, 16) },
    ],
    fields: [
      { key: "title", label: "Title", required: true, span: 2 },
      { key: "audience", label: "Audience", type: "select", options: ["all", "guards", "officers", "admins"] },
      { key: "body", label: "Message", required: true, span: 4 },
    ],
  });

export const Workflows = () =>
  ResourcePage({
    title: "Workflow Automation", icon: Workflow, injectOrg: true,
    description: "Trigger rules that auto-notify, create incidents, or escalate.",
    list: (o) => `/workflows/rules?organization_id=${o}`, create: "/workflows/rules", createLabel: "Add rule",
    columns: [
      { key: "name", label: "Rule" }, { key: "trigger", label: "Trigger" }, { key: "action", label: "Action" },
      { key: "is_active", label: "Active", render: (r) => (r.is_active ? "Yes" : "No") },
      { key: "trigger_count", label: "Fired" },
    ],
    fields: [
      { key: "name", label: "Name", required: true, span: 2 },
      { key: "trigger", label: "Trigger", type: "select",
        options: ["detection", "threat", "incident", "cyber_event", "access_denied", "manual"] },
      { key: "action", label: "Action", type: "select", options: ["notify", "create_incident", "escalate", "log"] },
    ],
  });

export const Integrations = () =>
  ResourcePage({
    title: "Integrations", icon: Network, injectOrg: true,
    description: "Connect Slack, SIEM, VMS, ANPR and other systems.",
    list: (o) => `/admin/integrations?organization_id=${o}`, create: "/admin/integrations", createLabel: "Add integration",
    columns: [
      { key: "name", label: "Name" }, { key: "kind", label: "Kind" },
      { key: "status", label: "Status", render: statusCell("status") },
    ],
    fields: [
      { key: "name", label: "Name", required: true, span: 2 },
      { key: "kind", label: "Kind", type: "select",
        options: ["slack", "teams", "email_smtp", "sms_gateway", "siem", "webhook", "vms", "anpr", "access_control"] },
      { key: "secret", label: "Secret / token", span: 2 },
    ],
    rowActions: (row, reload) => (
      <Button size="sm" variant="outline"
        onClick={async () => { await api.post(`/admin/integrations/${row.id}/status`, { active: row.status !== "active" }); reload(); }}>
        {row.status === "active" ? "Disable" : "Enable"}
      </Button>
    ),
  });

export const FeatureFlags = () =>
  ResourcePage({
    title: "Feature Flags & Settings", icon: ToggleLeft, injectOrg: true,
    description: "Toggle platform capabilities per tenant.",
    list: (o) => `/admin/feature-flags?organization_id=${o}`, create: "/admin/feature-flags", createLabel: "Set flag",
    columns: [
      { key: "key", label: "Key" },
      { key: "enabled", label: "Enabled", render: (r) => (r.enabled ? "On" : "Off") },
      { key: "description", label: "Description" },
    ],
    fields: [
      { key: "key", label: "Flag key", required: true, span: 2 },
      { key: "enabled", label: "Enabled", type: "checkbox" },
      { key: "description", label: "Description", span: 2 },
    ],
  });
