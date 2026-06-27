export interface User {
  id: string;
  username: string;
  email: string;
  full_name: string | null;
  organization_id: string | null;
  is_active: boolean;
  is_superuser: boolean;
  permissions: string[];
}

export interface FileItem {
  id: string;
  owner_id: string;
  original_filename: string;
  content_type: string;
  size_bytes: number;
  category: string;
  status: string;
  plaintext_sha256: string | null;
  created_at: string;
}

export interface Dashboard {
  encrypted_files: number;
  total_files: number;
  quarantined_files: number;
  integrity_violations: number;
  failed_decryptions: number;
  key_rotations: number;
  storage_usage_bytes: number;
  open_alerts: number;
  critical_alerts: number;
  encryption_health_score: number;
  total_assets: number;
  assets_by_criticality: Record<string, number>;
  open_vulnerabilities: number;
  vulns_by_severity: Record<string, number>;
  open_incidents: number;
  discovery_scans: number;
  vuln_scans: number;
  recent_events: Array<Record<string, unknown>>;
}

export interface Asset {
  id: string;
  name: string;
  asset_type: string;
  hostname: string | null;
  ip_address: string | null;
  operating_system: string | null;
  criticality: string;
  environment: string;
  status: string;
  tags: string[] | null;
  created_at: string;
  software: { name: string; version: string | null; vendor: string | null }[];
}

export interface VulnScan {
  id: string;
  name: string;
  status: string;
  summary: { total_findings?: number; by_severity?: Record<string, number> } | null;
  created_at: string;
}

export interface Finding {
  id: string;
  scan_id: string;
  asset_id: string;
  cve_id: string;
  title: string;
  severity: string;
  cvss_score: number | null;
  affected_software: string | null;
  affected_version: string | null;
  fixed_version: string | null;
  status: string;
}

export interface Incident {
  id: string;
  title: string;
  description: string | null;
  severity: string;
  status: string;
  assignee_id: string | null;
  created_at: string;
}

export interface IncidentNote {
  id: string;
  note_type: string;
  body: string;
  created_at: string;
}

export interface DiscoveryScan {
  id: string;
  name: string;
  targets: string[];
  ports: number[];
  status: string;
  hosts_found: number;
  created_at: string;
}

export interface SecurityAlert {
  id: string;
  alert_type: string;
  severity: string;
  status: string;
  title: string;
  created_at: string;
}

export interface AuditEntry {
  seq: number;
  event_type: string;
  outcome: string;
  actor_label: string | null;
  action: string | null;
  resource_id: string | null;
  created_at: string;
  entry_hash: string;
}

export interface ComplianceReport {
  id: string;
  framework: string;
  title: string;
  score: number | null;
  summary: Record<string, unknown> | null;
  created_at: string;
}
