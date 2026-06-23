export interface User {
  id: string;
  username: string;
  email: string;
  full_name: string | null;
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
  recent_events: Array<Record<string, unknown>>;
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
