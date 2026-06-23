"""Security: keys, audit, alerts, dashboard, compliance schemas."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict

from app.core.enums import (
    AlertSeverity,
    AlertStatus,
    AlertType,
    AuditEventType,
    AuditOutcome,
    ComplianceFramework,
    KeyStatus,
    KeyType,
)


class KeyResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    key_type: KeyType
    purpose: str | None = None
    provider: str
    master_key_id: str
    algorithm: str
    version: int
    status: KeyStatus
    created_at: datetime
    rotated_at: datetime | None = None
    revoked_at: datetime | None = None
    # NOTE: wrapped_key is deliberately NEVER serialized to clients.


class AuditLogResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    seq: int
    id: uuid.UUID
    event_type: AuditEventType
    outcome: AuditOutcome
    actor_label: str | None = None
    resource_type: str | None = None
    resource_id: str | None = None
    action: str | None = None
    ip_address: str | None = None
    created_at: datetime
    entry_hash: str


class ChainVerificationResponse(BaseModel):
    ok: bool
    entries_checked: int
    first_broken_seq: int | None = None
    detail: str


class AlertResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    alert_type: AlertType
    severity: AlertSeverity
    status: AlertStatus
    title: str
    description: str | None = None
    related_file_id: uuid.UUID | None = None
    created_at: datetime


class DashboardResponse(BaseModel):
    encrypted_files: int
    total_files: int
    quarantined_files: int
    integrity_violations: int
    failed_decryptions: int
    key_rotations: int
    storage_usage_bytes: int
    open_alerts: int
    critical_alerts: int
    encryption_health_score: float
    recent_events: list[dict[str, Any]]


class GenerateReportRequest(BaseModel):
    framework: ComplianceFramework


class ComplianceReportResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    framework: ComplianceFramework
    title: str
    score: float | None = None
    summary: dict[str, Any] | None = None
    content: dict[str, Any] | None = None
    created_at: datetime
