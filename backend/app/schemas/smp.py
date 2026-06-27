"""Security Monitoring Platform request/response schemas."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.core.enums import (
    AlertRuleType,
    AlertSeverity,
    AssetCriticality,
    AssetEnvironment,
    AssetStatus,
    AssetType,
    IncidentSeverity,
    IncidentStatus,
    ScanStatus,
    VulnSeverity,
    VulnStatus,
)


# ── Assets ──────────────────────────────────────────────────────
class SoftwareSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    name: str
    version: str | None = None
    vendor: str | None = None


class AssetCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    asset_type: AssetType = AssetType.host
    hostname: str | None = None
    ip_address: str | None = None
    mac_address: str | None = None
    operating_system: str | None = None
    os_version: str | None = None
    criticality: AssetCriticality = AssetCriticality.medium
    owner: str | None = None
    location: str | None = None
    tags: list[str] = []
    notes: str | None = None
    software: list[SoftwareSchema] = []


class AssetUpdate(BaseModel):
    name: str | None = None
    asset_type: AssetType | None = None
    hostname: str | None = None
    ip_address: str | None = None
    mac_address: str | None = None
    operating_system: str | None = None
    os_version: str | None = None
    criticality: AssetCriticality | None = None
    owner: str | None = None
    location: str | None = None
    tags: list[str] | None = None
    notes: str | None = None


class AssetResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    name: str
    asset_type: AssetType
    hostname: str | None = None
    ip_address: str | None = None
    mac_address: str | None = None
    operating_system: str | None = None
    os_version: str | None = None
    criticality: AssetCriticality
    environment: AssetEnvironment
    status: AssetStatus
    owner: str | None = None
    location: str | None = None
    tags: list[str] | None = None
    last_seen_at: datetime | None = None
    created_at: datetime
    software: list[SoftwareSchema] = []


# ── Network discovery ───────────────────────────────────────────
class DiscoveryScanCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    targets: list[str] = Field(min_length=1)
    ports: list[int] | None = None


class DiscoveryScanResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    name: str
    targets: list[str]
    ports: list[int]
    status: ScanStatus
    hosts_found: int
    summary: dict[str, Any] | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    created_at: datetime


class DiscoveredHostResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    ip_address: str
    hostname: str | None = None
    open_ports: list[int] | None = None
    latency_ms: float | None = None
    asset_id: uuid.UUID | None = None


# ── Vulnerabilities ─────────────────────────────────────────────
class VulnScanCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    asset_ids: list[uuid.UUID] | None = None


class VulnScanResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    name: str
    status: ScanStatus
    summary: dict[str, Any] | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    created_at: datetime


class FindingResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    scan_id: uuid.UUID
    asset_id: uuid.UUID
    cve_id: str
    title: str
    description: str | None = None
    severity: VulnSeverity
    cvss_score: float | None = None
    affected_software: str | None = None
    affected_version: str | None = None
    fixed_version: str | None = None
    remediation: str | None = None
    status: VulnStatus
    references: list[str] | None = None


class FindingStatusUpdate(BaseModel):
    status: VulnStatus


# ── Incidents ───────────────────────────────────────────────────
class IncidentCreate(BaseModel):
    title: str = Field(min_length=1, max_length=255)
    description: str | None = None
    severity: IncidentSeverity = IncidentSeverity.medium
    alert_ids: list[uuid.UUID] | None = None
    asset_ids: list[uuid.UUID] | None = None


class IncidentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    title: str
    description: str | None = None
    severity: IncidentSeverity
    status: IncidentStatus
    reporter_id: uuid.UUID | None = None
    assignee_id: uuid.UUID | None = None
    acknowledged_at: datetime | None = None
    sla_due_at: datetime | None = None
    resolved_at: datetime | None = None
    created_at: datetime


class IncidentNoteResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    note_type: str
    body: str
    author_id: uuid.UUID | None = None
    created_at: datetime


class CommentCreate(BaseModel):
    body: str = Field(min_length=1)


class IncidentStatusUpdate(BaseModel):
    status: IncidentStatus
    resolution: str | None = None


class AssignRequest(BaseModel):
    assignee_id: uuid.UUID


# ── Alert rules ─────────────────────────────────────────────────
class AlertRuleResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    name: str
    rule_type: AlertRuleType
    enabled: bool
    severity: AlertSeverity
    params: dict[str, Any] | None = None
    description: str | None = None


# ── User management ─────────────────────────────────────────────
class UserAdminResponse(BaseModel):
    id: uuid.UUID
    username: str
    email: str
    is_active: bool
    is_superuser: bool
    roles: list[str] = []
    created_at: datetime


class SetRolesRequest(BaseModel):
    roles: list[str]


class SetActiveRequest(BaseModel):
    active: bool
