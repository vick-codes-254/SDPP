"""Physical-security schemas: cameras, guards, patrols, visitors, contractors,
access control, vehicles/ANPR."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.core.enums import (
    AccessDecision,
    AccessMethod,
    AccessPointType,
    CameraStatus,
    ContractorStatus,
    GuardStatus,
    PatrolStatus,
    StreamQuality,
    VehicleDirection,
    VehicleStatus,
    VisitorStatus,
)


# ── Cameras ─────────────────────────────────────────────────────
class CameraCreate(BaseModel):
    organization_id: uuid.UUID
    site_id: uuid.UUID
    zone_id: uuid.UUID | None = None
    name: str = Field(min_length=1, max_length=255)
    rtsp_url: str | None = None
    snapshot_url: str | None = None
    stream_quality: StreamQuality = StreamQuality.high
    manufacturer: str | None = None
    model: str | None = None
    firmware_version: str | None = None
    ip_label: str | None = None
    retention_days: int = Field(default=30, ge=1, le=3650)


class CameraUpdate(BaseModel):
    name: str | None = None
    zone_id: uuid.UUID | None = None
    status: CameraStatus | None = None
    is_recording: bool | None = None
    stream_quality: StreamQuality | None = None
    firmware_version: str | None = None
    retention_days: int | None = Field(default=None, ge=1, le=3650)


class CameraHeartbeat(BaseModel):
    online: bool
    recording: bool | None = None


class CameraResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    organization_id: uuid.UUID
    site_id: uuid.UUID
    zone_id: uuid.UUID | None = None
    name: str
    status: CameraStatus
    is_recording: bool
    stream_quality: StreamQuality
    manufacturer: str | None = None
    model: str | None = None
    firmware_version: str | None = None
    ip_label: str | None = None
    retention_days: int
    last_heartbeat_at: datetime | None = None
    created_at: datetime


# ── Guards ──────────────────────────────────────────────────────
class GuardCreate(BaseModel):
    organization_id: uuid.UUID
    site_id: uuid.UUID | None = None
    employee_code: str = Field(min_length=1, max_length=32)
    full_name: str = Field(min_length=1, max_length=255)
    phone: str | None = None
    rank: str | None = None
    shift: str | None = None
    certifications: list[dict] | None = None


class GuardUpdate(BaseModel):
    site_id: uuid.UUID | None = None
    status: GuardStatus | None = None
    rank: str | None = None
    shift: str | None = None
    phone: str | None = None
    certifications: list[dict] | None = None


class GuardResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    organization_id: uuid.UUID
    site_id: uuid.UUID | None = None
    employee_code: str
    full_name: str
    phone: str | None = None
    status: GuardStatus
    rank: str | None = None
    shift: str | None = None
    last_lat: float | None = None
    last_lng: float | None = None
    last_seen_at: datetime | None = None
    created_at: datetime


# ── Patrols ─────────────────────────────────────────────────────
class PatrolCreate(BaseModel):
    organization_id: uuid.UUID
    site_id: uuid.UUID
    guard_id: uuid.UUID | None = None
    route_name: str = Field(min_length=1, max_length=255)
    scheduled_start: datetime | None = None
    checkpoints_total: int | None = None


class PatrolResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    organization_id: uuid.UUID
    site_id: uuid.UUID
    guard_id: uuid.UUID | None = None
    route_name: str
    status: PatrolStatus
    scheduled_start: datetime | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    checkpoints_total: int | None = None
    created_at: datetime


class PatrolScanCreate(BaseModel):
    checkpoint_id: uuid.UUID | None = None
    gps_verified: bool = False
    lat: float | None = None
    lng: float | None = None


class PatrolScanResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    patrol_id: uuid.UUID
    checkpoint_id: uuid.UUID | None = None
    scanned_at: datetime
    gps_verified: bool


# ── Visitors ────────────────────────────────────────────────────
class VisitorCreate(BaseModel):
    organization_id: uuid.UUID
    site_id: uuid.UUID | None = None
    full_name: str = Field(min_length=1, max_length=255)
    phone: str | None = None
    id_number: str | None = None
    company: str | None = None
    host_name: str | None = None
    purpose: str | None = None


class VisitorStatusUpdate(BaseModel):
    status: VisitorStatus


class VisitorResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    organization_id: uuid.UUID
    site_id: uuid.UUID | None = None
    full_name: str
    phone: str | None = None
    company: str | None = None
    host_name: str | None = None
    purpose: str | None = None
    status: VisitorStatus
    badge_code: str | None = None
    check_in_at: datetime | None = None
    check_out_at: datetime | None = None
    created_at: datetime


# ── Contractors ─────────────────────────────────────────────────
class ContractorCreate(BaseModel):
    organization_id: uuid.UUID
    company: str = Field(min_length=1, max_length=255)
    contact_name: str | None = None
    contact_phone: str | None = None
    work_permit_no: str | None = None
    permit_expiry: datetime | None = None
    safety_compliant: bool = False
    access_approved: bool = False


class ContractorUpdate(BaseModel):
    status: ContractorStatus | None = None
    safety_compliant: bool | None = None
    access_approved: bool | None = None
    permit_expiry: datetime | None = None


class ContractorResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    organization_id: uuid.UUID
    company: str
    contact_name: str | None = None
    contact_phone: str | None = None
    work_permit_no: str | None = None
    permit_expiry: datetime | None = None
    status: ContractorStatus
    safety_compliant: bool
    access_approved: bool
    created_at: datetime


# ── Access control ──────────────────────────────────────────────
class AccessPointCreate(BaseModel):
    organization_id: uuid.UUID
    site_id: uuid.UUID
    zone_id: uuid.UUID | None = None
    name: str = Field(min_length=1, max_length=255)
    point_type: AccessPointType = AccessPointType.door
    method: AccessMethod = AccessMethod.rfid
    is_locked: bool = True


class AccessPointUpdate(BaseModel):
    name: str | None = None
    is_locked: bool | None = None
    is_online: bool | None = None


class AccessPointResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    organization_id: uuid.UUID
    site_id: uuid.UUID
    zone_id: uuid.UUID | None = None
    name: str
    point_type: AccessPointType
    method: AccessMethod
    is_locked: bool
    is_online: bool
    created_at: datetime


class AccessEventCreate(BaseModel):
    organization_id: uuid.UUID
    access_point_id: uuid.UUID
    credential_type: AccessMethod = AccessMethod.rfid
    subject_label: str | None = None
    decision: AccessDecision = AccessDecision.granted
    reason: str | None = None


class AccessEventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    organization_id: uuid.UUID
    access_point_id: uuid.UUID
    credential_type: AccessMethod
    subject_label: str | None = None
    decision: AccessDecision
    reason: str | None = None
    occurred_at: datetime


# ── Vehicles & ANPR ─────────────────────────────────────────────
class VehicleCreate(BaseModel):
    organization_id: uuid.UUID
    plate: str = Field(min_length=1, max_length=32)
    make: str | None = None
    model: str | None = None
    color: str | None = None
    owner_name: str | None = None
    is_watchlisted: bool = False
    watch_reason: str | None = None
    status: VehicleStatus = VehicleStatus.active


class VehicleUpdate(BaseModel):
    status: VehicleStatus | None = None
    is_watchlisted: bool | None = None
    watch_reason: str | None = None
    color: str | None = None


class VehicleResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    organization_id: uuid.UUID
    plate: str
    make: str | None = None
    model: str | None = None
    color: str | None = None
    owner_name: str | None = None
    status: VehicleStatus
    is_watchlisted: bool
    watch_reason: str | None = None
    created_at: datetime


class AnprCreate(BaseModel):
    organization_id: uuid.UUID
    plate: str = Field(min_length=1, max_length=32)
    direction: VehicleDirection = VehicleDirection.entry
    site_id: uuid.UUID | None = None
    camera_id: uuid.UUID | None = None
    confidence: str | None = None


class VehicleEventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    organization_id: uuid.UUID
    site_id: uuid.UUID | None = None
    camera_id: uuid.UUID | None = None
    vehicle_id: uuid.UUID | None = None
    plate: str
    direction: VehicleDirection
    authorized: bool
    confidence: str | None = None
    occurred_at: datetime


class AnprResultResponse(BaseModel):
    event: VehicleEventResponse
    matched_vehicle_id: uuid.UUID | None = None
    flagged: bool
