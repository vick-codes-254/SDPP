"""SecOps schemas: notifications/alert delivery, emergency response, evidence."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.core.enums import (
    CustodyAction,
    EmergencyStatus,
    EmergencyType,
    EvidenceStatus,
    EvidenceType,
    NotificationChannel,
    NotificationStatus,
)


# ── Notification channels & templates ───────────────────────────
class ChannelCreate(BaseModel):
    organization_id: uuid.UUID
    name: str = Field(min_length=1, max_length=128)
    channel: NotificationChannel
    target: str = Field(min_length=1, max_length=255)
    min_severity: str = "low"
    config: dict | None = None


class ChannelResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    organization_id: uuid.UUID
    name: str
    channel: NotificationChannel
    target: str
    is_active: bool
    min_severity: str
    created_at: datetime


class TemplateCreate(BaseModel):
    organization_id: uuid.UUID
    key: str = Field(min_length=1, max_length=64)
    channel: NotificationChannel
    subject: str | None = None
    body: str = Field(min_length=1, max_length=2000)


class TemplateResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    organization_id: uuid.UUID
    key: str
    channel: NotificationChannel
    subject: str | None = None
    body: str
    is_active: bool


class DispatchRequest(BaseModel):
    organization_id: uuid.UUID
    channel: NotificationChannel
    target: str
    subject: str | None = None
    body: str = Field(min_length=1, max_length=2000)


class NotificationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    organization_id: uuid.UUID
    channel: NotificationChannel
    target: str
    subject: str | None = None
    body: str
    status: NotificationStatus
    provider: str | None = None
    error: str | None = None
    attempts: int
    sent_at: datetime | None = None
    created_at: datetime


# ── Emergency response ──────────────────────────────────────────
class EmergencyTrigger(BaseModel):
    organization_id: uuid.UUID
    event_type: EmergencyType
    site_id: uuid.UUID | None = None
    zone_id: uuid.UUID | None = None
    message: str | None = None


class EmergencyResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    organization_id: uuid.UUID
    event_type: EmergencyType
    status: EmergencyStatus
    site_id: uuid.UUID | None = None
    zone_id: uuid.UUID | None = None
    message: str | None = None
    notified_count: int
    incident_id: uuid.UUID | None = None
    resolved_at: datetime | None = None
    created_at: datetime


class ContactCreate(BaseModel):
    organization_id: uuid.UUID
    name: str = Field(min_length=1, max_length=255)
    role: str | None = None
    phone: str | None = None
    email: str | None = None
    channel: NotificationChannel = NotificationChannel.sms
    priority: int = Field(default=1, ge=1, le=99)


class ContactResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    organization_id: uuid.UUID
    name: str
    role: str | None = None
    phone: str | None = None
    email: str | None = None
    channel: NotificationChannel
    priority: int


# ── Evidence & chain of custody ─────────────────────────────────
class EvidenceRegister(BaseModel):
    organization_id: uuid.UUID
    title: str = Field(min_length=1, max_length=255)
    evidence_type: EvidenceType = EvidenceType.other
    incident_id: uuid.UUID | None = None
    file_id: uuid.UUID | None = None
    sha256: str | None = None
    source: str | None = None
    description: str | None = None
    tags: list[str] | None = None


class EvidenceResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    organization_id: uuid.UUID
    title: str
    evidence_type: EvidenceType
    status: EvidenceStatus
    incident_id: uuid.UUID | None = None
    file_id: uuid.UUID | None = None
    sha256: str | None = None
    source: str | None = None
    collected_by: uuid.UUID | None = None
    collected_at: datetime
    created_at: datetime


class CustodyLog(BaseModel):
    action: CustodyAction
    from_party: str | None = None
    to_party: str | None = None
    notes: str | None = None


class CustodyResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    evidence_id: uuid.UUID
    action: CustodyAction
    actor_id: uuid.UUID | None = None
    from_party: str | None = None
    to_party: str | None = None
    notes: str | None = None
    occurred_at: datetime
