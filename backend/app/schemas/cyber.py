"""Cybersecurity monitoring schemas."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.core.enums import AlertSeverity, CyberEventStatus, CyberEventType


class LoginEventIngest(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    success: bool
    user_id: uuid.UUID | None = None
    organization_id: uuid.UUID | None = None
    ip_address: str | None = None
    country: str | None = Field(default=None, max_length=2)
    city: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    device_fingerprint: str | None = None
    user_agent: str | None = None


class CyberEventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    organization_id: uuid.UUID | None = None
    event_type: CyberEventType
    severity: AlertSeverity
    status: CyberEventStatus
    user_id: uuid.UUID | None = None
    username: str | None = None
    country: str | None = None
    title: str
    detail: dict | None = None
    occurred_at: datetime


class IngestResult(BaseModel):
    events_triggered: list[CyberEventResponse]


class CyberStatusUpdate(BaseModel):
    status: CyberEventStatus


class LoginAttemptResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    username: str
    ip_address: str | None = None
    country: str | None = None
    city: str | None = None
    device_fingerprint: str | None = None
    success: bool
    occurred_at: datetime


class DeviceResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    user_id: uuid.UUID
    fingerprint: str
    label: str | None = None
    trusted: bool
    last_country: str | None = None
    first_seen_at: datetime
    last_seen_at: datetime
