"""AI detection & threat-intelligence schemas."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.core.enums import (
    DetectionStatus,
    DetectionType,
    ThreatLevel,
    ThreatStatus,
)


class DetectionIngest(BaseModel):
    organization_id: uuid.UUID
    detection_type: DetectionType
    confidence: float = Field(default=0.8, ge=0.0, le=1.0)
    site_id: uuid.UUID | None = None
    zone_id: uuid.UUID | None = None
    camera_id: uuid.UUID | None = None
    label: str | None = None
    snapshot_ref: str | None = None
    meta: dict | None = None


class DetectionStatusUpdate(BaseModel):
    status: DetectionStatus


class DetectionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    organization_id: uuid.UUID
    site_id: uuid.UUID | None = None
    zone_id: uuid.UUID | None = None
    camera_id: uuid.UUID | None = None
    detection_type: DetectionType
    confidence: float
    severity: ThreatLevel
    status: DetectionStatus
    label: str | None = None
    snapshot_ref: str | None = None
    threat_id: uuid.UUID | None = None
    detected_at: datetime


class DetectionIngestResult(BaseModel):
    detection: DetectionResponse
    threat_id: uuid.UUID | None = None


class ThreatStatusUpdate(BaseModel):
    status: ThreatStatus


class ThreatResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    organization_id: uuid.UUID
    title: str
    threat_type: DetectionType | None = None
    site_id: uuid.UUID | None = None
    zone_id: uuid.UUID | None = None
    score: int
    risk_level: ThreatLevel
    status: ThreatStatus
    detection_count: int
    incident_id: uuid.UUID | None = None
    first_seen_at: datetime | None = None
    last_seen_at: datetime | None = None
    created_at: datetime
