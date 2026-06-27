"""AI detection events and correlated threats.

A ``Detection`` is a single AI/analytics event from a camera or sensor (person,
weapon, fire, intrusion, ...). The Threat Intelligence engine correlates related
detections into a ``Threat`` with a computed risk score, which can be escalated
into a formal incident.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Enum, Float, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.enums import (
    DetectionStatus,
    DetectionType,
    ThreatLevel,
    ThreatStatus,
)
from app.db.base import Base, TenantMixin, TimestampMixin, UUIDPrimaryKeyMixin
from app.db.types import GUID, JSONType


class Detection(Base, UUIDPrimaryKeyMixin, TenantMixin, TimestampMixin):
    __tablename__ = "detections"

    site_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID, ForeignKey("sites.id", ondelete="SET NULL"), index=True
    )
    zone_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID, ForeignKey("zones.id", ondelete="SET NULL")
    )
    camera_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID, ForeignKey("cameras.id", ondelete="SET NULL"), index=True
    )

    detection_type: Mapped[DetectionType] = mapped_column(
        Enum(DetectionType, name="detection_type"), nullable=False, index=True
    )
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    severity: Mapped[ThreatLevel] = mapped_column(
        Enum(ThreatLevel, name="threat_level"),
        nullable=False, default=ThreatLevel.info, index=True,
    )
    status: Mapped[DetectionStatus] = mapped_column(
        Enum(DetectionStatus, name="detection_status"),
        nullable=False, default=DetectionStatus.new, index=True,
    )

    label: Mapped[str | None] = mapped_column(String(255))
    snapshot_ref: Mapped[str | None] = mapped_column(String(255))  # vault object id
    meta: Mapped[dict | None] = mapped_column(JSONType)
    detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )

    threat_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID, ForeignKey("threats.id", ondelete="SET NULL"), index=True
    )


class Threat(Base, UUIDPrimaryKeyMixin, TenantMixin, TimestampMixin):
    __tablename__ = "threats"

    title: Mapped[str] = mapped_column(String(255), nullable=False)
    threat_type: Mapped[DetectionType | None] = mapped_column(
        Enum(DetectionType, name="detection_type")
    )
    site_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID, ForeignKey("sites.id", ondelete="SET NULL"), index=True
    )
    zone_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID, ForeignKey("zones.id", ondelete="SET NULL")
    )

    score: Mapped[int] = mapped_column(Integer, nullable=False, default=0, index=True)
    risk_level: Mapped[ThreatLevel] = mapped_column(
        Enum(ThreatLevel, name="threat_level"),
        nullable=False, default=ThreatLevel.low, index=True,
    )
    status: Mapped[ThreatStatus] = mapped_column(
        Enum(ThreatStatus, name="threat_status"),
        nullable=False, default=ThreatStatus.active, index=True,
    )
    detection_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    first_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    incident_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID, ForeignKey("incidents.id", ondelete="SET NULL")
    )
