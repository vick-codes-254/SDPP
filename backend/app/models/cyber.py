"""Cybersecurity monitoring models: login attempts, known devices, cyber events.

This is the platform's cyber differentiator: behavioural detection over the
authentication stream (brute force, impossible travel, new device, suspicious
login) feeding a SOC event queue. Source IPs are encrypted at rest.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Enum, Float, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.enums import AlertSeverity, CyberEventStatus, CyberEventType
from app.core.security.field_encryption import EncryptedString
from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin
from app.db.types import GUID, JSONType


class LoginAttempt(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "login_attempts"

    organization_id: Mapped[uuid.UUID | None] = mapped_column(GUID, index=True)
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID, ForeignKey("users.id", ondelete="SET NULL"), index=True
    )
    username: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    ip_address: Mapped[str | None] = mapped_column(EncryptedString(context="login.ip"))
    country: Mapped[str | None] = mapped_column(String(2))
    city: Mapped[str | None] = mapped_column(String(128))
    latitude: Mapped[float | None] = mapped_column(Float)
    longitude: Mapped[float | None] = mapped_column(Float)
    device_fingerprint: Mapped[str | None] = mapped_column(String(128), index=True)
    user_agent: Mapped[str | None] = mapped_column(String(255))
    success: Mapped[bool] = mapped_column(Boolean, nullable=False, index=True)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )


class Device(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "devices"

    user_id: Mapped[uuid.UUID] = mapped_column(
        GUID, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    fingerprint: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    label: Mapped[str | None] = mapped_column(String(255))
    trusted: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    last_ip: Mapped[str | None] = mapped_column(EncryptedString(context="device.ip"))
    last_country: Mapped[str | None] = mapped_column(String(2))
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class CyberEvent(Base, UUIDPrimaryKeyMixin):
    """A detected cybersecurity event surfaced in the SOC queue."""

    __tablename__ = "cyber_events"

    organization_id: Mapped[uuid.UUID | None] = mapped_column(GUID, index=True)
    event_type: Mapped[CyberEventType] = mapped_column(
        Enum(CyberEventType, name="cyber_event_type"), nullable=False, index=True
    )
    severity: Mapped[AlertSeverity] = mapped_column(
        Enum(AlertSeverity, name="alert_severity"), nullable=False, index=True
    )
    status: Mapped[CyberEventStatus] = mapped_column(
        Enum(CyberEventStatus, name="cyber_event_status"),
        nullable=False, default=CyberEventStatus.new, index=True,
    )
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID, ForeignKey("users.id", ondelete="SET NULL"), index=True
    )
    username: Mapped[str | None] = mapped_column(String(128), index=True)
    ip_address: Mapped[str | None] = mapped_column(EncryptedString(context="cyber.ip"))
    country: Mapped[str | None] = mapped_column(String(2))
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    detail: Mapped[dict | None] = mapped_column(JSONType)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
