"""Multi-channel notification delivery models.

A tenant configures NotificationChannels (email/SMS/WhatsApp/push/webhook). Alerts
and emergencies fan out as Notification records whose delivery status is tracked.
Targets (email/phone/URL) are sensitive and encrypted at rest.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.enums import NotificationChannel, NotificationStatus
from app.core.security.field_encryption import EncryptedString
from app.db.base import Base, TenantMixin, TimestampMixin, UUIDPrimaryKeyMixin
from app.db.types import GUID, JSONType


class NotificationChannelConfig(Base, UUIDPrimaryKeyMixin, TenantMixin, TimestampMixin):
    __tablename__ = "notification_channels"

    name: Mapped[str] = mapped_column(String(128), nullable=False)
    channel: Mapped[NotificationChannel] = mapped_column(
        Enum(NotificationChannel, name="notification_channel"), nullable=False
    )
    target: Mapped[str] = mapped_column(EncryptedString(context="notif.target"), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    min_severity: Mapped[str] = mapped_column(String(16), nullable=False, default="low")
    config: Mapped[dict | None] = mapped_column(JSONType)


class AlertTemplate(Base, UUIDPrimaryKeyMixin, TenantMixin, TimestampMixin):
    __tablename__ = "alert_templates"

    key: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    channel: Mapped[NotificationChannel] = mapped_column(
        Enum(NotificationChannel, name="notification_channel"), nullable=False
    )
    subject: Mapped[str | None] = mapped_column(String(255))
    body: Mapped[str] = mapped_column(String(2000), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)


class Notification(Base, UUIDPrimaryKeyMixin, TenantMixin, TimestampMixin):
    __tablename__ = "notifications"

    channel: Mapped[NotificationChannel] = mapped_column(
        Enum(NotificationChannel, name="notification_channel"), nullable=False, index=True
    )
    target: Mapped[str] = mapped_column(EncryptedString(context="notif.target"), nullable=False)
    subject: Mapped[str | None] = mapped_column(String(255))
    body: Mapped[str] = mapped_column(String(2000), nullable=False)

    status: Mapped[NotificationStatus] = mapped_column(
        Enum(NotificationStatus, name="notification_status"),
        nullable=False, default=NotificationStatus.queued, index=True,
    )
    provider: Mapped[str | None] = mapped_column(String(64))
    error: Mapped[str | None] = mapped_column(String(255))
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    related_alert_id: Mapped[uuid.UUID | None] = mapped_column(GUID, index=True)
    related_emergency_id: Mapped[uuid.UUID | None] = mapped_column(GUID, index=True)
