"""Emergency response models: emergency events and emergency contacts."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Enum, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.enums import EmergencyStatus, EmergencyType, NotificationChannel
from app.core.security.field_encryption import EncryptedString
from app.db.base import Base, TenantMixin, TimestampMixin, UUIDPrimaryKeyMixin
from app.db.types import GUID


class EmergencyEvent(Base, UUIDPrimaryKeyMixin, TenantMixin, TimestampMixin):
    __tablename__ = "emergency_events"

    event_type: Mapped[EmergencyType] = mapped_column(
        Enum(EmergencyType, name="emergency_type"), nullable=False, index=True
    )
    status: Mapped[EmergencyStatus] = mapped_column(
        Enum(EmergencyStatus, name="emergency_status"),
        nullable=False, default=EmergencyStatus.active, index=True,
    )
    site_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID, ForeignKey("sites.id", ondelete="SET NULL"), index=True
    )
    zone_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID, ForeignKey("zones.id", ondelete="SET NULL")
    )
    message: Mapped[str | None] = mapped_column(EncryptedString(context="emergency.message"))
    triggered_by: Mapped[uuid.UUID | None] = mapped_column(
        GUID, ForeignKey("users.id", ondelete="SET NULL")
    )
    notified_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    incident_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID, ForeignKey("incidents.id", ondelete="SET NULL")
    )
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class EmergencyContact(Base, UUIDPrimaryKeyMixin, TenantMixin, TimestampMixin):
    __tablename__ = "emergency_contacts"

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str | None] = mapped_column(String(128))
    phone: Mapped[str | None] = mapped_column(EncryptedString(context="emergency.phone"))
    email: Mapped[str | None] = mapped_column(EncryptedString(context="emergency.email"))
    channel: Mapped[NotificationChannel] = mapped_column(
        Enum(NotificationChannel, name="notification_channel"),
        nullable=False, default=NotificationChannel.sms,
    )
    priority: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
