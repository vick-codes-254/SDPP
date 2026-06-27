"""Camera / CCTV models.

RTSP credentials and stream URLs are sensitive and stored encrypted at rest.
Health is tracked via heartbeat so the Live Monitoring Center can flag offline
cameras and raise stream-failure alerts.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.enums import CameraStatus, StreamQuality
from app.core.security.field_encryption import EncryptedString
from app.db.base import Base, TenantMixin, TimestampMixin, UUIDPrimaryKeyMixin
from app.db.types import GUID


class Camera(Base, UUIDPrimaryKeyMixin, TenantMixin, TimestampMixin):
    __tablename__ = "cameras"

    site_id: Mapped[uuid.UUID] = mapped_column(
        GUID, ForeignKey("sites.id", ondelete="CASCADE"), nullable=False, index=True
    )
    zone_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID, ForeignKey("zones.id", ondelete="SET NULL")
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)

    # Encrypted stream endpoint / credentials.
    rtsp_url: Mapped[str | None] = mapped_column(EncryptedString(context="cameras.rtsp_url"))
    snapshot_url: Mapped[str | None] = mapped_column(EncryptedString(context="cameras.snapshot_url"))

    status: Mapped[CameraStatus] = mapped_column(
        Enum(CameraStatus, name="camera_status"),
        nullable=False, default=CameraStatus.offline, index=True,
    )
    is_recording: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    stream_quality: Mapped[StreamQuality] = mapped_column(
        Enum(StreamQuality, name="stream_quality"), nullable=False, default=StreamQuality.high
    )

    manufacturer: Mapped[str | None] = mapped_column(String(128))
    model: Mapped[str | None] = mapped_column(String(128))
    firmware_version: Mapped[str | None] = mapped_column(String(64))
    ip_label: Mapped[str | None] = mapped_column(String(64))  # display-only, non-PII

    retention_days: Mapped[int] = mapped_column(Integer, nullable=False, default=30)
    last_heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_maintenance_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
