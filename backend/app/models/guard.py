"""Guard workforce and patrol models.

Guard PII (name, phone) is encrypted at rest. Patrols are scheduled rounds; each
checkpoint scan is recorded with optional GPS so missed/forged patrols surface.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Enum, Float, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.enums import GuardStatus, PatrolStatus
from app.core.security.field_encryption import EncryptedString
from app.db.base import Base, TenantMixin, TimestampMixin, UUIDPrimaryKeyMixin
from app.db.types import GUID, JSONType


class Guard(Base, UUIDPrimaryKeyMixin, TenantMixin, TimestampMixin):
    __tablename__ = "guards"

    site_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID, ForeignKey("sites.id", ondelete="SET NULL"), index=True
    )
    employee_code: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    full_name: Mapped[str] = mapped_column(EncryptedString(context="guards.full_name"), nullable=False)
    phone: Mapped[str | None] = mapped_column(EncryptedString(context="guards.phone"))

    status: Mapped[GuardStatus] = mapped_column(
        Enum(GuardStatus, name="guard_status"),
        nullable=False, default=GuardStatus.off_duty, index=True,
    )
    rank: Mapped[str | None] = mapped_column(String(64))
    certifications: Mapped[list | None] = mapped_column(JSONType)  # [{name, expires_at}]
    shift: Mapped[str | None] = mapped_column(String(32))  # day/night/rotating

    # Last reported GPS position (for the live guard map).
    last_lat: Mapped[float | None] = mapped_column(Float)
    last_lng: Mapped[float | None] = mapped_column(Float)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Patrol(Base, UUIDPrimaryKeyMixin, TenantMixin, TimestampMixin):
    __tablename__ = "patrols"

    site_id: Mapped[uuid.UUID] = mapped_column(
        GUID, ForeignKey("sites.id", ondelete="CASCADE"), nullable=False, index=True
    )
    guard_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID, ForeignKey("guards.id", ondelete="SET NULL"), index=True
    )
    route_name: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[PatrolStatus] = mapped_column(
        Enum(PatrolStatus, name="patrol_status"),
        nullable=False, default=PatrolStatus.scheduled, index=True,
    )
    scheduled_start: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    checkpoints_total: Mapped[int | None] = mapped_column()

    scans: Mapped[list[PatrolScan]] = relationship(
        back_populates="patrol", cascade="all, delete-orphan", lazy="selectin"
    )


class PatrolScan(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "patrol_scans"

    patrol_id: Mapped[uuid.UUID] = mapped_column(
        GUID, ForeignKey("patrols.id", ondelete="CASCADE"), nullable=False, index=True
    )
    checkpoint_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID, ForeignKey("checkpoints.id", ondelete="SET NULL")
    )
    scanned_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    gps_verified: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    lat: Mapped[float | None] = mapped_column(Float)
    lng: Mapped[float | None] = mapped_column(Float)

    patrol: Mapped[Patrol] = relationship(back_populates="scans")
