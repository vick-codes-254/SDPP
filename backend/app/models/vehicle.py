"""Vehicle registry and ANPR (number-plate recognition) event models.

Plates are PII and stored encrypted at rest; a deterministic blind index on the
normalized plate enables watchlist/registry matching at the gate without
decryption.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.enums import VehicleDirection, VehicleStatus
from app.core.security.field_encryption import BlindIndex, EncryptedString
from app.db.base import Base, TenantMixin, TimestampMixin, UUIDPrimaryKeyMixin
from app.db.types import GUID


class Vehicle(Base, UUIDPrimaryKeyMixin, TenantMixin, TimestampMixin):
    __tablename__ = "vehicles"

    plate: Mapped[str] = mapped_column(EncryptedString(context="vehicles.plate"), nullable=False)
    plate_bidx: Mapped[str] = mapped_column(BlindIndex(), nullable=False, index=True)
    make: Mapped[str | None] = mapped_column(String(64))
    model: Mapped[str | None] = mapped_column(String(64))
    color: Mapped[str | None] = mapped_column(String(32))
    owner_name: Mapped[str | None] = mapped_column(EncryptedString(context="vehicles.owner"))

    status: Mapped[VehicleStatus] = mapped_column(
        Enum(VehicleStatus, name="vehicle_status"),
        nullable=False, default=VehicleStatus.active, index=True,
    )
    is_watchlisted: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, index=True)
    watch_reason: Mapped[str | None] = mapped_column(String(255))


class VehicleEvent(Base, UUIDPrimaryKeyMixin):
    """An ANPR detection at a gate/camera (entry or exit)."""

    __tablename__ = "vehicle_events"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        GUID, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    site_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID, ForeignKey("sites.id", ondelete="SET NULL"), index=True
    )
    camera_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID, ForeignKey("cameras.id", ondelete="SET NULL")
    )
    vehicle_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID, ForeignKey("vehicles.id", ondelete="SET NULL")
    )
    plate: Mapped[str] = mapped_column(EncryptedString(context="vehicle_events.plate"), nullable=False)
    plate_bidx: Mapped[str] = mapped_column(BlindIndex(), nullable=False, index=True)
    direction: Mapped[VehicleDirection] = mapped_column(
        Enum(VehicleDirection, name="vehicle_direction"),
        nullable=False, default=VehicleDirection.entry,
    )
    authorized: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, index=True)
    confidence: Mapped[str | None] = mapped_column(String(8))  # e.g. "0.97"
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
