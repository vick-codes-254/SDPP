"""Physical estate hierarchy: sites, buildings, zones, checkpoints.

Site -> Building -> (Floor implicit via Building.floors) and Site -> Zone.
Checkpoints are patrol scan points (QR/NFC/GPS) anchored to a site/zone.
"""

from __future__ import annotations

import uuid

from sqlalchemy import Boolean, Enum, Float, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.enums import CheckpointType, SiteStatus, SiteType, ZoneType
from app.core.security.field_encryption import EncryptedString
from app.db.base import Base, TenantMixin, TimestampMixin, UUIDPrimaryKeyMixin
from app.db.types import GUID


class Site(Base, UUIDPrimaryKeyMixin, TenantMixin, TimestampMixin):
    """A physical location (campus/building cluster) under an organization."""

    __tablename__ = "sites"

    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    code: Mapped[str | None] = mapped_column(String(32))
    site_type: Mapped[SiteType] = mapped_column(
        Enum(SiteType, name="site_type"), nullable=False, default=SiteType.office
    )
    status: Mapped[SiteStatus] = mapped_column(
        Enum(SiteStatus, name="site_status"), nullable=False, default=SiteStatus.active, index=True
    )

    branch_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID, ForeignKey("branches.id", ondelete="SET NULL"), index=True
    )

    address: Mapped[str | None] = mapped_column(EncryptedString(context="sites.address"))
    city: Mapped[str | None] = mapped_column(String(128))
    country: Mapped[str | None] = mapped_column(String(64))
    latitude: Mapped[float | None] = mapped_column(Float)
    longitude: Mapped[float | None] = mapped_column(Float)
    timezone: Mapped[str] = mapped_column(String(64), nullable=False, default="UTC")

    buildings: Mapped[list[Building]] = relationship(
        back_populates="site", cascade="all, delete-orphan", lazy="selectin"
    )
    zones: Mapped[list[Zone]] = relationship(
        back_populates="site", cascade="all, delete-orphan", lazy="selectin"
    )


class Building(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "buildings"

    site_id: Mapped[uuid.UUID] = mapped_column(
        GUID, ForeignKey("sites.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    floors: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    site: Mapped[Site] = relationship(back_populates="buildings")


class Zone(Base, UUIDPrimaryKeyMixin, TenantMixin, TimestampMixin):
    """A security zone within a site (general/restricted/perimeter/...)."""

    __tablename__ = "zones"

    site_id: Mapped[uuid.UUID] = mapped_column(
        GUID, ForeignKey("sites.id", ondelete="CASCADE"), nullable=False, index=True
    )
    building_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID, ForeignKey("buildings.id", ondelete="SET NULL")
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    zone_type: Mapped[ZoneType] = mapped_column(
        Enum(ZoneType, name="zone_type"), nullable=False, default=ZoneType.general, index=True
    )
    floor: Mapped[int | None] = mapped_column(Integer)
    is_restricted: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    site: Mapped[Site] = relationship(back_populates="zones")


class Checkpoint(Base, UUIDPrimaryKeyMixin, TenantMixin, TimestampMixin):
    """A patrol scan point (QR/NFC/GPS) used to verify guard rounds."""

    __tablename__ = "checkpoints"

    site_id: Mapped[uuid.UUID] = mapped_column(
        GUID, ForeignKey("sites.id", ondelete="CASCADE"), nullable=False, index=True
    )
    zone_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID, ForeignKey("zones.id", ondelete="SET NULL")
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    checkpoint_type: Mapped[CheckpointType] = mapped_column(
        Enum(CheckpointType, name="checkpoint_type"), nullable=False, default=CheckpointType.qr
    )
    # Scan token (QR/NFC payload) — opaque identifier verified during patrols.
    code: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    latitude: Mapped[float | None] = mapped_column(Float)
    longitude: Mapped[float | None] = mapped_column(Float)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
