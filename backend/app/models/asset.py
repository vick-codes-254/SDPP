"""Asset inventory models.

Sensitive network identifiers (hostname, IP, MAC) are encrypted at rest via the
SDPP field-encryption layer; an IP blind index enables exact-match lookup without
decryption (e.g. "do we already have this host?").
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Enum, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.enums import (
    AssetCriticality,
    AssetEnvironment,
    AssetStatus,
    AssetType,
    DiscoverySource,
)
from app.core.security.field_encryption import BlindIndex, EncryptedString, EncryptedText
from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin
from app.db.types import GUID, JSONType


class Asset(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "assets"

    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    asset_type: Mapped[AssetType] = mapped_column(
        Enum(AssetType, name="asset_type"), nullable=False, default=AssetType.host, index=True
    )

    # Encrypted network identifiers (PII/sensitive in a security context).
    hostname: Mapped[str | None] = mapped_column(EncryptedString(context="assets.hostname"))
    ip_address: Mapped[str | None] = mapped_column(EncryptedString(context="assets.ip_address"))
    ip_bidx: Mapped[str | None] = mapped_column(BlindIndex(), index=True)  # lookup by IP
    mac_address: Mapped[str | None] = mapped_column(EncryptedString(context="assets.mac_address"))

    operating_system: Mapped[str | None] = mapped_column(String(128))
    os_version: Mapped[str | None] = mapped_column(String(64))

    criticality: Mapped[AssetCriticality] = mapped_column(
        Enum(AssetCriticality, name="asset_criticality"),
        nullable=False, default=AssetCriticality.medium, index=True,
    )
    environment: Mapped[AssetEnvironment] = mapped_column(
        Enum(AssetEnvironment, name="asset_environment"),
        nullable=False, default=AssetEnvironment.unknown,
    )
    status: Mapped[AssetStatus] = mapped_column(
        Enum(AssetStatus, name="asset_status"),
        nullable=False, default=AssetStatus.active, index=True,
    )

    owner: Mapped[str | None] = mapped_column(String(128))
    location: Mapped[str | None] = mapped_column(String(128))
    tags: Mapped[list | None] = mapped_column(JSONType)
    notes: Mapped[str | None] = mapped_column(EncryptedText(context="assets.notes"))

    discovered_by: Mapped[DiscoverySource] = mapped_column(
        Enum(DiscoverySource, name="discovery_source"),
        nullable=False, default=DiscoverySource.manual,
    )
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    software: Mapped[list[AssetSoftware]] = relationship(
        back_populates="asset", cascade="all, delete-orphan", lazy="selectin"
    )


class AssetSoftware(Base, UUIDPrimaryKeyMixin):
    """An installed software/package on an asset — the input to CVE matching."""

    __tablename__ = "asset_software"

    asset_id: Mapped[uuid.UUID] = mapped_column(
        GUID, ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    version: Mapped[str | None] = mapped_column(String(64))
    vendor: Mapped[str | None] = mapped_column(String(128))

    asset: Mapped[Asset] = relationship(back_populates="software")
