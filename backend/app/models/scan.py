"""Network discovery scan models."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Enum, Float, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.enums import ScanStatus
from app.core.security.field_encryption import EncryptedString
from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin
from app.db.types import GUID, JSONType


class DiscoveryScan(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "discovery_scans"

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    targets: Mapped[list] = mapped_column(JSONType, nullable=False)  # raw user-supplied targets
    ports: Mapped[list] = mapped_column(JSONType, nullable=False)
    status: Mapped[ScanStatus] = mapped_column(
        Enum(ScanStatus, name="scan_status"), nullable=False, default=ScanStatus.pending, index=True
    )
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        GUID, ForeignKey("users.id", ondelete="SET NULL")
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    hosts_found: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    summary: Mapped[dict | None] = mapped_column(JSONType)

    hosts: Mapped[list[DiscoveredHost]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )


class DiscoveredHost(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "discovered_hosts"

    scan_id: Mapped[uuid.UUID] = mapped_column(
        GUID, ForeignKey("discovery_scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    ip_address: Mapped[str] = mapped_column(
        EncryptedString(context="discovered_hosts.ip_address"), nullable=False
    )
    hostname: Mapped[str | None] = mapped_column(
        EncryptedString(context="discovered_hosts.hostname")
    )
    open_ports: Mapped[list | None] = mapped_column(JSONType)
    latency_ms: Mapped[float | None] = mapped_column(Float)
    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID, ForeignKey("assets.id", ondelete="SET NULL")
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    scan: Mapped[DiscoveryScan] = relationship(back_populates="hosts")
