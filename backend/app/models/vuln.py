"""Vulnerability scan and finding models."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Enum, Float, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.enums import ScanStatus, VulnSeverity, VulnStatus
from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin
from app.db.types import GUID, JSONType


class VulnScan(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "vuln_scans"

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    # None/empty scope = scan all assets; otherwise a list of asset id strings.
    scope: Mapped[list | None] = mapped_column(JSONType)
    status: Mapped[ScanStatus] = mapped_column(
        Enum(ScanStatus, name="vuln_scan_status"), nullable=False,
        default=ScanStatus.pending, index=True,
    )
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        GUID, ForeignKey("users.id", ondelete="SET NULL")
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    summary: Mapped[dict | None] = mapped_column(JSONType)

    findings: Mapped[list[Finding]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )


class Finding(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "findings"

    scan_id: Mapped[uuid.UUID] = mapped_column(
        GUID, ForeignKey("vuln_scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        GUID, ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    cve_id: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    severity: Mapped[VulnSeverity] = mapped_column(
        Enum(VulnSeverity, name="vuln_severity"), nullable=False, index=True
    )
    cvss_score: Mapped[float | None] = mapped_column(Float)
    affected_software: Mapped[str | None] = mapped_column(String(128))
    affected_version: Mapped[str | None] = mapped_column(String(64))
    fixed_version: Mapped[str | None] = mapped_column(String(64))
    remediation: Mapped[str | None] = mapped_column(Text)
    status: Mapped[VulnStatus] = mapped_column(
        Enum(VulnStatus, name="vuln_status"), nullable=False, default=VulnStatus.open, index=True
    )
    references: Mapped[list | None] = mapped_column(JSONType)

    scan: Mapped[VulnScan] = relationship(back_populates="findings")
