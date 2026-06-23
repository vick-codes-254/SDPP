"""Compliance reporting model."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Enum, ForeignKey, Numeric, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin
from app.db.types import GUID, JSONType
from app.models.enums import ComplianceFramework, ReportStatus


class ComplianceReport(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """A generated compliance report mapping platform controls to a framework."""

    __tablename__ = "compliance_reports"

    framework: Mapped[ComplianceFramework] = mapped_column(
        Enum(ComplianceFramework, name="compliance_framework"), nullable=False, index=True
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[ReportStatus] = mapped_column(
        Enum(ReportStatus, name="report_status"), nullable=False, default=ReportStatus.draft
    )

    # Compliance score as a percentage (0.00–100.00).
    score: Mapped[float | None] = mapped_column(Numeric(5, 2))

    period_start: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    period_end: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # Machine-readable control results + human-readable narrative.
    summary: Mapped[dict | None] = mapped_column(JSONType)
    content: Mapped[dict | None] = mapped_column(JSONType)

    generated_by: Mapped[uuid.UUID | None] = mapped_column(
        GUID, ForeignKey("users.id", ondelete="SET NULL")
    )
