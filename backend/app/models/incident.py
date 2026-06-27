"""Incident management models.

Incidents tie together alerts, affected assets, an encrypted investigation
timeline, and encrypted evidence files (stored in the SDPP vault). Free-text
investigation content is encrypted at rest.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Column, DateTime, Enum, ForeignKey, String, Table
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.enums import IncidentSeverity, IncidentStatus
from app.core.security.field_encryption import EncryptedText
from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin
from app.db.types import GUID

# ── Association tables ───────────────────────────────────────────
incident_alerts = Table(
    "incident_alerts", Base.metadata,
    Column("incident_id", GUID, ForeignKey("incidents.id", ondelete="CASCADE"), primary_key=True),
    Column("alert_id", GUID, ForeignKey("security_alerts.id", ondelete="CASCADE"), primary_key=True),
)
incident_assets = Table(
    "incident_assets", Base.metadata,
    Column("incident_id", GUID, ForeignKey("incidents.id", ondelete="CASCADE"), primary_key=True),
    Column("asset_id", GUID, ForeignKey("assets.id", ondelete="CASCADE"), primary_key=True),
)
incident_evidence = Table(
    "incident_evidence", Base.metadata,
    Column("incident_id", GUID, ForeignKey("incidents.id", ondelete="CASCADE"), primary_key=True),
    Column("file_id", GUID, ForeignKey("files.id", ondelete="CASCADE"), primary_key=True),
)


class Incident(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "incidents"

    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(EncryptedText(context="incidents.description"))
    severity: Mapped[IncidentSeverity] = mapped_column(
        Enum(IncidentSeverity, name="incident_severity"),
        nullable=False, default=IncidentSeverity.medium, index=True,
    )
    status: Mapped[IncidentStatus] = mapped_column(
        Enum(IncidentStatus, name="incident_status"),
        nullable=False, default=IncidentStatus.open, index=True,
    )
    reporter_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID, ForeignKey("users.id", ondelete="SET NULL")
    )
    assignee_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID, ForeignKey("users.id", ondelete="SET NULL"), index=True
    )
    # Multi-tenant scoping (nullable so legacy/global incidents remain valid).
    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID, ForeignKey("organizations.id", ondelete="CASCADE"), index=True
    )
    # SLA tracking.
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    sla_due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    resolution: Mapped[str | None] = mapped_column(EncryptedText(context="incidents.resolution"))

    notes: Mapped[list[IncidentNote]] = relationship(
        back_populates="incident", cascade="all, delete-orphan", order_by="IncidentNote.created_at",
    )
    alerts = relationship("SecurityAlert", secondary=incident_alerts, lazy="selectin")
    assets = relationship("Asset", secondary=incident_assets, lazy="selectin")
    evidence = relationship("File", secondary=incident_evidence, lazy="selectin")


class IncidentNote(Base, UUIDPrimaryKeyMixin):
    """A timeline entry (comment, status change, assignment, system event)."""

    __tablename__ = "incident_notes"

    incident_id: Mapped[uuid.UUID] = mapped_column(
        GUID, ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True
    )
    author_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID, ForeignKey("users.id", ondelete="SET NULL")
    )
    note_type: Mapped[str] = mapped_column(String(32), nullable=False, default="comment")
    body: Mapped[str] = mapped_column(EncryptedText(context="incident_notes.body"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    incident: Mapped[Incident] = relationship(back_populates="notes")
