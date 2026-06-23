"""Audit logging & security monitoring models.

The audit log is **append-only** and **tamper-evident**: each row stores the
SHA-256 hash of its own canonical content concatenated with the previous row's
hash (a hash chain / mini-blockchain). Altering or deleting any historical row
breaks the chain and is detectable by re-walking it. At the database level the
application role is granted INSERT/SELECT only (no UPDATE/DELETE) on this table —
see the migration and ``docs/SECURITY.md``.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    DateTime,
    Enum,
    ForeignKey,
    Index,
    String,
    Text,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin
from app.db.types import BigIntPK, GUID, JSONType
from app.models.enums import (
    AlertSeverity,
    AlertStatus,
    AlertType,
    AuditEventType,
    AuditOutcome,
)


class AuditLog(Base):
    """A single immutable audit entry in the tamper-evident chain."""

    __tablename__ = "audit_logs"
    __table_args__ = (
        Index("ix_audit_logs_event_outcome", "event_type", "outcome"),
        Index("ix_audit_logs_created_at", "created_at"),
    )

    # Monotonic sequence anchors the hash chain ordering.
    seq: Mapped[int] = mapped_column(BigIntPK, primary_key=True, autoincrement=True)
    id: Mapped[uuid.UUID] = mapped_column(
        GUID, default=uuid.uuid4, unique=True, nullable=False
    )

    event_type: Mapped[AuditEventType] = mapped_column(
        Enum(AuditEventType, name="audit_event_type"), nullable=False, index=True
    )
    outcome: Mapped[AuditOutcome] = mapped_column(
        Enum(AuditOutcome, name="audit_outcome"), nullable=False
    )

    actor_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID, ForeignKey("users.id", ondelete="SET NULL"), index=True
    )
    actor_label: Mapped[str | None] = mapped_column(String(64))  # username snapshot

    resource_type: Mapped[str | None] = mapped_column(String(48))
    resource_id: Mapped[str | None] = mapped_column(String(64), index=True)
    action: Mapped[str | None] = mapped_column(String(64))

    ip_address: Mapped[str | None] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(String(256))
    detail: Mapped[dict | None] = mapped_column(JSONType)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    # Tamper-evident hash chain.
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    entry_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)


class SecurityAlert(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """A security event surfaced to the monitoring dashboard / responders."""

    __tablename__ = "security_alerts"
    __table_args__ = (Index("ix_security_alerts_status_severity", "status", "severity"),)

    alert_type: Mapped[AlertType] = mapped_column(
        Enum(AlertType, name="alert_type"), nullable=False, index=True
    )
    severity: Mapped[AlertSeverity] = mapped_column(
        Enum(AlertSeverity, name="alert_severity"), nullable=False, index=True
    )
    status: Mapped[AlertStatus] = mapped_column(
        Enum(AlertStatus, name="alert_status"), nullable=False, default=AlertStatus.open
    )

    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    source_ip: Mapped[str | None] = mapped_column(String(64))

    related_file_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID, ForeignKey("files.id", ondelete="SET NULL")
    )
    related_user_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID, ForeignKey("users.id", ondelete="SET NULL")
    )

    acknowledged_by: Mapped[uuid.UUID | None] = mapped_column(
        GUID, ForeignKey("users.id", ondelete="SET NULL")
    )
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
