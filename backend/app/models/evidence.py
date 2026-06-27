"""Evidence management with chain of custody.

Evidence items reference encrypted vault objects (the SDPP file vault) and carry a
SHA-256 integrity hash. Every handling action (collected/accessed/transferred/
sealed/released) is appended to an ordered custody log so provenance is auditable.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Enum, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.enums import CustodyAction, EvidenceStatus, EvidenceType
from app.core.security.field_encryption import EncryptedText
from app.db.base import Base, TenantMixin, TimestampMixin, UUIDPrimaryKeyMixin
from app.db.types import GUID, JSONType


class Evidence(Base, UUIDPrimaryKeyMixin, TenantMixin, TimestampMixin):
    __tablename__ = "evidence"

    title: Mapped[str] = mapped_column(String(255), nullable=False)
    evidence_type: Mapped[EvidenceType] = mapped_column(
        Enum(EvidenceType, name="evidence_type"), nullable=False, default=EvidenceType.other
    )
    status: Mapped[EvidenceStatus] = mapped_column(
        Enum(EvidenceStatus, name="evidence_status"),
        nullable=False, default=EvidenceStatus.collected, index=True,
    )

    incident_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID, ForeignKey("incidents.id", ondelete="SET NULL"), index=True
    )
    file_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID, ForeignKey("files.id", ondelete="SET NULL")
    )
    sha256: Mapped[str | None] = mapped_column(String(64), index=True)
    source: Mapped[str | None] = mapped_column(String(255))
    description: Mapped[str | None] = mapped_column(EncryptedText(context="evidence.description"))
    tags: Mapped[list | None] = mapped_column(JSONType)

    collected_by: Mapped[uuid.UUID | None] = mapped_column(
        GUID, ForeignKey("users.id", ondelete="SET NULL")
    )
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    custody: Mapped[list[CustodyEntry]] = relationship(
        back_populates="evidence", cascade="all, delete-orphan",
        order_by="CustodyEntry.occurred_at", lazy="selectin",
    )


class CustodyEntry(Base, UUIDPrimaryKeyMixin):
    """An append-only chain-of-custody record for a piece of evidence."""

    __tablename__ = "custody_entries"

    evidence_id: Mapped[uuid.UUID] = mapped_column(
        GUID, ForeignKey("evidence.id", ondelete="CASCADE"), nullable=False, index=True
    )
    action: Mapped[CustodyAction] = mapped_column(
        Enum(CustodyAction, name="custody_action"), nullable=False
    )
    actor_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID, ForeignKey("users.id", ondelete="SET NULL")
    )
    from_party: Mapped[str | None] = mapped_column(String(255))
    to_party: Mapped[str | None] = mapped_column(String(255))
    notes: Mapped[str | None] = mapped_column(String(500))
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    evidence: Mapped[Evidence] = relationship(back_populates="custody")
