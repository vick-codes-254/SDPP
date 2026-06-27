"""Visitor and contractor models.

Visitor/contractor identity data is PII and stored encrypted at rest. Blacklist
checks use a deterministic blind index on the full name so a banned visitor can be
detected on re-registration without decrypting the directory.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.enums import ContractorStatus, VisitorStatus
from app.core.security.field_encryption import BlindIndex, EncryptedString
from app.db.base import Base, TenantMixin, TimestampMixin, UUIDPrimaryKeyMixin
from app.db.types import GUID


class Visitor(Base, UUIDPrimaryKeyMixin, TenantMixin, TimestampMixin):
    __tablename__ = "visitors"

    site_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID, ForeignKey("sites.id", ondelete="SET NULL"), index=True
    )
    full_name: Mapped[str] = mapped_column(EncryptedString(context="visitors.full_name"), nullable=False)
    name_bidx: Mapped[str | None] = mapped_column(BlindIndex(), index=True)  # blacklist lookup
    phone: Mapped[str | None] = mapped_column(EncryptedString(context="visitors.phone"))
    id_number: Mapped[str | None] = mapped_column(EncryptedString(context="visitors.id_number"))
    photo_ref: Mapped[str | None] = mapped_column(String(255))  # vault object id for the capture

    company: Mapped[str | None] = mapped_column(String(255))
    host_name: Mapped[str | None] = mapped_column(String(255))
    purpose: Mapped[str | None] = mapped_column(String(255))

    status: Mapped[VisitorStatus] = mapped_column(
        Enum(VisitorStatus, name="visitor_status"),
        nullable=False, default=VisitorStatus.pending_approval, index=True,
    )
    badge_code: Mapped[str | None] = mapped_column(String(32), index=True)
    check_in_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    check_out_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Contractor(Base, UUIDPrimaryKeyMixin, TenantMixin, TimestampMixin):
    __tablename__ = "contractors"

    company: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    contact_name: Mapped[str | None] = mapped_column(EncryptedString(context="contractors.contact"))
    contact_phone: Mapped[str | None] = mapped_column(EncryptedString(context="contractors.phone"))

    work_permit_no: Mapped[str | None] = mapped_column(String(64), index=True)
    permit_expiry: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[ContractorStatus] = mapped_column(
        Enum(ContractorStatus, name="contractor_status"),
        nullable=False, default=ContractorStatus.pending, index=True,
    )
    safety_compliant: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    access_approved: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
