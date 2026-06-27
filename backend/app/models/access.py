"""Access control models: access points (doors/turnstiles/gates) and events.

Every entry attempt is logged as an immutable AccessEvent with the decision
(granted/denied). The subject's credential identity is encrypted at rest.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.enums import AccessDecision, AccessMethod, AccessPointType
from app.core.security.field_encryption import EncryptedString
from app.db.base import Base, TenantMixin, TimestampMixin, UUIDPrimaryKeyMixin
from app.db.types import GUID


class AccessPoint(Base, UUIDPrimaryKeyMixin, TenantMixin, TimestampMixin):
    __tablename__ = "access_points"

    site_id: Mapped[uuid.UUID] = mapped_column(
        GUID, ForeignKey("sites.id", ondelete="CASCADE"), nullable=False, index=True
    )
    zone_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID, ForeignKey("zones.id", ondelete="SET NULL")
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    point_type: Mapped[AccessPointType] = mapped_column(
        Enum(AccessPointType, name="access_point_type"),
        nullable=False, default=AccessPointType.door,
    )
    method: Mapped[AccessMethod] = mapped_column(
        Enum(AccessMethod, name="access_method"),
        nullable=False, default=AccessMethod.rfid,
    )
    is_locked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    is_online: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)


class AccessEvent(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "access_events"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        GUID, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    access_point_id: Mapped[uuid.UUID] = mapped_column(
        GUID, ForeignKey("access_points.id", ondelete="CASCADE"), nullable=False, index=True
    )
    credential_type: Mapped[AccessMethod] = mapped_column(
        Enum(AccessMethod, name="access_method"), nullable=False, default=AccessMethod.rfid
    )
    # Encrypted credential subject (card id / person reference).
    subject_label: Mapped[str | None] = mapped_column(EncryptedString(context="access.subject"))
    decision: Mapped[AccessDecision] = mapped_column(
        Enum(AccessDecision, name="access_decision"),
        nullable=False, default=AccessDecision.granted, index=True,
    )
    reason: Mapped[str | None] = mapped_column(String(255))
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
