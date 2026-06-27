"""Multi-tenant organization hierarchy: organizations, branches, departments.

The platform is multi-tenant. Every operational record ultimately belongs to an
``Organization`` (the tenant). Branches and departments provide internal company
structure; the physical estate (sites, buildings, zones) lives in ``site.py``.
"""

from __future__ import annotations

import uuid

from sqlalchemy import Boolean, Enum, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.enums import OrgStatus, SubscriptionPlan
from app.core.security.field_encryption import EncryptedString
from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin
from app.db.types import GUID, JSONType


class Organization(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """A tenant: a company/customer that owns sites, users, devices, and data."""

    __tablename__ = "organizations"

    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    slug: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)

    status: Mapped[OrgStatus] = mapped_column(
        Enum(OrgStatus, name="org_status"),
        nullable=False, default=OrgStatus.trial, index=True,
    )
    plan: Mapped[SubscriptionPlan] = mapped_column(
        Enum(SubscriptionPlan, name="subscription_plan"),
        nullable=False, default=SubscriptionPlan.trial,
    )

    # Encrypted tenant contact PII.
    contact_email: Mapped[str | None] = mapped_column(EncryptedString(context="org.contact_email"))
    contact_phone: Mapped[str | None] = mapped_column(EncryptedString(context="org.contact_phone"))
    address: Mapped[str | None] = mapped_column(EncryptedString(context="org.address"))

    country: Mapped[str | None] = mapped_column(String(64))
    timezone: Mapped[str] = mapped_column(String(64), nullable=False, default="UTC")
    settings: Mapped[dict | None] = mapped_column(JSONType)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    branches: Mapped[list[Branch]] = relationship(
        back_populates="organization", cascade="all, delete-orphan", lazy="selectin"
    )
    departments: Mapped[list[Department]] = relationship(
        back_populates="organization", cascade="all, delete-orphan", lazy="selectin"
    )


class Branch(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """A regional/divisional grouping of sites within an organization."""

    __tablename__ = "branches"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        GUID, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    code: Mapped[str | None] = mapped_column(String(32))
    city: Mapped[str | None] = mapped_column(String(128))
    country: Mapped[str | None] = mapped_column(String(64))

    organization: Mapped[Organization] = relationship(back_populates="branches")


class Department(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """An internal department; supports a self-referential hierarchy."""

    __tablename__ = "departments"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        GUID, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    parent_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID, ForeignKey("departments.id", ondelete="SET NULL")
    )

    organization: Mapped[Organization] = relationship(back_populates="departments")
