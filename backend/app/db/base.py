"""SQLAlchemy declarative base, naming conventions, and reusable mixins.

A consistent constraint naming convention is essential for Alembic to generate
stable, reversible migrations (especially for ``ALTER``/``DROP`` of named
constraints across databases).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import DateTime, ForeignKey, MetaData, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from app.db.types import GUID


def _utcnow() -> datetime:
    return datetime.now(UTC)

# Deterministic constraint names -> clean, reversible migrations.
NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    """Declarative base for all ORM models."""

    metadata = MetaData(naming_convention=NAMING_CONVENTION)


class UUIDPrimaryKeyMixin:
    """Adds a UUID v4 primary key (non-sequential, non-enumerable)."""

    id: Mapped[uuid.UUID] = mapped_column(
        GUID,
        primary_key=True,
        default=uuid.uuid4,
    )


class TimestampMixin:
    """Adds DB-managed created/updated timestamps (UTC)."""

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=_utcnow,  # populate the Python instance on flush
        server_default=func.now(),  # DB-side default for out-of-band inserts
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=_utcnow,
        server_default=func.now(),
        onupdate=_utcnow,
        nullable=False,
    )


class TenantMixin:
    """Adds the multi-tenant scoping FK.

    Every tenant-owned record carries the owning ``organization_id`` so all
    queries can be isolated per tenant. The column is copied onto each mapped
    subclass (SQLAlchemy mixin column semantics)."""

    organization_id: Mapped[uuid.UUID] = mapped_column(
        GUID,
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
