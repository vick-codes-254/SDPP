"""Identity & access models: users, roles, permissions, password history, tokens."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Table,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.security.field_encryption import BlindIndex, EncryptedString
from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin
from app.db.types import GUID

# ── Many-to-many association tables ─────────────────────────────
user_roles = Table(
    "user_roles",
    Base.metadata,
    Column("user_id", GUID, ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
    Column("role_id", GUID, ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True),
)

role_permissions = Table(
    "role_permissions",
    Base.metadata,
    Column("role_id", GUID, ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True),
    Column("permission_id", GUID, ForeignKey("permissions.id", ondelete="CASCADE"), primary_key=True),
)


class User(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "users"

    # Login identifier (non-PII handle). Email/full name are encrypted PII.
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)

    email: Mapped[str] = mapped_column(EncryptedString(context="users.email"), nullable=False)
    # Deterministic blind index enables "find user by email" without decryption.
    email_bidx: Mapped[str] = mapped_column(BlindIndex(), unique=True, index=True, nullable=False)
    full_name: Mapped[str | None] = mapped_column(EncryptedString(context="users.full_name"))
    phone: Mapped[str | None] = mapped_column(EncryptedString(context="users.phone"))

    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)

    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_superuser: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # MFA (TOTP secret stored encrypted).
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    mfa_secret: Mapped[str | None] = mapped_column(EncryptedString(context="users.mfa_secret"))

    # Brute-force / lockout state.
    failed_login_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # Password lifecycle.
    password_changed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    roles: Mapped[list[Role]] = relationship(
        secondary=user_roles, back_populates="users", lazy="selectin"
    )
    password_history: Mapped[list[PasswordHistory]] = relationship(
        back_populates="user", cascade="all, delete-orphan", lazy="selectin"
    )
    refresh_tokens: Mapped[list[RefreshToken]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )


class Role(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "roles"

    name: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    description: Mapped[str | None] = mapped_column(String(255))
    is_system: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    users: Mapped[list[User]] = relationship(secondary=user_roles, back_populates="roles")
    permissions: Mapped[list[Permission]] = relationship(
        secondary=role_permissions, back_populates="roles", lazy="selectin"
    )


class Permission(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "permissions"

    # e.g. "file:upload", "key:rotate", "audit:read"
    code: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    resource: Mapped[str] = mapped_column(String(32), nullable=False)
    action: Mapped[str] = mapped_column(String(32), nullable=False)
    description: Mapped[str | None] = mapped_column(String(255))

    roles: Mapped[list[Role]] = relationship(
        secondary=role_permissions, back_populates="permissions"
    )


class PasswordHistory(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "password_history"

    user_id: Mapped[uuid.UUID] = mapped_column(
        GUID, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )

    user: Mapped[User] = relationship(back_populates="password_history")


class RefreshToken(Base, UUIDPrimaryKeyMixin):
    """Server-side record enabling refresh-token rotation & revocation."""

    __tablename__ = "refresh_tokens"
    __table_args__ = (UniqueConstraint("jti", name="uq_refresh_tokens_jti"),)

    user_id: Mapped[uuid.UUID] = mapped_column(
        GUID, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    jti: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    replaced_by_jti: Mapped[str | None] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(String(255))
    ip_address: Mapped[str | None] = mapped_column(EncryptedString(context="refresh_tokens.ip"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    user: Mapped[User] = relationship(back_populates="refresh_tokens")

    @property
    def is_active(self) -> bool:
        return self.revoked_at is None
