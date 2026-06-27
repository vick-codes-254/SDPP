"""System administration models: feature flags, settings, backups, integrations.

Feature flags and settings can be global (organization_id NULL) or tenant-scoped.
Integration credentials are encrypted at rest.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import BigInteger, Boolean, DateTime, Enum, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.core.enums import (
    BackupStatus,
    IntegrationKind,
    IntegrationStatus,
    SettingScope,
)
from app.core.security.field_encryption import EncryptedText
from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin
from app.db.types import GUID, JSONType


class FeatureFlag(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "feature_flags"
    __table_args__ = (UniqueConstraint("organization_id", "key", name="uq_feature_flags_org_key"),)

    organization_id: Mapped[uuid.UUID | None] = mapped_column(GUID, index=True)  # NULL = global
    key: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    description: Mapped[str | None] = mapped_column(String(255))


class Setting(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "settings"
    __table_args__ = (UniqueConstraint("organization_id", "key", name="uq_settings_org_key"),)

    organization_id: Mapped[uuid.UUID | None] = mapped_column(GUID, index=True)  # NULL = global
    scope: Mapped[SettingScope] = mapped_column(
        Enum(SettingScope, name="setting_scope"), nullable=False, default=SettingScope.tenant
    )
    key: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    value: Mapped[dict | None] = mapped_column(JSONType)


class BackupRecord(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "backup_records"

    organization_id: Mapped[uuid.UUID | None] = mapped_column(GUID, index=True)
    status: Mapped[BackupStatus] = mapped_column(
        Enum(BackupStatus, name="backup_status"),
        nullable=False, default=BackupStatus.pending, index=True,
    )
    location: Mapped[str | None] = mapped_column(String(512))
    size_bytes: Mapped[int | None] = mapped_column(BigInteger)
    note: Mapped[str | None] = mapped_column(String(255))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Integration(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "integrations"

    organization_id: Mapped[uuid.UUID] = mapped_column(GUID, nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    kind: Mapped[IntegrationKind] = mapped_column(
        Enum(IntegrationKind, name="integration_kind"), nullable=False
    )
    status: Mapped[IntegrationStatus] = mapped_column(
        Enum(IntegrationStatus, name="integration_status"),
        nullable=False, default=IntegrationStatus.inactive, index=True,
    )
    # Connection secret/config encrypted at rest (JSON-encoded string).
    secret: Mapped[str | None] = mapped_column(EncryptedText(context="integration.secret"))
    config: Mapped[dict | None] = mapped_column(JSONType)
    last_sync_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
