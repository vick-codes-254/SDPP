"""System administration: feature flags, settings, backups, integrations."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import BackupStatus, IntegrationStatus
from app.models.sysadmin import BackupRecord, FeatureFlag, Integration, Setting
from app.services.exceptions import NotFoundError


def _now() -> datetime:
    return datetime.now(UTC)


class AdminService:
    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    # ── Feature flags ───────────────────────────────────────────
    async def list_flags(self, *, organization_id: uuid.UUID | None = None) -> list[FeatureFlag]:
        stmt = select(FeatureFlag).order_by(FeatureFlag.key)
        # Return global flags + this org's overrides.
        if organization_id is not None:
            stmt = stmt.where(
                (FeatureFlag.organization_id == organization_id)
                | (FeatureFlag.organization_id.is_(None))
            )
        return list((await self.db.execute(stmt)).scalars().all())

    async def set_flag(self, *, key: str, enabled: bool, organization_id: uuid.UUID | None = None,
                       description: str | None = None) -> FeatureFlag:
        stmt = select(FeatureFlag).where(FeatureFlag.key == key)
        stmt = stmt.where(FeatureFlag.organization_id == organization_id) if organization_id \
            else stmt.where(FeatureFlag.organization_id.is_(None))
        flag = (await self.db.execute(stmt)).scalar_one_or_none()
        if flag is None:
            flag = FeatureFlag(id=uuid.uuid4(), organization_id=organization_id, key=key)
            self.db.add(flag)
        flag.enabled = enabled
        if description is not None:
            flag.description = description
        await self.db.flush()
        return flag

    # ── Settings ────────────────────────────────────────────────
    async def list_settings(self, *, organization_id: uuid.UUID | None = None) -> list[Setting]:
        stmt = select(Setting).order_by(Setting.key)
        if organization_id is not None:
            stmt = stmt.where(
                (Setting.organization_id == organization_id) | (Setting.organization_id.is_(None))
            )
        return list((await self.db.execute(stmt)).scalars().all())

    async def set_setting(self, *, key: str, value: Any, scope, organization_id: uuid.UUID | None = None,
                          ) -> Setting:
        stmt = select(Setting).where(Setting.key == key)
        stmt = stmt.where(Setting.organization_id == organization_id) if organization_id \
            else stmt.where(Setting.organization_id.is_(None))
        setting = (await self.db.execute(stmt)).scalar_one_or_none()
        if setting is None:
            setting = Setting(id=uuid.uuid4(), organization_id=organization_id, key=key, scope=scope)
            self.db.add(setting)
        setting.value = value
        setting.scope = scope
        await self.db.flush()
        return setting

    # ── Backups (records the operation; storage integration pluggable) ─
    async def list_backups(self, *, organization_id: uuid.UUID | None = None) -> list[BackupRecord]:
        stmt = select(BackupRecord).order_by(BackupRecord.created_at.desc())
        if organization_id is not None:
            stmt = stmt.where(BackupRecord.organization_id == organization_id)
        return list((await self.db.execute(stmt)).scalars().all())

    async def create_backup(self, *, organization_id: uuid.UUID | None = None,
                            note: str | None = None) -> BackupRecord:
        now = _now()
        rec = BackupRecord(
            id=uuid.uuid4(), organization_id=organization_id, status=BackupStatus.completed,
            location=f"backups/{organization_id or 'global'}/{now:%Y%m%dT%H%M%S}.enc",
            size_bytes=0, note=note, completed_at=now,
        )
        self.db.add(rec)
        await self.db.flush()
        return rec

    # ── Integrations ────────────────────────────────────────────
    async def list_integrations(self, *, organization_id: uuid.UUID) -> list[Integration]:
        return list((await self.db.execute(
            select(Integration).where(Integration.organization_id == organization_id)
            .order_by(Integration.name)
        )).scalars().all())

    async def create_integration(self, data: dict[str, Any]) -> Integration:
        integ = Integration(id=uuid.uuid4(), **data)
        self.db.add(integ)
        await self.db.flush()
        return integ

    async def set_integration_status(self, integration_id: uuid.UUID, *, active: bool) -> Integration:
        integ = (await self.db.execute(
            select(Integration).where(Integration.id == integration_id)
        )).scalar_one_or_none()
        if integ is None:
            raise NotFoundError("Integration not found")
        integ.status = IntegrationStatus.active if active else IntegrationStatus.inactive
        integ.last_sync_at = _now()
        await self.db.flush()
        return integ
