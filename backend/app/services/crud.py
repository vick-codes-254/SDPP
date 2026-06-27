"""Generic tenant-scoped CRUD base for the platform's many domain entities.

Most modules need the same shape: list (optionally filtered by tenant), get/404,
create, update, delete — each mutation recorded to the tamper-evident audit log.
Domain services subclass this and add only their special behaviour (blind-index
computation, status transitions, watchlist checks, etc.).
"""

from __future__ import annotations

import uuid
from typing import Any, Generic, TypeVar

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import AuditEventType, AuditOutcome
from app.db.base import Base
from app.services.audit_service import AuditService
from app.services.exceptions import NotFoundError

M = TypeVar("M", bound=Base)


class CrudService(Generic[M]):
    #: ORM model class — set by subclasses.
    model: type[M]
    #: Label used in the audit trail (e.g. "camera").
    audit_resource: str = "record"
    #: Tenant scoping column name (None disables tenant filtering).
    tenant_field: str | None = "organization_id"

    def __init__(self, db: AsyncSession, *, audit: AuditService | None = None) -> None:
        self.db = db
        self.audit = audit or AuditService(db)

    # ── Hooks (override as needed) ──────────────────────────────
    def _pre_create(self, data: dict[str, Any]) -> dict[str, Any]:
        return data

    def _pre_update(self, obj: M, changes: dict[str, Any]) -> dict[str, Any]:
        return changes

    async def _audit(self, action: str, resource_id: str, actor_id: uuid.UUID | None,
                     detail: dict[str, Any] | None = None) -> None:
        await self.audit.record(
            event_type=AuditEventType.config_change, outcome=AuditOutcome.success,
            actor_id=actor_id, resource_type=self.audit_resource, resource_id=resource_id,
            action=action, detail=detail or {},
        )

    # ── Reads ───────────────────────────────────────────────────
    async def get(self, obj_id: uuid.UUID) -> M | None:
        return (await self.db.execute(
            select(self.model).where(self.model.id == obj_id)  # type: ignore[attr-defined]
        )).scalar_one_or_none()

    async def get_or_404(self, obj_id: uuid.UUID) -> M:
        obj = await self.get(obj_id)
        if obj is None:
            raise NotFoundError(f"{self.audit_resource.capitalize()} not found")
        return obj

    async def list(
        self,
        *,
        organization_id: uuid.UUID | None = None,
        filters: dict[str, Any] | None = None,
        order_desc: str | None = "created_at",
        limit: int = 200,
        offset: int = 0,
    ) -> list[M]:
        stmt = select(self.model)
        if organization_id is not None and self.tenant_field:
            stmt = stmt.where(getattr(self.model, self.tenant_field) == organization_id)
        for key, value in (filters or {}).items():
            if value is not None and hasattr(self.model, key):
                stmt = stmt.where(getattr(self.model, key) == value)
        if order_desc and hasattr(self.model, order_desc):
            stmt = stmt.order_by(getattr(self.model, order_desc).desc())
        return list((await self.db.execute(stmt.limit(limit).offset(offset))).scalars().all())

    # ── Writes ──────────────────────────────────────────────────
    async def create(self, data: dict[str, Any], *, actor_id: uuid.UUID | None = None) -> M:
        obj = self.model(id=uuid.uuid4(), **self._pre_create(dict(data)))  # type: ignore[call-arg]
        self.db.add(obj)
        await self.db.flush()
        await self._audit("create", str(obj.id), actor_id)  # type: ignore[attr-defined]
        return obj

    async def update(self, obj_id: uuid.UUID, changes: dict[str, Any], *,
                     actor_id: uuid.UUID | None = None) -> M:
        obj = await self.get_or_404(obj_id)
        for key, value in self._pre_update(obj, dict(changes)).items():
            if hasattr(obj, key):
                setattr(obj, key, value)
        await self.db.flush()
        await self._audit("update", str(obj_id), actor_id, {"fields": sorted(changes)})
        return obj

    async def delete(self, obj_id: uuid.UUID, *, actor_id: uuid.UUID | None = None) -> None:
        obj = await self.get_or_404(obj_id)
        await self.db.delete(obj)
        await self.db.flush()
        await self._audit("delete", str(obj_id), actor_id)
