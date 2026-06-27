"""Tenancy & physical-estate service.

CRUD over the multi-tenant hierarchy: organizations -> branches/departments and
organizations -> sites -> buildings/zones/checkpoints. Mutations are recorded to
the tamper-evident audit log (as ``config_change`` events).
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import AuditEventType, AuditOutcome
from app.models.organization import Branch, Department, Organization
from app.models.site import Building, Checkpoint, Site, Zone
from app.services.audit_service import AuditService
from app.services.exceptions import ConflictError, NotFoundError


class OrgService:
    def __init__(self, db: AsyncSession, *, audit: AuditService | None = None) -> None:
        self.db = db
        self.audit = audit or AuditService(db)

    async def _audit(self, action: str, resource_type: str, resource_id: str,
                     actor_id: uuid.UUID | None, detail: dict[str, Any] | None = None) -> None:
        await self.audit.record(
            event_type=AuditEventType.config_change, outcome=AuditOutcome.success,
            actor_id=actor_id, resource_type=resource_type, resource_id=resource_id,
            action=action, detail=detail or {},
        )

    # ── Organizations ───────────────────────────────────────────
    async def list_orgs(self, *, limit: int = 100, offset: int = 0) -> list[Organization]:
        stmt = select(Organization).order_by(Organization.created_at.desc()).limit(limit).offset(offset)
        return list((await self.db.execute(stmt)).scalars().all())

    async def get_org_or_404(self, org_id: uuid.UUID) -> Organization:
        org = (await self.db.execute(select(Organization).where(Organization.id == org_id))).scalar_one_or_none()
        if org is None:
            raise NotFoundError("Organization not found")
        return org

    async def create_org(self, data: dict[str, Any], *, actor_id: uuid.UUID | None = None) -> Organization:
        exists = (await self.db.execute(
            select(Organization.id).where(Organization.slug == data["slug"])
        )).scalar_one_or_none()
        if exists is not None:
            raise ConflictError(f"Organization slug '{data['slug']}' already exists")
        org = Organization(id=uuid.uuid4(), **data)
        self.db.add(org)
        await self.db.flush()
        await self._audit("create", "organization", str(org.id), actor_id, {"slug": org.slug})
        return org

    async def update_org(self, org_id: uuid.UUID, changes: dict[str, Any], *,
                         actor_id: uuid.UUID | None = None) -> Organization:
        org = await self.get_org_or_404(org_id)
        for k, v in changes.items():
            if hasattr(org, k):
                setattr(org, k, v)
        await self.db.flush()
        await self._audit("update", "organization", str(org.id), actor_id, {"fields": sorted(changes)})
        return org

    async def delete_org(self, org_id: uuid.UUID, *, actor_id: uuid.UUID | None = None) -> None:
        org = await self.get_org_or_404(org_id)
        await self.db.delete(org)
        await self.db.flush()
        await self._audit("delete", "organization", str(org_id), actor_id)

    # ── Branches / departments ──────────────────────────────────
    async def list_branches(self, org_id: uuid.UUID) -> list[Branch]:
        return list((await self.db.execute(
            select(Branch).where(Branch.organization_id == org_id).order_by(Branch.name)
        )).scalars().all())

    async def create_branch(self, data: dict[str, Any], *, actor_id: uuid.UUID | None = None) -> Branch:
        branch = Branch(id=uuid.uuid4(), **data)
        self.db.add(branch)
        await self.db.flush()
        await self._audit("create", "branch", str(branch.id), actor_id)
        return branch

    async def list_departments(self, org_id: uuid.UUID) -> list[Department]:
        return list((await self.db.execute(
            select(Department).where(Department.organization_id == org_id).order_by(Department.name)
        )).scalars().all())

    async def create_department(self, data: dict[str, Any], *, actor_id: uuid.UUID | None = None) -> Department:
        dept = Department(id=uuid.uuid4(), **data)
        self.db.add(dept)
        await self.db.flush()
        await self._audit("create", "department", str(dept.id), actor_id)
        return dept

    # ── Sites ───────────────────────────────────────────────────
    async def list_sites(self, *, organization_id: uuid.UUID | None = None,
                         limit: int = 200, offset: int = 0) -> list[Site]:
        stmt = select(Site).order_by(Site.created_at.desc())
        if organization_id is not None:
            stmt = stmt.where(Site.organization_id == organization_id)
        return list((await self.db.execute(stmt.limit(limit).offset(offset))).scalars().all())

    async def get_site_or_404(self, site_id: uuid.UUID) -> Site:
        site = (await self.db.execute(select(Site).where(Site.id == site_id))).scalar_one_or_none()
        if site is None:
            raise NotFoundError("Site not found")
        return site

    async def create_site(self, data: dict[str, Any], *, actor_id: uuid.UUID | None = None) -> Site:
        site = Site(id=uuid.uuid4(), **data)
        self.db.add(site)
        await self.db.flush()
        await self._audit("create", "site", str(site.id), actor_id, {"name": site.name})
        return site

    async def update_site(self, site_id: uuid.UUID, changes: dict[str, Any], *,
                          actor_id: uuid.UUID | None = None) -> Site:
        site = await self.get_site_or_404(site_id)
        for k, v in changes.items():
            if hasattr(site, k):
                setattr(site, k, v)
        await self.db.flush()
        await self._audit("update", "site", str(site.id), actor_id, {"fields": sorted(changes)})
        return site

    async def delete_site(self, site_id: uuid.UUID, *, actor_id: uuid.UUID | None = None) -> None:
        site = await self.get_site_or_404(site_id)
        await self.db.delete(site)
        await self.db.flush()
        await self._audit("delete", "site", str(site_id), actor_id)

    # ── Buildings ───────────────────────────────────────────────
    async def list_buildings(self, site_id: uuid.UUID) -> list[Building]:
        return list((await self.db.execute(
            select(Building).where(Building.site_id == site_id).order_by(Building.name)
        )).scalars().all())

    async def create_building(self, data: dict[str, Any], *, actor_id: uuid.UUID | None = None) -> Building:
        building = Building(id=uuid.uuid4(), **data)
        self.db.add(building)
        await self.db.flush()
        await self._audit("create", "building", str(building.id), actor_id)
        return building

    # ── Zones ───────────────────────────────────────────────────
    async def list_zones(self, *, site_id: uuid.UUID | None = None,
                         organization_id: uuid.UUID | None = None) -> list[Zone]:
        stmt = select(Zone).order_by(Zone.name)
        if site_id is not None:
            stmt = stmt.where(Zone.site_id == site_id)
        if organization_id is not None:
            stmt = stmt.where(Zone.organization_id == organization_id)
        return list((await self.db.execute(stmt)).scalars().all())

    async def create_zone(self, data: dict[str, Any], *, actor_id: uuid.UUID | None = None) -> Zone:
        zone = Zone(id=uuid.uuid4(), **data)
        self.db.add(zone)
        await self.db.flush()
        await self._audit("create", "zone", str(zone.id), actor_id, {"type": str(zone.zone_type)})
        return zone

    async def delete_zone(self, zone_id: uuid.UUID, *, actor_id: uuid.UUID | None = None) -> None:
        zone = (await self.db.execute(select(Zone).where(Zone.id == zone_id))).scalar_one_or_none()
        if zone is None:
            raise NotFoundError("Zone not found")
        await self.db.delete(zone)
        await self.db.flush()
        await self._audit("delete", "zone", str(zone_id), actor_id)

    # ── Checkpoints ─────────────────────────────────────────────
    async def list_checkpoints(self, *, site_id: uuid.UUID | None = None,
                               organization_id: uuid.UUID | None = None) -> list[Checkpoint]:
        stmt = select(Checkpoint).order_by(Checkpoint.name)
        if site_id is not None:
            stmt = stmt.where(Checkpoint.site_id == site_id)
        if organization_id is not None:
            stmt = stmt.where(Checkpoint.organization_id == organization_id)
        return list((await self.db.execute(stmt)).scalars().all())

    async def create_checkpoint(self, data: dict[str, Any], *, actor_id: uuid.UUID | None = None) -> Checkpoint:
        cp = Checkpoint(id=uuid.uuid4(), **data)
        self.db.add(cp)
        await self.db.flush()
        await self._audit("create", "checkpoint", str(cp.id), actor_id)
        return cp

    # ── Aggregate counts (for dashboards) ───────────────────────
    async def counts(self, *, organization_id: uuid.UUID | None = None) -> dict[str, int]:
        async def _count(model, tenant_col=None) -> int:
            stmt = select(func.count()).select_from(model)
            if organization_id is not None and tenant_col is not None:
                stmt = stmt.where(tenant_col == organization_id)
            return int((await self.db.execute(stmt)).scalar_one())

        return {
            "organizations": await _count(Organization),
            "sites": await _count(Site, Site.organization_id),
            "zones": await _count(Zone, Zone.organization_id),
            "checkpoints": await _count(Checkpoint, Checkpoint.organization_id),
        }
