"""Site management endpoints: sites, buildings, zones, checkpoints."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query, status

from app.api.deps import get_org_service, require_permission
from app.schemas.common import Message
from app.schemas.tenancy import (
    BuildingCreate,
    BuildingResponse,
    CheckpointCreate,
    CheckpointResponse,
    SiteCreate,
    SiteResponse,
    SiteUpdate,
    ZoneCreate,
    ZoneResponse,
)
from app.services.org_service import OrgService

router = APIRouter(prefix="/sites", tags=["site-management"])

OrgDep = Annotated[OrgService, Depends(get_org_service)]


@router.get("", response_model=list[SiteResponse])
async def list_sites(
    svc: OrgDep,
    _: Annotated[object, Depends(require_permission("site:read"))],
    organization_id: uuid.UUID | None = None,
) -> list[SiteResponse]:
    rows = await svc.list_sites(organization_id=organization_id)
    return [SiteResponse.model_validate(s) for s in rows]


@router.post("", response_model=SiteResponse, status_code=status.HTTP_201_CREATED)
async def create_site(
    body: SiteCreate,
    svc: OrgDep,
    principal: Annotated[object, Depends(require_permission("site:manage"))],
) -> SiteResponse:
    site = await svc.create_site(body.model_dump(), actor_id=principal.user_id)  # type: ignore[attr-defined]
    return SiteResponse.model_validate(site)


@router.get("/{site_id}", response_model=SiteResponse)
async def get_site(
    site_id: uuid.UUID,
    svc: OrgDep,
    _: Annotated[object, Depends(require_permission("site:read"))],
) -> SiteResponse:
    return SiteResponse.model_validate(await svc.get_site_or_404(site_id))


@router.patch("/{site_id}", response_model=SiteResponse)
async def update_site(
    site_id: uuid.UUID,
    body: SiteUpdate,
    svc: OrgDep,
    principal: Annotated[object, Depends(require_permission("site:manage"))],
) -> SiteResponse:
    site = await svc.update_site(site_id, body.model_dump(exclude_unset=True), actor_id=principal.user_id)  # type: ignore[attr-defined]
    return SiteResponse.model_validate(site)


@router.delete("/{site_id}", response_model=Message)
async def delete_site(
    site_id: uuid.UUID,
    svc: OrgDep,
    principal: Annotated[object, Depends(require_permission("site:manage"))],
) -> Message:
    await svc.delete_site(site_id, actor_id=principal.user_id)  # type: ignore[attr-defined]
    return Message(detail="Site deleted")


# ── Buildings ───────────────────────────────────────────────────
@router.get("/{site_id}/buildings", response_model=list[BuildingResponse])
async def list_buildings(
    site_id: uuid.UUID,
    svc: OrgDep,
    _: Annotated[object, Depends(require_permission("site:read"))],
) -> list[BuildingResponse]:
    return [BuildingResponse.model_validate(b) for b in await svc.list_buildings(site_id)]


@router.post("/buildings", response_model=BuildingResponse, status_code=status.HTTP_201_CREATED)
async def create_building(
    body: BuildingCreate,
    svc: OrgDep,
    principal: Annotated[object, Depends(require_permission("site:manage"))],
) -> BuildingResponse:
    building = await svc.create_building(body.model_dump(), actor_id=principal.user_id)  # type: ignore[attr-defined]
    return BuildingResponse.model_validate(building)


# ── Zones ───────────────────────────────────────────────────────
@router.get("/zones/list", response_model=list[ZoneResponse])
async def list_zones(
    svc: OrgDep,
    _: Annotated[object, Depends(require_permission("site:read"))],
    site_id: Annotated[uuid.UUID | None, Query()] = None,
    organization_id: Annotated[uuid.UUID | None, Query()] = None,
) -> list[ZoneResponse]:
    rows = await svc.list_zones(site_id=site_id, organization_id=organization_id)
    return [ZoneResponse.model_validate(z) for z in rows]


@router.post("/zones", response_model=ZoneResponse, status_code=status.HTTP_201_CREATED)
async def create_zone(
    body: ZoneCreate,
    svc: OrgDep,
    principal: Annotated[object, Depends(require_permission("site:manage"))],
) -> ZoneResponse:
    zone = await svc.create_zone(body.model_dump(), actor_id=principal.user_id)  # type: ignore[attr-defined]
    return ZoneResponse.model_validate(zone)


@router.delete("/zones/{zone_id}", response_model=Message)
async def delete_zone(
    zone_id: uuid.UUID,
    svc: OrgDep,
    principal: Annotated[object, Depends(require_permission("site:manage"))],
) -> Message:
    await svc.delete_zone(zone_id, actor_id=principal.user_id)  # type: ignore[attr-defined]
    return Message(detail="Zone deleted")


# ── Checkpoints ─────────────────────────────────────────────────
@router.get("/checkpoints/list", response_model=list[CheckpointResponse])
async def list_checkpoints(
    svc: OrgDep,
    _: Annotated[object, Depends(require_permission("site:read"))],
    site_id: Annotated[uuid.UUID | None, Query()] = None,
    organization_id: Annotated[uuid.UUID | None, Query()] = None,
) -> list[CheckpointResponse]:
    rows = await svc.list_checkpoints(site_id=site_id, organization_id=organization_id)
    return [CheckpointResponse.model_validate(c) for c in rows]


@router.post("/checkpoints", response_model=CheckpointResponse, status_code=status.HTTP_201_CREATED)
async def create_checkpoint(
    body: CheckpointCreate,
    svc: OrgDep,
    principal: Annotated[object, Depends(require_permission("site:manage"))],
) -> CheckpointResponse:
    cp = await svc.create_checkpoint(body.model_dump(), actor_id=principal.user_id)  # type: ignore[attr-defined]
    return CheckpointResponse.model_validate(cp)
