"""Guard workforce & patrol endpoints."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, status

from app.api.deps import get_guard_service, get_patrol_service, require_permission
from app.schemas.common import Message
from app.schemas.physical import (
    GuardCreate,
    GuardResponse,
    GuardUpdate,
    PatrolCreate,
    PatrolResponse,
    PatrolScanCreate,
    PatrolScanResponse,
)
from app.services.physical_service import GuardService, PatrolService

router = APIRouter(prefix="/guards", tags=["guard-management"])

GuardDep = Annotated[GuardService, Depends(get_guard_service)]
PatrolDep = Annotated[PatrolService, Depends(get_patrol_service)]


# ── Guards ──────────────────────────────────────────────────────
@router.get("", response_model=list[GuardResponse])
async def list_guards(
    svc: GuardDep,
    _: Annotated[object, Depends(require_permission("guard:read"))],
    organization_id: uuid.UUID | None = None,
    site_id: uuid.UUID | None = None,
) -> list[GuardResponse]:
    rows = await svc.list(organization_id=organization_id, filters={"site_id": site_id})
    return [GuardResponse.model_validate(g) for g in rows]


@router.post("", response_model=GuardResponse, status_code=status.HTTP_201_CREATED)
async def create_guard(
    body: GuardCreate,
    svc: GuardDep,
    principal: Annotated[object, Depends(require_permission("guard:manage"))],
) -> GuardResponse:
    guard = await svc.create(body.model_dump(), actor_id=principal.user_id)  # type: ignore[attr-defined]
    return GuardResponse.model_validate(guard)


@router.patch("/{guard_id}", response_model=GuardResponse)
async def update_guard(
    guard_id: uuid.UUID,
    body: GuardUpdate,
    svc: GuardDep,
    principal: Annotated[object, Depends(require_permission("guard:manage"))],
) -> GuardResponse:
    guard = await svc.update(guard_id, body.model_dump(exclude_unset=True), actor_id=principal.user_id)  # type: ignore[attr-defined]
    return GuardResponse.model_validate(guard)


@router.delete("/{guard_id}", response_model=Message)
async def delete_guard(
    guard_id: uuid.UUID,
    svc: GuardDep,
    principal: Annotated[object, Depends(require_permission("guard:manage"))],
) -> Message:
    await svc.delete(guard_id, actor_id=principal.user_id)  # type: ignore[attr-defined]
    return Message(detail="Guard deleted")


# ── Patrols ─────────────────────────────────────────────────────
@router.get("/patrols/list", response_model=list[PatrolResponse])
async def list_patrols(
    svc: PatrolDep,
    _: Annotated[object, Depends(require_permission("guard:read"))],
    organization_id: uuid.UUID | None = None,
    site_id: uuid.UUID | None = None,
) -> list[PatrolResponse]:
    rows = await svc.list(organization_id=organization_id, filters={"site_id": site_id})
    return [PatrolResponse.model_validate(p) for p in rows]


@router.post("/patrols", response_model=PatrolResponse, status_code=status.HTTP_201_CREATED)
async def create_patrol(
    body: PatrolCreate,
    svc: PatrolDep,
    principal: Annotated[object, Depends(require_permission("guard:manage"))],
) -> PatrolResponse:
    patrol = await svc.create(body.model_dump(), actor_id=principal.user_id)  # type: ignore[attr-defined]
    return PatrolResponse.model_validate(patrol)


@router.post("/patrols/{patrol_id}/scan", response_model=PatrolScanResponse)
async def record_patrol_scan(
    patrol_id: uuid.UUID,
    body: PatrolScanCreate,
    svc: PatrolDep,
    _: Annotated[object, Depends(require_permission("guard:manage"))],
) -> PatrolScanResponse:
    scan = await svc.record_scan(
        patrol_id, checkpoint_id=body.checkpoint_id, gps_verified=body.gps_verified,
        lat=body.lat, lng=body.lng,
    )
    return PatrolScanResponse.model_validate(scan)


@router.post("/patrols/{patrol_id}/complete", response_model=PatrolResponse)
async def complete_patrol(
    patrol_id: uuid.UUID,
    svc: PatrolDep,
    _: Annotated[object, Depends(require_permission("guard:manage"))],
) -> PatrolResponse:
    return PatrolResponse.model_validate(await svc.complete(patrol_id))
