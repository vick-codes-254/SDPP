"""Access control endpoints: access points and access events."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, status

from app.api.deps import get_access_service, require_permission
from app.schemas.common import Message
from app.schemas.physical import (
    AccessEventCreate,
    AccessEventResponse,
    AccessPointCreate,
    AccessPointResponse,
    AccessPointUpdate,
)
from app.services.physical_service import AccessService

router = APIRouter(prefix="/access", tags=["access-control"])

Dep = Annotated[AccessService, Depends(get_access_service)]


@router.get("/points", response_model=list[AccessPointResponse])
async def list_points(
    svc: Dep,
    _: Annotated[object, Depends(require_permission("access:read"))],
    organization_id: uuid.UUID | None = None,
    site_id: uuid.UUID | None = None,
) -> list[AccessPointResponse]:
    rows = await svc.list(organization_id=organization_id, filters={"site_id": site_id})
    return [AccessPointResponse.model_validate(p) for p in rows]


@router.post("/points", response_model=AccessPointResponse, status_code=status.HTTP_201_CREATED)
async def create_point(
    body: AccessPointCreate,
    svc: Dep,
    principal: Annotated[object, Depends(require_permission("access:manage"))],
) -> AccessPointResponse:
    point = await svc.create(body.model_dump(), actor_id=principal.user_id)  # type: ignore[attr-defined]
    return AccessPointResponse.model_validate(point)


@router.patch("/points/{point_id}", response_model=AccessPointResponse)
async def update_point(
    point_id: uuid.UUID,
    body: AccessPointUpdate,
    svc: Dep,
    principal: Annotated[object, Depends(require_permission("access:manage"))],
) -> AccessPointResponse:
    point = await svc.update(point_id, body.model_dump(exclude_unset=True), actor_id=principal.user_id)  # type: ignore[attr-defined]
    return AccessPointResponse.model_validate(point)


@router.delete("/points/{point_id}", response_model=Message)
async def delete_point(
    point_id: uuid.UUID,
    svc: Dep,
    principal: Annotated[object, Depends(require_permission("access:manage"))],
) -> Message:
    await svc.delete(point_id, actor_id=principal.user_id)  # type: ignore[attr-defined]
    return Message(detail="Access point deleted")


@router.get("/events", response_model=list[AccessEventResponse])
async def list_events(
    svc: Dep,
    _: Annotated[object, Depends(require_permission("access:read"))],
    organization_id: uuid.UUID | None = None,
) -> list[AccessEventResponse]:
    rows = await svc.recent_events(organization_id=organization_id)
    return [AccessEventResponse.model_validate(e) for e in rows]


@router.post("/events", response_model=AccessEventResponse, status_code=status.HTTP_201_CREATED)
async def log_event(
    body: AccessEventCreate,
    svc: Dep,
    _: Annotated[object, Depends(require_permission("access:manage"))],
) -> AccessEventResponse:
    event = await svc.log_event(
        organization_id=body.organization_id, access_point_id=body.access_point_id,
        credential_type=body.credential_type, subject_label=body.subject_label,
        decision=body.decision, reason=body.reason,
    )
    return AccessEventResponse.model_validate(event)
