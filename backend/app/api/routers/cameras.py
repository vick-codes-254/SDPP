"""Camera management & live-monitoring endpoints."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, status

from app.api.deps import get_camera_service, require_permission
from app.schemas.common import Message
from app.schemas.physical import (
    CameraCreate,
    CameraHeartbeat,
    CameraResponse,
    CameraUpdate,
)
from app.services.physical_service import CameraService

router = APIRouter(prefix="/cameras", tags=["camera-management"])

Dep = Annotated[CameraService, Depends(get_camera_service)]


@router.get("", response_model=list[CameraResponse])
async def list_cameras(
    svc: Dep,
    _: Annotated[object, Depends(require_permission("camera:read"))],
    organization_id: uuid.UUID | None = None,
    site_id: uuid.UUID | None = None,
) -> list[CameraResponse]:
    rows = await svc.list(organization_id=organization_id, filters={"site_id": site_id})
    return [CameraResponse.model_validate(c) for c in rows]


@router.get("/health", response_model=dict)
async def camera_health(
    svc: Dep,
    _: Annotated[object, Depends(require_permission("camera:read"))],
    organization_id: uuid.UUID | None = None,
) -> dict:
    return await svc.health_summary(organization_id=organization_id)


@router.post("", response_model=CameraResponse, status_code=status.HTTP_201_CREATED)
async def create_camera(
    body: CameraCreate,
    svc: Dep,
    principal: Annotated[object, Depends(require_permission("camera:manage"))],
) -> CameraResponse:
    cam = await svc.create(body.model_dump(), actor_id=principal.user_id)  # type: ignore[attr-defined]
    return CameraResponse.model_validate(cam)


@router.get("/{camera_id}", response_model=CameraResponse)
async def get_camera(
    camera_id: uuid.UUID,
    svc: Dep,
    _: Annotated[object, Depends(require_permission("camera:read"))],
) -> CameraResponse:
    return CameraResponse.model_validate(await svc.get_or_404(camera_id))


@router.patch("/{camera_id}", response_model=CameraResponse)
async def update_camera(
    camera_id: uuid.UUID,
    body: CameraUpdate,
    svc: Dep,
    principal: Annotated[object, Depends(require_permission("camera:manage"))],
) -> CameraResponse:
    cam = await svc.update(camera_id, body.model_dump(exclude_unset=True), actor_id=principal.user_id)  # type: ignore[attr-defined]
    return CameraResponse.model_validate(cam)


@router.post("/{camera_id}/heartbeat", response_model=CameraResponse)
async def camera_heartbeat(
    camera_id: uuid.UUID,
    body: CameraHeartbeat,
    svc: Dep,
    _: Annotated[object, Depends(require_permission("camera:manage"))],
) -> CameraResponse:
    cam = await svc.heartbeat(camera_id, online=body.online, recording=body.recording)
    return CameraResponse.model_validate(cam)


@router.delete("/{camera_id}", response_model=Message)
async def delete_camera(
    camera_id: uuid.UUID,
    svc: Dep,
    principal: Annotated[object, Depends(require_permission("camera:manage"))],
) -> Message:
    await svc.delete(camera_id, actor_id=principal.user_id)  # type: ignore[attr-defined]
    return Message(detail="Camera deleted")
