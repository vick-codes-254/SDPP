"""Vehicle registry & ANPR endpoints."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, status

from app.api.deps import get_vehicle_service, require_permission
from app.schemas.common import Message
from app.schemas.physical import (
    AnprCreate,
    AnprResultResponse,
    VehicleCreate,
    VehicleEventResponse,
    VehicleResponse,
    VehicleUpdate,
)
from app.services.physical_service import VehicleService

router = APIRouter(prefix="/vehicles", tags=["vehicle-management"])

Dep = Annotated[VehicleService, Depends(get_vehicle_service)]


@router.get("", response_model=list[VehicleResponse])
async def list_vehicles(
    svc: Dep,
    _: Annotated[object, Depends(require_permission("vehicle:read"))],
    organization_id: uuid.UUID | None = None,
) -> list[VehicleResponse]:
    rows = await svc.list(organization_id=organization_id)
    return [VehicleResponse.model_validate(v) for v in rows]


@router.post("", response_model=VehicleResponse, status_code=status.HTTP_201_CREATED)
async def create_vehicle(
    body: VehicleCreate,
    svc: Dep,
    principal: Annotated[object, Depends(require_permission("vehicle:manage"))],
) -> VehicleResponse:
    vehicle = await svc.create(body.model_dump(), actor_id=principal.user_id)  # type: ignore[attr-defined]
    return VehicleResponse.model_validate(vehicle)


@router.patch("/{vehicle_id}", response_model=VehicleResponse)
async def update_vehicle(
    vehicle_id: uuid.UUID,
    body: VehicleUpdate,
    svc: Dep,
    principal: Annotated[object, Depends(require_permission("vehicle:manage"))],
) -> VehicleResponse:
    vehicle = await svc.update(vehicle_id, body.model_dump(exclude_unset=True), actor_id=principal.user_id)  # type: ignore[attr-defined]
    return VehicleResponse.model_validate(vehicle)


@router.get("/events", response_model=list[VehicleEventResponse])
async def list_anpr_events(
    svc: Dep,
    _: Annotated[object, Depends(require_permission("vehicle:read"))],
    organization_id: uuid.UUID | None = None,
) -> list[VehicleEventResponse]:
    rows = await svc.recent_events(organization_id=organization_id)
    return [VehicleEventResponse.model_validate(e) for e in rows]


@router.post("/anpr", response_model=AnprResultResponse, status_code=status.HTTP_201_CREATED)
async def record_anpr(
    body: AnprCreate,
    svc: Dep,
    _: Annotated[object, Depends(require_permission("vehicle:manage"))],
) -> AnprResultResponse:
    result = await svc.record_anpr(
        organization_id=body.organization_id, plate=body.plate, direction=body.direction,
        site_id=body.site_id, camera_id=body.camera_id, confidence=body.confidence,
    )
    return AnprResultResponse(
        event=VehicleEventResponse.model_validate(result.event),
        matched_vehicle_id=result.vehicle.id if result.vehicle else None,
        flagged=result.flagged,
    )
