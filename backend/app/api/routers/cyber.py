"""Cybersecurity monitoring & SOC endpoints."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, status

from app.api.deps import get_cyber_service, require_permission
from app.core.enums import CyberEventType
from app.schemas.cyber import (
    CyberEventResponse,
    CyberStatusUpdate,
    DeviceResponse,
    IngestResult,
    LoginAttemptResponse,
    LoginEventIngest,
)
from app.services.cyber_service import CyberMonitoringService

router = APIRouter(prefix="/cyber", tags=["cybersecurity-monitoring"])

Dep = Annotated[CyberMonitoringService, Depends(get_cyber_service)]


@router.post("/login-events", response_model=IngestResult, status_code=status.HTTP_201_CREATED)
async def ingest_login_event(
    body: LoginEventIngest,
    svc: Dep,
    _: Annotated[object, Depends(require_permission("cyber:manage"))],
) -> IngestResult:
    events = await svc.record_login(
        username=body.username, success=body.success, user_id=body.user_id,
        organization_id=body.organization_id, ip_address=body.ip_address,
        country=body.country, city=body.city, latitude=body.latitude,
        longitude=body.longitude, device_fingerprint=body.device_fingerprint,
        user_agent=body.user_agent,
    )
    return IngestResult(events_triggered=[CyberEventResponse.model_validate(e) for e in events])


@router.get("/events", response_model=list[CyberEventResponse])
async def list_events(
    svc: Dep,
    _: Annotated[object, Depends(require_permission("cyber:read"))],
    organization_id: uuid.UUID | None = None,
    event_type: CyberEventType | None = None,
) -> list[CyberEventResponse]:
    rows = await svc.list_events(organization_id=organization_id, event_type=event_type)
    return [CyberEventResponse.model_validate(e) for e in rows]


@router.get("/soc", response_model=dict)
async def soc_summary(
    svc: Dep,
    _: Annotated[object, Depends(require_permission("cyber:read"))],
    organization_id: uuid.UUID | None = None,
) -> dict:
    return await svc.soc_summary(organization_id=organization_id)


@router.post("/events/{event_id}/status", response_model=CyberEventResponse)
async def set_event_status(
    event_id: uuid.UUID,
    body: CyberStatusUpdate,
    svc: Dep,
    _: Annotated[object, Depends(require_permission("cyber:manage"))],
) -> CyberEventResponse:
    return CyberEventResponse.model_validate(await svc.set_status(event_id, body.status))


@router.get("/login-attempts", response_model=list[LoginAttemptResponse])
async def list_attempts(
    svc: Dep,
    _: Annotated[object, Depends(require_permission("cyber:read"))],
    username: str | None = None,
) -> list[LoginAttemptResponse]:
    rows = await svc.list_attempts(username=username)
    return [LoginAttemptResponse.model_validate(a) for a in rows]


@router.get("/devices", response_model=list[DeviceResponse])
async def list_devices(
    user_id: uuid.UUID,
    svc: Dep,
    _: Annotated[object, Depends(require_permission("cyber:read"))],
) -> list[DeviceResponse]:
    return [DeviceResponse.model_validate(d) for d in await svc.list_devices(user_id)]
