"""Emergency response endpoints: trigger, acknowledge, resolve, contacts."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, status

from app.api.deps import get_emergency_service, require_permission
from app.schemas.secops import (
    ContactCreate,
    ContactResponse,
    EmergencyResponse,
    EmergencyTrigger,
)
from app.services.emergency_service import EmergencyService

router = APIRouter(prefix="/emergency", tags=["emergency-response"])

Dep = Annotated[EmergencyService, Depends(get_emergency_service)]


@router.post("/trigger", response_model=EmergencyResponse, status_code=status.HTTP_201_CREATED)
async def trigger(
    body: EmergencyTrigger,
    svc: Dep,
    principal: Annotated[object, Depends(require_permission("emergency:respond"))],
) -> EmergencyResponse:
    event = await svc.trigger(
        organization_id=body.organization_id, event_type=body.event_type,
        site_id=body.site_id, zone_id=body.zone_id, message=body.message,
        actor_id=principal.user_id,  # type: ignore[attr-defined]
    )
    return EmergencyResponse.model_validate(event)


@router.get("/events", response_model=list[EmergencyResponse])
async def list_events(
    svc: Dep,
    _: Annotated[object, Depends(require_permission("emergency:read"))],
    organization_id: uuid.UUID | None = None,
) -> list[EmergencyResponse]:
    rows = await svc.list(organization_id=organization_id)
    return [EmergencyResponse.model_validate(e) for e in rows]


@router.post("/events/{event_id}/acknowledge", response_model=EmergencyResponse)
async def acknowledge(
    event_id: uuid.UUID,
    svc: Dep,
    principal: Annotated[object, Depends(require_permission("emergency:respond"))],
) -> EmergencyResponse:
    return EmergencyResponse.model_validate(
        await svc.acknowledge(event_id, actor_id=principal.user_id)  # type: ignore[attr-defined]
    )


@router.post("/events/{event_id}/resolve", response_model=EmergencyResponse)
async def resolve(
    event_id: uuid.UUID,
    svc: Dep,
    principal: Annotated[object, Depends(require_permission("emergency:respond"))],
) -> EmergencyResponse:
    return EmergencyResponse.model_validate(
        await svc.resolve(event_id, actor_id=principal.user_id)  # type: ignore[attr-defined]
    )


@router.get("/contacts", response_model=list[ContactResponse])
async def list_contacts(
    svc: Dep,
    _: Annotated[object, Depends(require_permission("emergency:read"))],
    organization_id: uuid.UUID | None = None,
) -> list[ContactResponse]:
    rows = await svc.list_contacts(organization_id=organization_id)
    return [ContactResponse.model_validate(c) for c in rows]


@router.post("/contacts", response_model=ContactResponse, status_code=status.HTTP_201_CREATED)
async def add_contact(
    body: ContactCreate,
    svc: Dep,
    principal: Annotated[object, Depends(require_permission("emergency:respond"))],
) -> ContactResponse:
    contact = await svc.add_contact(body.model_dump(), actor_id=principal.user_id)  # type: ignore[attr-defined]
    return ContactResponse.model_validate(contact)
