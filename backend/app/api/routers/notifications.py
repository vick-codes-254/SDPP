"""Alert management: notification channels, templates, dispatch & delivery log."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, status

from app.api.deps import get_notification_service, require_permission
from app.schemas.secops import (
    ChannelCreate,
    ChannelResponse,
    DispatchRequest,
    NotificationResponse,
    TemplateCreate,
    TemplateResponse,
)
from app.services.notification_service import NotificationService

router = APIRouter(prefix="/notifications", tags=["alert-management"])

Dep = Annotated[NotificationService, Depends(get_notification_service)]


@router.get("/channels", response_model=list[ChannelResponse])
async def list_channels(
    svc: Dep,
    _: Annotated[object, Depends(require_permission("notify:read"))],
    organization_id: uuid.UUID | None = None,
) -> list[ChannelResponse]:
    return [ChannelResponse.model_validate(c) for c in await svc.list_channels(organization_id=organization_id)]


@router.post("/channels", response_model=ChannelResponse, status_code=status.HTTP_201_CREATED)
async def create_channel(
    body: ChannelCreate,
    svc: Dep,
    principal: Annotated[object, Depends(require_permission("notify:manage"))],
) -> ChannelResponse:
    ch = await svc.create(body.model_dump(), actor_id=principal.user_id)  # type: ignore[attr-defined]
    return ChannelResponse.model_validate(ch)


@router.get("/templates", response_model=list[TemplateResponse])
async def list_templates(
    svc: Dep,
    _: Annotated[object, Depends(require_permission("notify:read"))],
    organization_id: uuid.UUID | None = None,
) -> list[TemplateResponse]:
    return [TemplateResponse.model_validate(t) for t in await svc.list_templates(organization_id=organization_id)]


@router.post("/templates", response_model=TemplateResponse, status_code=status.HTTP_201_CREATED)
async def create_template(
    body: TemplateCreate,
    svc: Dep,
    principal: Annotated[object, Depends(require_permission("notify:manage"))],
) -> TemplateResponse:
    tpl = await svc.create_template(body.model_dump(), actor_id=principal.user_id)  # type: ignore[attr-defined]
    return TemplateResponse.model_validate(tpl)


@router.post("/dispatch", response_model=NotificationResponse, status_code=status.HTTP_201_CREATED)
async def dispatch(
    body: DispatchRequest,
    svc: Dep,
    _: Annotated[object, Depends(require_permission("notify:manage"))],
) -> NotificationResponse:
    note = await svc.dispatch(
        organization_id=body.organization_id, channel=body.channel,
        target=body.target, subject=body.subject, body=body.body,
    )
    return NotificationResponse.model_validate(note)


@router.get("/history", response_model=list[NotificationResponse])
async def history(
    svc: Dep,
    _: Annotated[object, Depends(require_permission("notify:read"))],
    organization_id: uuid.UUID | None = None,
) -> list[NotificationResponse]:
    return [NotificationResponse.model_validate(n) for n in await svc.history(organization_id=organization_id)]


@router.get("/stats", response_model=dict)
async def stats(
    svc: Dep,
    _: Annotated[object, Depends(require_permission("notify:read"))],
    organization_id: uuid.UUID | None = None,
) -> dict:
    return await svc.delivery_stats(organization_id=organization_id)
