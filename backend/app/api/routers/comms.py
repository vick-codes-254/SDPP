"""Communication center endpoints: announcements and chat rooms."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, status

from app.api.deps import get_comms_service, require_permission
from app.schemas.collab import (
    AnnouncementCreate,
    AnnouncementResponse,
    MessagePost,
    MessageResponse,
)
from app.services.comms_service import CommsService

router = APIRouter(prefix="/comms", tags=["communication"])

Dep = Annotated[CommsService, Depends(get_comms_service)]


@router.get("/announcements", response_model=list[AnnouncementResponse])
async def list_announcements(
    svc: Dep,
    _: Annotated[object, Depends(require_permission("comms:read"))],
    organization_id: uuid.UUID | None = None,
) -> list[AnnouncementResponse]:
    rows = await svc.list_announcements(organization_id=organization_id)
    return [AnnouncementResponse.model_validate(a) for a in rows]


@router.post("/announcements", response_model=AnnouncementResponse, status_code=status.HTTP_201_CREATED)
async def create_announcement(
    body: AnnouncementCreate,
    svc: Dep,
    principal: Annotated[object, Depends(require_permission("comms:manage"))],
) -> AnnouncementResponse:
    data = body.model_dump()
    data["created_by"] = principal.user_id  # type: ignore[attr-defined]
    return AnnouncementResponse.model_validate(await svc.create_announcement(data))


@router.get("/rooms/{room}/messages", response_model=list[MessageResponse])
async def list_messages(
    room: str,
    svc: Dep,
    _: Annotated[object, Depends(require_permission("comms:read"))],
    organization_id: uuid.UUID | None = None,
) -> list[MessageResponse]:
    rows = await svc.list_messages(room=room, organization_id=organization_id)
    return [MessageResponse.model_validate(m) for m in rows]


@router.post("/messages", response_model=MessageResponse, status_code=status.HTTP_201_CREATED)
async def post_message(
    body: MessagePost,
    svc: Dep,
    principal: Annotated[object, Depends(require_permission("comms:read"))],
) -> MessageResponse:
    msg = await svc.post_message(
        organization_id=body.organization_id, room=body.room, body=body.body,
        author_id=principal.user_id, author_label=principal.username,  # type: ignore[attr-defined]
    )
    return MessageResponse.model_validate(msg)
