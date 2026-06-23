"""Key management endpoints."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Body, Depends

from app.api.deps import get_key_service, require_permission
from app.schemas.common import Message
from app.schemas.security import KeyResponse
from app.services.exceptions import NotFoundError
from app.services.key_service import KeyService

router = APIRouter(prefix="/keys", tags=["key-management"])

KeyDep = Annotated[KeyService, Depends(get_key_service)]


@router.get("", response_model=list[KeyResponse])
async def list_keys(
    keys: KeyDep,
    principal: Annotated[object, Depends(require_permission("key:read"))],
) -> list[KeyResponse]:
    return [KeyResponse.model_validate(k) for k in await keys.list_keys()]


@router.post("/{key_id}/rotate", response_model=KeyResponse)
async def rotate_key(
    key_id: uuid.UUID,
    keys: KeyDep,
    principal: Annotated[object, Depends(require_permission("key:rotate"))],
) -> KeyResponse:
    record = await keys.get_key(key_id)
    if record is None:
        raise NotFoundError("Key not found")
    rotated = await keys.rotate_master_key(record, actor_id=principal.user_id)  # type: ignore[attr-defined]
    return KeyResponse.model_validate(rotated)


@router.post("/{key_id}/revoke", response_model=Message)
async def revoke_key(
    key_id: uuid.UUID,
    keys: KeyDep,
    principal: Annotated[object, Depends(require_permission("key:revoke"))],
    reason: Annotated[str, Body(embed=True)] = "manual revocation",
) -> Message:
    record = await keys.get_key(key_id)
    if record is None:
        raise NotFoundError("Key not found")
    await keys.revoke(record, reason=reason, actor_id=principal.user_id)  # type: ignore[attr-defined]
    return Message(detail="Key revoked")
