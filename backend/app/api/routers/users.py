"""User management endpoints (admin)."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends

from app.api.deps import get_user_service, require_permission
from app.models.user import User
from app.schemas.smp import SetActiveRequest, SetRolesRequest, UserAdminResponse
from app.services.user_service import UserService

router = APIRouter(prefix="/users", tags=["user-management"])

UserDep = Annotated[UserService, Depends(get_user_service)]


def _to_admin(user: User) -> UserAdminResponse:
    return UserAdminResponse(
        id=user.id, username=user.username, email=user.email,
        is_active=user.is_active, is_superuser=user.is_superuser,
        roles=[r.name for r in user.roles], created_at=user.created_at,
    )


@router.get("", response_model=list[UserAdminResponse])
async def list_users(
    svc: UserDep,
    principal: Annotated[object, Depends(require_permission("user:read"))],
) -> list[UserAdminResponse]:
    return [_to_admin(u) for u in await svc.list_users()]


@router.get("/{user_id}", response_model=UserAdminResponse)
async def get_user(
    user_id: uuid.UUID,
    svc: UserDep,
    principal: Annotated[object, Depends(require_permission("user:read"))],
) -> UserAdminResponse:
    return _to_admin(await svc.get_user(user_id))


@router.post("/{user_id}/roles", response_model=UserAdminResponse)
async def set_roles(
    user_id: uuid.UUID,
    body: SetRolesRequest,
    svc: UserDep,
    principal: Annotated[object, Depends(require_permission("user:manage"))],
) -> UserAdminResponse:
    user = await svc.set_roles(user_id, body.roles, actor_id=principal.user_id)  # type: ignore[attr-defined]
    return _to_admin(user)


@router.post("/{user_id}/active", response_model=UserAdminResponse)
async def set_active(
    user_id: uuid.UUID,
    body: SetActiveRequest,
    svc: UserDep,
    principal: Annotated[object, Depends(require_permission("user:manage"))],
) -> UserAdminResponse:
    user = await svc.set_active(user_id, body.active, actor_id=principal.user_id)  # type: ignore[attr-defined]
    return _to_admin(user)
