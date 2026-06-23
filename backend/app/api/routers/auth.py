"""Authentication endpoints."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Request, status

from app.api.deps import (
    CurrentPrincipal,
    client_ip,
    get_auth_service,
    require_permission,
)
from app.schemas.auth import (
    ChangePasswordRequest,
    LoginRequest,
    RefreshRequest,
    RegisterRequest,
    TokenResponse,
    UserWithPermissions,
)
from app.schemas.common import Message
from app.services.auth_service import AuthService, user_permissions

router = APIRouter(prefix="/auth", tags=["authentication"])

AuthDep = Annotated[AuthService, Depends(get_auth_service)]


@router.post("/register", response_model=UserWithPermissions, status_code=status.HTTP_201_CREATED)
async def register(
    body: RegisterRequest,
    request: Request,
    auth: AuthDep,
    principal: Annotated[object, Depends(require_permission("user:manage"))],
) -> UserWithPermissions:
    """Create a user (admin-only — requires ``user:manage``)."""
    user = await auth.register(
        username=body.username, email=body.email, password=body.password,
        full_name=body.full_name, phone=body.phone, ip_address=client_ip(request),
    )
    return UserWithPermissions.model_validate(
        {**user.__dict__, "email": user.email, "permissions": sorted(user_permissions(user))}
    )


@router.post("/login", response_model=TokenResponse)
async def login(body: LoginRequest, request: Request, auth: AuthDep) -> TokenResponse:
    _, tokens = await auth.login(
        identifier=body.identifier, password=body.password,
        ip_address=client_ip(request), user_agent=request.headers.get("user-agent"),
    )
    return TokenResponse(access_token=tokens.access_token, refresh_token=tokens.refresh_token)


@router.post("/refresh", response_model=TokenResponse)
async def refresh(body: RefreshRequest, request: Request, auth: AuthDep) -> TokenResponse:
    tokens = await auth.refresh(
        body.refresh_token, ip_address=client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    return TokenResponse(access_token=tokens.access_token, refresh_token=tokens.refresh_token)


@router.post("/logout", response_model=Message)
async def logout(body: RefreshRequest, auth: AuthDep, principal: CurrentPrincipal) -> Message:
    await auth.logout(body.refresh_token, actor_id=principal.user_id)
    return Message(detail="Logged out")


@router.get("/me", response_model=UserWithPermissions)
async def me(auth: AuthDep, principal: CurrentPrincipal) -> UserWithPermissions:
    user = await auth.get_user(principal.user_id)
    if user is None:  # token valid but user removed
        from app.services.exceptions import NotFoundError

        raise NotFoundError("User not found")
    return UserWithPermissions.model_validate(
        {**user.__dict__, "email": user.email, "permissions": sorted(principal.permissions)}
    )


@router.post("/change-password", response_model=Message)
async def change_password(
    body: ChangePasswordRequest,
    request: Request,
    auth: AuthDep,
    principal: CurrentPrincipal,
) -> Message:
    user = await auth.get_user(principal.user_id)
    if user is None:
        from app.services.exceptions import NotFoundError

        raise NotFoundError("User not found")
    await auth.change_password(
        user, old_password=body.old_password, new_password=body.new_password,
        ip_address=client_ip(request),
    )
    return Message(detail="Password changed; please log in again")
