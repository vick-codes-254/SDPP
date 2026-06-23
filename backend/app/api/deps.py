"""FastAPI dependencies: DB session, authenticated principal, RBAC, services.

Authorization is stateless: an access token carries the user's effective
permission codes (``perms``) and superuser flag (``su``), so per-request authz is
a set membership check with no database round-trip.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable, Coroutine
from dataclasses import dataclass, field
from typing import Annotated, Any

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.authz.access import has_permission
from app.core.security.exceptions import TokenError
from app.core.security.tokens import TokenType, get_token_manager
from app.db.session import get_db
from app.services.audit_service import AuditService
from app.services.auth_service import AuthService
from app.services.compliance_service import ComplianceService
from app.services.key_service import KeyService
from app.services.monitoring_service import MonitoringService
from app.services.vault_service import VaultService

_bearer = HTTPBearer(auto_error=False, description="JWT access token")

DbDep = Annotated[AsyncSession, Depends(get_db)]


@dataclass(frozen=True, slots=True)
class Principal:
    user_id: uuid.UUID
    username: str
    permissions: frozenset[str] = field(default_factory=frozenset)
    is_superuser: bool = False


def client_ip(request: Request) -> str | None:
    # Honour X-Forwarded-For from the trusted reverse proxy, else peer address.
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else None


async def get_current_principal(
    creds: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> Principal:
    if creds is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        decoded = get_token_manager().decode(creds.credentials, TokenType.access)
    except TokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    claims = decoded.claims
    return Principal(
        user_id=uuid.UUID(decoded.subject),
        username=claims.get("username", ""),
        permissions=frozenset(claims.get("perms", [])),
        is_superuser=bool(claims.get("su", False)),
    )


CurrentPrincipal = Annotated[Principal, Depends(get_current_principal)]


def require_permission(
    code: str,
) -> Callable[[Principal], Coroutine[Any, Any, Principal]]:
    """Dependency factory enforcing a single permission code."""

    async def _dep(principal: CurrentPrincipal) -> Principal:
        if not has_permission(principal.permissions, code, is_superuser=principal.is_superuser):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing required permission: {code}",
            )
        return principal

    return _dep


# ── Service providers ───────────────────────────────────────────
async def get_auth_service(db: DbDep) -> AuthService:
    return AuthService(db)


async def get_vault_service(db: DbDep) -> VaultService:
    return VaultService(db)


async def get_key_service(db: DbDep) -> KeyService:
    return KeyService(db)


async def get_audit_service(db: DbDep) -> AuditService:
    return AuditService(db)


async def get_monitoring_service(db: DbDep) -> MonitoringService:
    return MonitoringService(db)


async def get_compliance_service(db: DbDep) -> ComplianceService:
    return ComplianceService(db)
