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
from app.services.alert_engine import AlertEngine
from app.services.asset_service import AssetService
from app.services.audit_service import AuditService
from app.services.auth_service import AuthService
from app.services.compliance_service import ComplianceService
from app.services.discovery_service import DiscoveryService
from app.services.incident_service import IncidentService
from app.services.key_service import KeyService
from app.services.admin_service import AdminService
from app.services.analytics_service import AnalyticsService
from app.services.billing_service import BillingService
from app.services.comms_service import CommsService
from app.services.cyber_service import CyberMonitoringService
from app.services.detection_service import DetectionService, ThreatService
from app.services.emergency_service import EmergencyService
from app.services.evidence_service import EvidenceService
from app.services.monitoring_service import MonitoringService
from app.services.notification_service import NotificationService
from app.services.org_service import OrgService
from app.services.workflow_service import WorkflowService
from app.services.physical_service import (
    AccessService,
    CameraService,
    ContractorService,
    GuardService,
    PatrolService,
    VehicleService,
    VisitorService,
)
from app.services.user_service import UserService
from app.services.vault_service import VaultService
from app.services.vuln_service import VulnService

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


async def get_asset_service(db: DbDep) -> AssetService:
    return AssetService(db)


async def get_discovery_service(db: DbDep) -> DiscoveryService:
    return DiscoveryService(db)


async def get_vuln_service(db: DbDep) -> VulnService:
    return VulnService(db)


async def get_alert_engine(db: DbDep) -> AlertEngine:
    return AlertEngine(db)


async def get_incident_service(db: DbDep) -> IncidentService:
    return IncidentService(db)


async def get_user_service(db: DbDep) -> UserService:
    return UserService(db)


async def get_org_service(db: DbDep) -> OrgService:
    return OrgService(db)


async def get_camera_service(db: DbDep) -> CameraService:
    return CameraService(db)


async def get_guard_service(db: DbDep) -> GuardService:
    return GuardService(db)


async def get_patrol_service(db: DbDep) -> PatrolService:
    return PatrolService(db)


async def get_visitor_service(db: DbDep) -> VisitorService:
    return VisitorService(db)


async def get_contractor_service(db: DbDep) -> ContractorService:
    return ContractorService(db)


async def get_access_service(db: DbDep) -> AccessService:
    return AccessService(db)


async def get_vehicle_service(db: DbDep) -> VehicleService:
    return VehicleService(db)


async def get_detection_service(db: DbDep) -> DetectionService:
    return DetectionService(db)


async def get_threat_service(db: DbDep) -> ThreatService:
    return ThreatService(db)


async def get_notification_service(db: DbDep) -> NotificationService:
    return NotificationService(db)


async def get_emergency_service(db: DbDep) -> EmergencyService:
    return EmergencyService(db)


async def get_evidence_service(db: DbDep) -> EvidenceService:
    return EvidenceService(db)


async def get_cyber_service(db: DbDep) -> CyberMonitoringService:
    return CyberMonitoringService(db)


async def get_analytics_service(db: DbDep) -> AnalyticsService:
    return AnalyticsService(db)


async def get_comms_service(db: DbDep) -> CommsService:
    return CommsService(db)


async def get_workflow_service(db: DbDep) -> WorkflowService:
    return WorkflowService(db)


async def get_billing_service(db: DbDep) -> BillingService:
    return BillingService(db)


async def get_admin_service(db: DbDep) -> AdminService:
    return AdminService(db)
