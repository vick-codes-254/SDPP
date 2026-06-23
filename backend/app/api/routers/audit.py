"""Audit trail endpoints."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query

from app.api.deps import get_audit_service, require_permission
from app.schemas.security import AuditLogResponse, ChainVerificationResponse
from app.services.audit_service import AuditService

router = APIRouter(prefix="/audit-logs", tags=["audit"])

AuditDep = Annotated[AuditService, Depends(get_audit_service)]


@router.get("", response_model=list[AuditLogResponse])
async def list_audit_logs(
    audit: AuditDep,
    principal: Annotated[object, Depends(require_permission("audit:read"))],
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[AuditLogResponse]:
    entries = await audit.list_entries(limit=limit, offset=offset)
    return [AuditLogResponse.model_validate(e) for e in entries]


@router.get("/verify", response_model=ChainVerificationResponse)
async def verify_chain(
    audit: AuditDep,
    principal: Annotated[object, Depends(require_permission("audit:verify"))],
) -> ChainVerificationResponse:
    result = await audit.verify_chain()
    return ChainVerificationResponse(
        ok=result.ok, entries_checked=result.entries_checked,
        first_broken_seq=result.first_broken_seq, detail=result.detail,
    )
