"""Compliance reporting endpoints."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, status

from app.api.deps import get_compliance_service, require_permission
from app.schemas.security import ComplianceReportResponse, GenerateReportRequest
from app.services.compliance_service import ComplianceService
from app.services.exceptions import NotFoundError

router = APIRouter(prefix="/compliance", tags=["compliance"])

ComplianceDep = Annotated[ComplianceService, Depends(get_compliance_service)]


@router.post("/reports", response_model=ComplianceReportResponse, status_code=status.HTTP_201_CREATED)
async def generate_report(
    body: GenerateReportRequest,
    svc: ComplianceDep,
    principal: Annotated[object, Depends(require_permission("report:generate"))],
) -> ComplianceReportResponse:
    report = await svc.generate(body.framework, actor_id=principal.user_id)  # type: ignore[attr-defined]
    return ComplianceReportResponse.model_validate(report)


@router.get("/reports", response_model=list[ComplianceReportResponse])
async def list_reports(
    svc: ComplianceDep,
    principal: Annotated[object, Depends(require_permission("report:read"))],
) -> list[ComplianceReportResponse]:
    return [ComplianceReportResponse.model_validate(r) for r in await svc.list_reports()]


@router.get("/reports/{report_id}", response_model=ComplianceReportResponse)
async def get_report(
    report_id: uuid.UUID,
    svc: ComplianceDep,
    principal: Annotated[object, Depends(require_permission("report:read"))],
) -> ComplianceReportResponse:
    report = await svc.get_report(report_id)
    if report is None:
        raise NotFoundError("Report not found")
    return ComplianceReportResponse.model_validate(report)
