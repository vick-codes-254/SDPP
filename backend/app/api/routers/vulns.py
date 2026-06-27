"""Vulnerability scanning endpoints."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query, status

from app.api.deps import get_alert_engine, get_vuln_service, require_permission
from app.core.enums import VulnStatus
from app.schemas.smp import (
    FindingResponse,
    FindingStatusUpdate,
    VulnScanCreate,
    VulnScanResponse,
)
from app.services.alert_engine import AlertEngine
from app.services.vuln_service import VulnService

router = APIRouter(prefix="/vulnerabilities", tags=["vulnerability-scanner"])

VulnDep = Annotated[VulnService, Depends(get_vuln_service)]


@router.get("/scans", response_model=list[VulnScanResponse])
async def list_scans(
    svc: VulnDep,
    principal: Annotated[object, Depends(require_permission("vuln:read"))],
) -> list[VulnScanResponse]:
    return [VulnScanResponse.model_validate(s) for s in await svc.list_scans()]


@router.post("/scans", response_model=VulnScanResponse, status_code=status.HTTP_201_CREATED)
async def create_scan(
    body: VulnScanCreate,
    svc: VulnDep,
    principal: Annotated[object, Depends(require_permission("vuln:scan"))],
) -> VulnScanResponse:
    scan = await svc.create_scan(
        name=body.name, asset_ids=body.asset_ids, actor_id=principal.user_id  # type: ignore[attr-defined]
    )
    return VulnScanResponse.model_validate(scan)


@router.post("/scans/{scan_id}/run", response_model=VulnScanResponse)
async def run_scan(
    scan_id: uuid.UUID,
    svc: VulnDep,
    engine: Annotated[AlertEngine, Depends(get_alert_engine)],
    principal: Annotated[object, Depends(require_permission("vuln:scan"))],
) -> VulnScanResponse:
    scan = await svc.run_scan(scan_id)
    # Feed findings into the alert engine automatically.
    await engine.run_for_vuln_scan(scan_id)
    return VulnScanResponse.model_validate(scan)


@router.get("/findings", response_model=list[FindingResponse])
async def list_findings(
    svc: VulnDep,
    principal: Annotated[object, Depends(require_permission("vuln:read"))],
    scan_id: uuid.UUID | None = None,
    asset_id: uuid.UUID | None = None,
    status_filter: Annotated[VulnStatus | None, Query(alias="status")] = None,
) -> list[FindingResponse]:
    rows = await svc.list_findings(scan_id=scan_id, asset_id=asset_id, status=status_filter)
    return [FindingResponse.model_validate(f) for f in rows]


@router.patch("/findings/{finding_id}", response_model=FindingResponse)
async def update_finding(
    finding_id: uuid.UUID,
    body: FindingStatusUpdate,
    svc: VulnDep,
    principal: Annotated[object, Depends(require_permission("vuln:manage"))],
) -> FindingResponse:
    finding = await svc.set_finding_status(
        finding_id, body.status, actor_id=principal.user_id  # type: ignore[attr-defined]
    )
    return FindingResponse.model_validate(finding)
