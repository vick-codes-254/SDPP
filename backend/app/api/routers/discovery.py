"""Network discovery endpoints."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, status

from app.api.deps import get_discovery_service, require_permission
from app.schemas.smp import (
    DiscoveredHostResponse,
    DiscoveryScanCreate,
    DiscoveryScanResponse,
)
from app.services.discovery_service import DiscoveryService

router = APIRouter(prefix="/discovery", tags=["network-discovery"])

DiscoveryDep = Annotated[DiscoveryService, Depends(get_discovery_service)]


@router.get("/scans", response_model=list[DiscoveryScanResponse])
async def list_scans(
    svc: DiscoveryDep,
    principal: Annotated[object, Depends(require_permission("discovery:read"))],
) -> list[DiscoveryScanResponse]:
    return [DiscoveryScanResponse.model_validate(s) for s in await svc.list_scans()]


@router.post("/scans", response_model=DiscoveryScanResponse, status_code=status.HTTP_201_CREATED)
async def create_scan(
    body: DiscoveryScanCreate,
    svc: DiscoveryDep,
    principal: Annotated[object, Depends(require_permission("discovery:run"))],
) -> DiscoveryScanResponse:
    scan = await svc.create_scan(
        name=body.name, targets=body.targets, ports=body.ports,
        actor_id=principal.user_id,  # type: ignore[attr-defined]
    )
    return DiscoveryScanResponse.model_validate(scan)


@router.post("/scans/{scan_id}/run", response_model=DiscoveryScanResponse)
async def run_scan(
    scan_id: uuid.UUID,
    svc: DiscoveryDep,
    principal: Annotated[object, Depends(require_permission("discovery:run"))],
) -> DiscoveryScanResponse:
    return DiscoveryScanResponse.model_validate(await svc.run_scan(scan_id))


@router.get("/scans/{scan_id}/hosts", response_model=list[DiscoveredHostResponse])
async def scan_hosts(
    scan_id: uuid.UUID,
    svc: DiscoveryDep,
    principal: Annotated[object, Depends(require_permission("discovery:read"))],
) -> list[DiscoveredHostResponse]:
    return [DiscoveredHostResponse.model_validate(h) for h in await svc.list_hosts(scan_id)]
