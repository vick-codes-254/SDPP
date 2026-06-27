"""Visitor & contractor management endpoints."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status

from app.api.deps import get_contractor_service, get_visitor_service, require_permission
from app.schemas.common import Message
from app.schemas.physical import (
    ContractorCreate,
    ContractorResponse,
    ContractorUpdate,
    VisitorCreate,
    VisitorResponse,
    VisitorStatusUpdate,
)
from app.services.physical_service import ContractorService, VisitorService

router = APIRouter(prefix="/visitors", tags=["visitor-management"])

VisitorDep = Annotated[VisitorService, Depends(get_visitor_service)]
ContractorDep = Annotated[ContractorService, Depends(get_contractor_service)]


# ── Visitors ────────────────────────────────────────────────────
@router.get("", response_model=list[VisitorResponse])
async def list_visitors(
    svc: VisitorDep,
    _: Annotated[object, Depends(require_permission("visitor:read"))],
    organization_id: uuid.UUID | None = None,
    site_id: uuid.UUID | None = None,
) -> list[VisitorResponse]:
    rows = await svc.list(organization_id=organization_id, filters={"site_id": site_id})
    return [VisitorResponse.model_validate(v) for v in rows]


@router.post("", response_model=VisitorResponse, status_code=status.HTTP_201_CREATED)
async def register_visitor(
    body: VisitorCreate,
    svc: VisitorDep,
    principal: Annotated[object, Depends(require_permission("visitor:manage"))],
) -> VisitorResponse:
    if await svc.is_blacklisted(body.full_name):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Visitor matches a blacklisted identity",
        )
    visitor = await svc.create(body.model_dump(), actor_id=principal.user_id)  # type: ignore[attr-defined]
    return VisitorResponse.model_validate(visitor)


@router.post("/{visitor_id}/status", response_model=VisitorResponse)
async def set_visitor_status(
    visitor_id: uuid.UUID,
    body: VisitorStatusUpdate,
    svc: VisitorDep,
    principal: Annotated[object, Depends(require_permission("visitor:manage"))],
) -> VisitorResponse:
    visitor = await svc.set_status(visitor_id, body.status, actor_id=principal.user_id)  # type: ignore[attr-defined]
    return VisitorResponse.model_validate(visitor)


# ── Contractors ─────────────────────────────────────────────────
@router.get("/contractors/list", response_model=list[ContractorResponse])
async def list_contractors(
    svc: ContractorDep,
    _: Annotated[object, Depends(require_permission("visitor:read"))],
    organization_id: uuid.UUID | None = None,
) -> list[ContractorResponse]:
    rows = await svc.list(organization_id=organization_id)
    return [ContractorResponse.model_validate(c) for c in rows]


@router.post("/contractors", response_model=ContractorResponse, status_code=status.HTTP_201_CREATED)
async def create_contractor(
    body: ContractorCreate,
    svc: ContractorDep,
    principal: Annotated[object, Depends(require_permission("visitor:manage"))],
) -> ContractorResponse:
    contractor = await svc.create(body.model_dump(), actor_id=principal.user_id)  # type: ignore[attr-defined]
    return ContractorResponse.model_validate(contractor)


@router.patch("/contractors/{contractor_id}", response_model=ContractorResponse)
async def update_contractor(
    contractor_id: uuid.UUID,
    body: ContractorUpdate,
    svc: ContractorDep,
    principal: Annotated[object, Depends(require_permission("visitor:manage"))],
) -> ContractorResponse:
    contractor = await svc.update(
        contractor_id, body.model_dump(exclude_unset=True), actor_id=principal.user_id  # type: ignore[attr-defined]
    )
    return ContractorResponse.model_validate(contractor)
