"""Evidence management & chain-of-custody endpoints."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, status

from app.api.deps import get_evidence_service, require_permission
from app.schemas.secops import (
    CustodyLog,
    CustodyResponse,
    EvidenceRegister,
    EvidenceResponse,
)
from app.services.evidence_service import EvidenceService

router = APIRouter(prefix="/evidence", tags=["evidence-management"])

Dep = Annotated[EvidenceService, Depends(get_evidence_service)]


@router.get("", response_model=list[EvidenceResponse])
async def list_evidence(
    svc: Dep,
    _: Annotated[object, Depends(require_permission("evidence:read"))],
    organization_id: uuid.UUID | None = None,
    incident_id: uuid.UUID | None = None,
) -> list[EvidenceResponse]:
    rows = await svc.list(organization_id=organization_id, filters={"incident_id": incident_id})
    return [EvidenceResponse.model_validate(e) for e in rows]


@router.post("", response_model=EvidenceResponse, status_code=status.HTTP_201_CREATED)
async def register_evidence(
    body: EvidenceRegister,
    svc: Dep,
    principal: Annotated[object, Depends(require_permission("evidence:manage"))],
) -> EvidenceResponse:
    ev = await svc.register(
        organization_id=body.organization_id, title=body.title,
        evidence_type=body.evidence_type, incident_id=body.incident_id,
        file_id=body.file_id, sha256=body.sha256, source=body.source,
        description=body.description, tags=body.tags,
        actor_id=principal.user_id,  # type: ignore[attr-defined]
    )
    return EvidenceResponse.model_validate(ev)


@router.get("/{evidence_id}", response_model=EvidenceResponse)
async def get_evidence(
    evidence_id: uuid.UUID,
    svc: Dep,
    _: Annotated[object, Depends(require_permission("evidence:read"))],
) -> EvidenceResponse:
    return EvidenceResponse.model_validate(await svc.get_or_404(evidence_id))


@router.get("/{evidence_id}/custody", response_model=list[CustodyResponse])
async def custody_chain(
    evidence_id: uuid.UUID,
    svc: Dep,
    _: Annotated[object, Depends(require_permission("evidence:read"))],
) -> list[CustodyResponse]:
    return [CustodyResponse.model_validate(c) for c in await svc.chain(evidence_id)]


@router.post("/{evidence_id}/custody", response_model=CustodyResponse, status_code=status.HTTP_201_CREATED)
async def log_custody(
    evidence_id: uuid.UUID,
    body: CustodyLog,
    svc: Dep,
    principal: Annotated[object, Depends(require_permission("evidence:manage"))],
) -> CustodyResponse:
    entry = await svc.log_custody(
        evidence_id, action=body.action, from_party=body.from_party,
        to_party=body.to_party, notes=body.notes, actor_id=principal.user_id,  # type: ignore[attr-defined]
    )
    return CustodyResponse.model_validate(entry)
