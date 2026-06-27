"""Incident management endpoints."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query, status

from app.api.deps import get_incident_service, require_permission
from app.core.enums import IncidentSeverity, IncidentStatus
from app.schemas.smp import (
    AssignRequest,
    CommentCreate,
    IncidentCreate,
    IncidentNoteResponse,
    IncidentResponse,
    IncidentStatusUpdate,
)
from app.services.incident_service import IncidentService

router = APIRouter(prefix="/incidents", tags=["incident-management"])

IncidentDep = Annotated[IncidentService, Depends(get_incident_service)]


@router.get("", response_model=list[IncidentResponse])
async def list_incidents(
    svc: IncidentDep,
    principal: Annotated[object, Depends(require_permission("incident:read"))],
    status_filter: Annotated[IncidentStatus | None, Query(alias="status")] = None,
    severity: IncidentSeverity | None = None,
) -> list[IncidentResponse]:
    rows = await svc.list(status=status_filter, severity=severity)
    return [IncidentResponse.model_validate(i) for i in rows]


@router.post("", response_model=IncidentResponse, status_code=status.HTTP_201_CREATED)
async def create_incident(
    body: IncidentCreate,
    svc: IncidentDep,
    principal: Annotated[object, Depends(require_permission("incident:manage"))],
) -> IncidentResponse:
    inc = await svc.create(
        title=body.title, description=body.description, severity=body.severity,
        reporter_id=principal.user_id,  # type: ignore[attr-defined]
        alert_ids=body.alert_ids, asset_ids=body.asset_ids,
    )
    return IncidentResponse.model_validate(inc)


@router.get("/{incident_id}", response_model=IncidentResponse)
async def get_incident(
    incident_id: uuid.UUID,
    svc: IncidentDep,
    principal: Annotated[object, Depends(require_permission("incident:read"))],
) -> IncidentResponse:
    return IncidentResponse.model_validate(await svc.get_or_404(incident_id))


@router.get("/{incident_id}/timeline", response_model=list[IncidentNoteResponse])
async def incident_timeline(
    incident_id: uuid.UUID,
    svc: IncidentDep,
    principal: Annotated[object, Depends(require_permission("incident:read"))],
) -> list[IncidentNoteResponse]:
    return [IncidentNoteResponse.model_validate(n) for n in await svc.timeline(incident_id)]


@router.post("/{incident_id}/comments", response_model=IncidentNoteResponse)
async def add_comment(
    incident_id: uuid.UUID,
    body: CommentCreate,
    svc: IncidentDep,
    principal: Annotated[object, Depends(require_permission("incident:manage"))],
) -> IncidentNoteResponse:
    note = await svc.add_comment(incident_id, body.body, author_id=principal.user_id)  # type: ignore[attr-defined]
    return IncidentNoteResponse.model_validate(note)


@router.post("/{incident_id}/assign", response_model=IncidentResponse)
async def assign_incident(
    incident_id: uuid.UUID,
    body: AssignRequest,
    svc: IncidentDep,
    principal: Annotated[object, Depends(require_permission("incident:manage"))],
) -> IncidentResponse:
    inc = await svc.assign(incident_id, body.assignee_id, actor_id=principal.user_id)  # type: ignore[attr-defined]
    return IncidentResponse.model_validate(inc)


@router.post("/{incident_id}/acknowledge", response_model=IncidentResponse)
async def acknowledge_incident(
    incident_id: uuid.UUID,
    svc: IncidentDep,
    principal: Annotated[object, Depends(require_permission("incident:manage"))],
) -> IncidentResponse:
    inc = await svc.acknowledge(incident_id, actor_id=principal.user_id)  # type: ignore[attr-defined]
    return IncidentResponse.model_validate(inc)


@router.post("/{incident_id}/status", response_model=IncidentResponse)
async def change_status(
    incident_id: uuid.UUID,
    body: IncidentStatusUpdate,
    svc: IncidentDep,
    principal: Annotated[object, Depends(require_permission("incident:manage"))],
) -> IncidentResponse:
    inc = await svc.transition(
        incident_id, body.status, actor_id=principal.user_id, resolution=body.resolution  # type: ignore[attr-defined]
    )
    return IncidentResponse.model_validate(inc)


@router.post("/{incident_id}/evidence/{file_id}", response_model=IncidentResponse)
async def attach_evidence(
    incident_id: uuid.UUID,
    file_id: uuid.UUID,
    svc: IncidentDep,
    principal: Annotated[object, Depends(require_permission("incident:manage"))],
) -> IncidentResponse:
    inc = await svc.attach_evidence(incident_id, file_id, actor_id=principal.user_id)  # type: ignore[attr-defined]
    return IncidentResponse.model_validate(inc)
