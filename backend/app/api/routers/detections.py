"""AI detection & threat-intelligence endpoints."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query, status

from app.api.deps import get_detection_service, get_threat_service, require_permission
from app.core.enums import DetectionStatus, DetectionType, ThreatLevel, ThreatStatus
from app.schemas.detection import (
    DetectionIngest,
    DetectionIngestResult,
    DetectionResponse,
    DetectionStatusUpdate,
    ThreatResponse,
    ThreatStatusUpdate,
)
from app.services.detection_service import DetectionService, ThreatService

router = APIRouter(prefix="/detections", tags=["ai-detection"])

DetDep = Annotated[DetectionService, Depends(get_detection_service)]
ThreatDep = Annotated[ThreatService, Depends(get_threat_service)]


# ── Detections ──────────────────────────────────────────────────
@router.get("", response_model=list[DetectionResponse])
async def list_detections(
    svc: DetDep,
    _: Annotated[object, Depends(require_permission("detection:read"))],
    organization_id: uuid.UUID | None = None,
    detection_type: DetectionType | None = None,
    status_filter: Annotated[DetectionStatus | None, Query(alias="status")] = None,
) -> list[DetectionResponse]:
    rows = await svc.list(
        organization_id=organization_id,
        filters={"detection_type": detection_type, "status": status_filter},
        order_desc="detected_at",
    )
    return [DetectionResponse.model_validate(d) for d in rows]


@router.post("/ingest", response_model=DetectionIngestResult, status_code=status.HTTP_201_CREATED)
async def ingest_detection(
    body: DetectionIngest,
    svc: DetDep,
    principal: Annotated[object, Depends(require_permission("detection:manage"))],
) -> DetectionIngestResult:
    det, threat = await svc.ingest(
        organization_id=body.organization_id, detection_type=body.detection_type,
        confidence=body.confidence, site_id=body.site_id, zone_id=body.zone_id,
        camera_id=body.camera_id, label=body.label, snapshot_ref=body.snapshot_ref,
        meta=body.meta, actor_id=principal.user_id,  # type: ignore[attr-defined]
    )
    return DetectionIngestResult(
        detection=DetectionResponse.model_validate(det),
        threat_id=threat.id if threat else None,
    )


@router.post("/{detection_id}/status", response_model=DetectionResponse)
async def set_detection_status(
    detection_id: uuid.UUID,
    body: DetectionStatusUpdate,
    svc: DetDep,
    principal: Annotated[object, Depends(require_permission("detection:manage"))],
) -> DetectionResponse:
    det = await svc.set_status(detection_id, body.status, actor_id=principal.user_id)  # type: ignore[attr-defined]
    return DetectionResponse.model_validate(det)


# ── Threats (Threat Intelligence Center) ────────────────────────
@router.get("/threats/list", response_model=list[ThreatResponse])
async def list_threats(
    svc: ThreatDep,
    _: Annotated[object, Depends(require_permission("threat:read"))],
    organization_id: uuid.UUID | None = None,
    risk_level: ThreatLevel | None = None,
    status_filter: Annotated[ThreatStatus | None, Query(alias="status")] = None,
) -> list[ThreatResponse]:
    rows = await svc.list(
        organization_id=organization_id,
        filters={"risk_level": risk_level, "status": status_filter},
        order_desc="score",
    )
    return [ThreatResponse.model_validate(th) for th in rows]


@router.get("/threats/summary", response_model=dict)
async def threats_summary(
    svc: ThreatDep,
    _: Annotated[object, Depends(require_permission("threat:read"))],
    organization_id: uuid.UUID | None = None,
) -> dict:
    return await svc.active_summary(organization_id=organization_id)


@router.post("/threats/{threat_id}/status", response_model=ThreatResponse)
async def set_threat_status(
    threat_id: uuid.UUID,
    body: ThreatStatusUpdate,
    svc: ThreatDep,
    principal: Annotated[object, Depends(require_permission("threat:manage"))],
) -> ThreatResponse:
    threat = await svc.set_status(threat_id, body.status, actor_id=principal.user_id)  # type: ignore[attr-defined]
    return ThreatResponse.model_validate(threat)


@router.post("/threats/{threat_id}/escalate", response_model=ThreatResponse)
async def escalate_threat(
    threat_id: uuid.UUID,
    svc: ThreatDep,
    principal: Annotated[object, Depends(require_permission("threat:manage"))],
) -> ThreatResponse:
    threat = await svc.escalate_to_incident(threat_id, actor_id=principal.user_id)  # type: ignore[attr-defined]
    return ThreatResponse.model_validate(threat)
