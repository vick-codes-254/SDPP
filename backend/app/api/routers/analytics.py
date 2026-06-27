"""Analytics, BI, GIS map feed, and intelligence reports."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends

from app.api.deps import get_analytics_service, require_permission
from app.services.analytics_service import AnalyticsService

router = APIRouter(prefix="/analytics", tags=["analytics"])

Dep = Annotated[AnalyticsService, Depends(get_analytics_service)]
Read = Annotated[object, Depends(require_permission("analytics:read"))]


@router.get("/kpis", response_model=dict)
async def kpis(svc: Dep, _: Read, organization_id: uuid.UUID | None = None) -> dict:
    return await svc.kpis(organization_id=organization_id)


@router.get("/trends/incidents", response_model=list[dict])
async def incident_trends(svc: Dep, _: Read, organization_id: uuid.UUID | None = None,
                          days: int = 14) -> list[dict]:
    return await svc.incident_trends(organization_id=organization_id, days=days)


@router.get("/trends/threats", response_model=list[dict])
async def threat_trends(svc: Dep, _: Read, organization_id: uuid.UUID | None = None,
                        days: int = 14) -> list[dict]:
    return await svc.threat_trends(organization_id=organization_id, days=days)


@router.get("/detections", response_model=dict)
async def detection_breakdown(svc: Dep, _: Read,
                              organization_id: uuid.UUID | None = None) -> dict:
    return await svc.detection_breakdown(organization_id=organization_id)


@router.get("/response-times", response_model=dict)
async def response_times(svc: Dep, _: Read,
                         organization_id: uuid.UUID | None = None) -> dict:
    return await svc.response_times(organization_id=organization_id)


@router.get("/camera-uptime", response_model=dict)
async def camera_uptime(svc: Dep, _: Read,
                        organization_id: uuid.UUID | None = None) -> dict:
    return await svc.camera_uptime(organization_id=organization_id)


@router.get("/map", response_model=dict)
async def map_feed(svc: Dep, _: Read, organization_id: uuid.UUID | None = None) -> dict:
    return await svc.map_feed(organization_id=organization_id)


@router.get("/reports/{kind}", response_model=dict)
async def report(kind: str, svc: Dep, _: Read,
                 organization_id: uuid.UUID | None = None) -> dict:
    return await svc.generate_report(kind=kind, organization_id=organization_id)
