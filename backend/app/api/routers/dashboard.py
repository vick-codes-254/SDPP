"""Security monitoring dashboard & alert endpoints."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query

from app.api.deps import get_monitoring_service, require_permission
from app.core.enums import AlertStatus
from app.schemas.common import Message
from app.schemas.security import AlertResponse, DashboardResponse
from app.services.exceptions import NotFoundError
from app.services.monitoring_service import MonitoringService

router = APIRouter(tags=["monitoring"])

MonDep = Annotated[MonitoringService, Depends(get_monitoring_service)]


@router.get("/security-dashboard", response_model=DashboardResponse)
async def security_dashboard(
    mon: MonDep,
    principal: Annotated[object, Depends(require_permission("dashboard:read"))],
) -> DashboardResponse:
    return DashboardResponse(**(await mon.dashboard()).to_dict())


@router.get("/alerts", response_model=list[AlertResponse])
async def list_alerts(
    mon: MonDep,
    principal: Annotated[object, Depends(require_permission("alert:read"))],
    status_filter: Annotated[AlertStatus | None, Query(alias="status")] = None,
) -> list[AlertResponse]:
    alerts = await mon.list_alerts(status=status_filter)
    return [AlertResponse.model_validate(a) for a in alerts]


@router.post("/alerts/{alert_id}/acknowledge", response_model=Message)
async def acknowledge_alert(
    alert_id: uuid.UUID,
    mon: MonDep,
    principal: Annotated[object, Depends(require_permission("alert:acknowledge"))],
) -> Message:
    alert = await mon.acknowledge_alert(alert_id, actor_id=principal.user_id)  # type: ignore[attr-defined]
    if alert is None:
        raise NotFoundError("Alert not found")
    return Message(detail="Alert acknowledged")


@router.post("/alerts/{alert_id}/resolve", response_model=Message)
async def resolve_alert(
    alert_id: uuid.UUID,
    mon: MonDep,
    principal: Annotated[object, Depends(require_permission("alert:acknowledge"))],
    false_positive: bool = False,
) -> Message:
    alert = await mon.resolve_alert(
        alert_id, actor_id=principal.user_id, false_positive=false_positive  # type: ignore[attr-defined]
    )
    if alert is None:
        raise NotFoundError("Alert not found")
    return Message(detail="Alert resolved")
