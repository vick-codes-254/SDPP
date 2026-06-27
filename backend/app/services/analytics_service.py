"""Analytics, BI, GIS map feeds, and intelligence reports.

All read-only aggregation over existing domain tables — KPIs, trends, detection
breakdowns, response-time analytics, camera uptime, a map feed (sites + live guard
positions), and on-demand daily/weekly/monthly/executive intelligence reports.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import (
    CameraStatus,
    CyberEventStatus,
    GuardStatus,
    IncidentStatus,
    ThreatStatus,
    VisitorStatus,
)
from app.models.access import AccessEvent
from app.models.camera import Camera
from app.models.cyber import CyberEvent
from app.models.detection import Detection, Threat
from app.models.guard import Guard
from app.models.incident import Incident
from app.models.site import Site
from app.models.vehicle import VehicleEvent
from app.models.visitor import Visitor


def _now() -> datetime:
    return datetime.now(UTC)


def _as_utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=UTC)


class AnalyticsService:
    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    async def _count(self, model, *conds, organization_id=None, tenant=True) -> int:
        stmt = select(func.count()).select_from(model)
        for c in conds:
            stmt = stmt.where(c)
        if organization_id is not None and tenant and hasattr(model, "organization_id"):
            stmt = stmt.where(model.organization_id == organization_id)
        return int((await self.db.execute(stmt)).scalar_one())

    # ── KPIs ────────────────────────────────────────────────────
    async def kpis(self, *, organization_id: uuid.UUID | None = None) -> dict:
        return {
            "sites": await self._count(Site, organization_id=organization_id),
            "cameras": await self._count(Camera, organization_id=organization_id),
            "cameras_online": await self._count(
                Camera, Camera.status == CameraStatus.online, organization_id=organization_id
            ),
            "open_threats": await self._count(
                Threat, Threat.status == ThreatStatus.active, organization_id=organization_id
            ),
            "open_incidents": await self._count(
                Incident, Incident.status.notin_([IncidentStatus.resolved, IncidentStatus.closed]),
                organization_id=organization_id,
            ),
            "open_cyber_events": await self._count(
                CyberEvent, CyberEvent.status == CyberEventStatus.new,
                organization_id=organization_id,
            ),
            "guards_on_duty": await self._count(
                Guard, Guard.status == GuardStatus.on_duty, organization_id=organization_id
            ),
            "visitors_on_site": await self._count(
                Visitor, Visitor.status == VisitorStatus.checked_in,
                organization_id=organization_id,
            ),
        }

    # ── Trends (per-day counts over a window) ───────────────────
    async def _daily(self, model, ts_col, days: int, organization_id) -> list[dict]:
        start = _now() - timedelta(days=days)
        day = func.date(ts_col)
        stmt = select(day, func.count()).where(ts_col >= start).group_by(day).order_by(day)
        if organization_id is not None and hasattr(model, "organization_id"):
            stmt = stmt.where(model.organization_id == organization_id)
        rows = (await self.db.execute(stmt)).all()
        return [{"date": str(d), "count": int(c)} for d, c in rows]

    async def threat_trends(self, *, organization_id=None, days: int = 14) -> list[dict]:
        return await self._daily(Detection, Detection.detected_at, days, organization_id)

    async def incident_trends(self, *, organization_id=None, days: int = 14) -> list[dict]:
        return await self._daily(Incident, Incident.created_at, days, organization_id)

    async def detection_breakdown(self, *, organization_id=None) -> dict[str, int]:
        stmt = select(Detection.detection_type, func.count()).group_by(Detection.detection_type)
        if organization_id is not None:
            stmt = stmt.where(Detection.organization_id == organization_id)
        rows = (await self.db.execute(stmt)).all()
        return {(t.value if hasattr(t, "value") else str(t)): int(c) for t, c in rows}

    # ── Response-time analytics (computed in Python for portability) ─
    async def response_times(self, *, organization_id=None) -> dict:
        stmt = select(Incident)
        if organization_id is not None:
            stmt = stmt.where(Incident.organization_id == organization_id)
        incidents = list((await self.db.execute(stmt)).scalars().all())
        ack, res = [], []
        for inc in incidents:
            created = _as_utc(inc.created_at)
            if inc.acknowledged_at and created:
                ack.append((_as_utc(inc.acknowledged_at) - created).total_seconds() / 60)
            if inc.resolved_at and created:
                res.append((_as_utc(inc.resolved_at) - created).total_seconds() / 60)
        breached = sum(
            1 for inc in incidents
            if inc.sla_due_at and inc.resolved_at is None and _as_utc(inc.sla_due_at) < _now()
        )
        return {
            "avg_ack_minutes": round(sum(ack) / len(ack), 1) if ack else None,
            "avg_resolve_minutes": round(sum(res) / len(res), 1) if res else None,
            "incidents": len(incidents),
            "sla_breached_open": breached,
        }

    async def camera_uptime(self, *, organization_id=None) -> dict:
        total = await self._count(Camera, organization_id=organization_id)
        online = await self._count(
            Camera, Camera.status == CameraStatus.online, organization_id=organization_id
        )
        pct = round(online / total * 100, 1) if total else 0.0
        return {"cameras": total, "online": online, "uptime_pct": pct}

    # ── GIS / map feed ──────────────────────────────────────────
    async def map_feed(self, *, organization_id=None) -> dict:
        site_stmt = select(Site).where(Site.latitude.isnot(None))
        if organization_id is not None:
            site_stmt = site_stmt.where(Site.organization_id == organization_id)
        sites = list((await self.db.execute(site_stmt)).scalars().all())

        guard_stmt = select(Guard).where(Guard.last_lat.isnot(None))
        if organization_id is not None:
            guard_stmt = guard_stmt.where(Guard.organization_id == organization_id)
        guards = list((await self.db.execute(guard_stmt)).scalars().all())

        return {
            "sites": [
                {"id": str(s.id), "name": s.name, "lat": s.latitude, "lng": s.longitude,
                 "type": s.site_type.value, "status": s.status.value}
                for s in sites
            ],
            "guards": [
                {"id": str(g.id), "code": g.employee_code, "lat": g.last_lat,
                 "lng": g.last_lng, "status": g.status.value}
                for g in guards
            ],
        }

    # ── Intelligence reports (on-demand) ────────────────────────
    async def generate_report(self, *, kind: str = "daily",
                              organization_id: uuid.UUID | None = None) -> dict:
        windows = {"daily": 1, "weekly": 7, "monthly": 30, "executive": 30}
        days = windows.get(kind, 1)
        return {
            "kind": kind,
            "period_days": days,
            "generated_at": _now().isoformat(),
            "organization_id": str(organization_id) if organization_id else None,
            "kpis": await self.kpis(organization_id=organization_id),
            "incident_trends": await self.incident_trends(organization_id=organization_id, days=days),
            "threat_trends": await self.threat_trends(organization_id=organization_id, days=days),
            "detection_breakdown": await self.detection_breakdown(organization_id=organization_id),
            "response_times": await self.response_times(organization_id=organization_id),
            "camera_uptime": await self.camera_uptime(organization_id=organization_id),
            "anpr_events": await self._count(VehicleEvent, organization_id=organization_id),
            "access_events": await self._count(AccessEvent, organization_id=organization_id),
        }
