"""Cybersecurity monitoring & user-behaviour analytics.

Ingests authentication events and runs behavioural detectors:
  - brute force         : >= N failures for a username within a short window
  - impossible travel   : two successful logins from far-apart locations too fast
  - new device          : first time a device fingerprint is seen for a user
  - suspicious login    : success from a new country

Detections are written to the ``cyber_events`` SOC queue (and high-severity ones
also raise a SecurityAlert). Designed to ingest from the auth stream or an
external IdP — no external calls, fully testable offline.
"""

from __future__ import annotations

import math
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import (
    AlertSeverity,
    AlertStatus,
    AlertType,
    CyberEventStatus,
    CyberEventType,
)
from app.models.audit import SecurityAlert
from app.models.cyber import CyberEvent, Device, LoginAttempt
from app.services.audit_service import AuditService

BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW = timedelta(minutes=15)
IMPOSSIBLE_TRAVEL_WINDOW = timedelta(hours=2)
IMPOSSIBLE_TRAVEL_SPEED_KMH = 900.0  # faster than a commercial flight => impossible


def _now() -> datetime:
    return datetime.now(UTC)


def _as_utc(dt: datetime) -> datetime:
    """Coerce a possibly-naive DB timestamp (SQLite drops tzinfo) to UTC-aware."""
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=UTC)


def _haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    r = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlmb = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dlmb / 2) ** 2
    return 2 * r * math.asin(min(1.0, math.sqrt(a)))


class CyberMonitoringService:
    def __init__(self, db: AsyncSession, *, audit: AuditService | None = None) -> None:
        self.db = db
        self.audit = audit or AuditService(db)

    async def _emit(
        self,
        *,
        event_type: CyberEventType,
        severity: AlertSeverity,
        title: str,
        username: str | None = None,
        user_id: uuid.UUID | None = None,
        ip_address: str | None = None,
        country: str | None = None,
        organization_id: uuid.UUID | None = None,
        detail: dict | None = None,
    ) -> CyberEvent:
        event = CyberEvent(
            id=uuid.uuid4(), organization_id=organization_id, event_type=event_type,
            severity=severity, status=CyberEventStatus.new, user_id=user_id,
            username=username, ip_address=ip_address, country=country, title=title,
            detail=detail or {}, occurred_at=_now(),
        )
        self.db.add(event)
        # High-severity cyber events also raise a SOC alert.
        if severity in (AlertSeverity.high, AlertSeverity.critical):
            self.db.add(SecurityAlert(
                id=uuid.uuid4(),
                alert_type=AlertType.brute_force if event_type == CyberEventType.brute_force
                else AlertType.unauthorized_access,
                severity=severity, status=AlertStatus.open, title=title,
                description=f"Cyber event: {event_type.value} for {username or 'unknown'}",
                related_user_id=user_id, source_ref=f"cyber:{event.id}",
            ))
        await self.db.flush()
        return event

    async def record_login(
        self,
        *,
        username: str,
        success: bool,
        user_id: uuid.UUID | None = None,
        organization_id: uuid.UUID | None = None,
        ip_address: str | None = None,
        country: str | None = None,
        city: str | None = None,
        latitude: float | None = None,
        longitude: float | None = None,
        device_fingerprint: str | None = None,
        user_agent: str | None = None,
    ) -> list[CyberEvent]:
        """Record an auth attempt and run detectors. Returns triggered events."""
        now = _now()
        attempt = LoginAttempt(
            id=uuid.uuid4(), organization_id=organization_id, user_id=user_id,
            username=username, ip_address=ip_address, country=country, city=city,
            latitude=latitude, longitude=longitude, device_fingerprint=device_fingerprint,
            user_agent=user_agent, success=success, occurred_at=now,
        )
        self.db.add(attempt)
        await self.db.flush()

        events: list[CyberEvent] = []

        if not success:
            # Brute force: count recent failures for this username.
            since = now - BRUTE_FORCE_WINDOW
            failures = int((await self.db.execute(
                select(func.count()).select_from(LoginAttempt).where(
                    LoginAttempt.username == username,
                    LoginAttempt.success.is_(False),
                    LoginAttempt.occurred_at >= since,
                )
            )).scalar_one())
            if failures >= BRUTE_FORCE_THRESHOLD:
                events.append(await self._emit(
                    event_type=CyberEventType.brute_force, severity=AlertSeverity.high,
                    title=f"Brute-force suspected for '{username}' ({failures} failures/15m)",
                    username=username, user_id=user_id, ip_address=ip_address,
                    country=country, organization_id=organization_id,
                    detail={"failures": failures},
                ))
            else:
                events.append(await self._emit(
                    event_type=CyberEventType.failed_login, severity=AlertSeverity.low,
                    title=f"Failed login for '{username}'", username=username,
                    user_id=user_id, ip_address=ip_address, country=country,
                    organization_id=organization_id,
                ))
            return events

        # ── Successful login analytics (need a user to profile) ──
        if user_id is not None:
            events += await self._check_new_device(
                user_id, username, device_fingerprint, ip_address, country,
                organization_id, now,
            )
            events += await self._check_impossible_travel(
                user_id, username, latitude, longitude, country, ip_address,
                organization_id, attempt.id, now,
            )
        return events

    async def _check_new_device(self, user_id, username, fingerprint, ip_address,
                                country, organization_id, now) -> list[CyberEvent]:
        if not fingerprint:
            return []
        device = (await self.db.execute(
            select(Device).where(Device.user_id == user_id, Device.fingerprint == fingerprint)
        )).scalar_one_or_none()
        if device is not None:
            device.last_seen_at = now
            device.last_ip = ip_address
            device.last_country = country
            await self.db.flush()
            return []
        self.db.add(Device(
            id=uuid.uuid4(), user_id=user_id, fingerprint=fingerprint, trusted=False,
            last_ip=ip_address, last_country=country, first_seen_at=now, last_seen_at=now,
        ))
        await self.db.flush()
        return [await self._emit(
            event_type=CyberEventType.new_device, severity=AlertSeverity.medium,
            title=f"New device for '{username}'", username=username, user_id=user_id,
            ip_address=ip_address, country=country, organization_id=organization_id,
            detail={"fingerprint": fingerprint[:16]},
        )]

    async def _check_impossible_travel(self, user_id, username, lat, lng, country,
                                       ip_address, organization_id, current_id, now) -> list[CyberEvent]:
        since = now - IMPOSSIBLE_TRAVEL_WINDOW
        prev = (await self.db.execute(
            select(LoginAttempt).where(
                LoginAttempt.user_id == user_id,
                LoginAttempt.success.is_(True),
                LoginAttempt.id != current_id,
                LoginAttempt.occurred_at >= since,
            ).order_by(LoginAttempt.occurred_at.desc()).limit(1)
        )).scalar_one_or_none()
        if prev is None:
            return []

        impossible = False
        detail: dict = {}
        if None not in (lat, lng, prev.latitude, prev.longitude):
            dist = _haversine_km(prev.latitude, prev.longitude, lat, lng)
            hours = max((now - _as_utc(prev.occurred_at)).total_seconds() / 3600.0, 1 / 60)
            speed = dist / hours
            detail = {"distance_km": round(dist), "speed_kmh": round(speed)}
            impossible = speed > IMPOSSIBLE_TRAVEL_SPEED_KMH
        elif prev.country and country and prev.country != country:
            # Different country within the window with no coords -> flag.
            detail = {"from_country": prev.country, "to_country": country}
            impossible = True

        if not impossible:
            return []
        return [await self._emit(
            event_type=CyberEventType.impossible_travel, severity=AlertSeverity.high,
            title=f"Impossible travel for '{username}'", username=username, user_id=user_id,
            ip_address=ip_address, country=country, organization_id=organization_id,
            detail=detail,
        )]

    async def record_privilege_change(self, *, user_id: uuid.UUID, username: str,
                                      old_count: int, new_count: int,
                                      organization_id: uuid.UUID | None = None) -> CyberEvent | None:
        if new_count <= old_count:
            return None
        return await self._emit(
            event_type=CyberEventType.privilege_escalation, severity=AlertSeverity.high,
            title=f"Privilege escalation for '{username}' ({old_count}->{new_count} perms)",
            username=username, user_id=user_id, organization_id=organization_id,
            detail={"old": old_count, "new": new_count},
        )

    # ── Reads (SOC workspace) ───────────────────────────────────
    async def list_events(self, *, organization_id: uuid.UUID | None = None,
                          event_type: CyberEventType | None = None,
                          limit: int = 100) -> list[CyberEvent]:
        stmt = select(CyberEvent).order_by(CyberEvent.occurred_at.desc()).limit(limit)
        if organization_id is not None:
            stmt = stmt.where(CyberEvent.organization_id == organization_id)
        if event_type is not None:
            stmt = stmt.where(CyberEvent.event_type == event_type)
        return list((await self.db.execute(stmt)).scalars().all())

    async def list_attempts(self, *, username: str | None = None,
                            limit: int = 100) -> list[LoginAttempt]:
        stmt = select(LoginAttempt).order_by(LoginAttempt.occurred_at.desc()).limit(limit)
        if username is not None:
            stmt = stmt.where(LoginAttempt.username == username)
        return list((await self.db.execute(stmt)).scalars().all())

    async def list_devices(self, user_id: uuid.UUID) -> list[Device]:
        return list((await self.db.execute(
            select(Device).where(Device.user_id == user_id).order_by(Device.last_seen_at.desc())
        )).scalars().all())

    async def soc_summary(self, *, organization_id: uuid.UUID | None = None) -> dict:
        stmt = select(CyberEvent.event_type, func.count()).group_by(CyberEvent.event_type)
        if organization_id is not None:
            stmt = stmt.where(CyberEvent.organization_id == organization_id)
        rows = (await self.db.execute(stmt)).all()
        by_type = {t.value: 0 for t in CyberEventType}
        for et, count in rows:
            by_type[et.value if hasattr(et, "value") else str(et)] = int(count)
        open_stmt = select(func.count()).select_from(CyberEvent).where(
            CyberEvent.status == CyberEventStatus.new
        )
        if organization_id is not None:
            open_stmt = open_stmt.where(CyberEvent.organization_id == organization_id)
        return {
            "by_type": by_type,
            "total_events": sum(by_type.values()),
            "open_events": int((await self.db.execute(open_stmt)).scalar_one()),
        }

    async def set_status(self, event_id: uuid.UUID, status: CyberEventStatus) -> CyberEvent:
        event = (await self.db.execute(
            select(CyberEvent).where(CyberEvent.id == event_id)
        )).scalar_one_or_none()
        if event is None:
            from app.services.exceptions import NotFoundError
            raise NotFoundError("Cyber event not found")
        event.status = status
        await self.db.flush()
        return event
