"""Physical-security services: cameras, guards, patrols, visitors, contractors,
access control, and vehicles/ANPR.

Each service extends the generic tenant CRUD base and adds its domain logic:
camera heartbeats, patrol scan verification, visitor check-in/out & blacklist
matching (blind index), access-event logging, and ANPR watchlist matching.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select

from app.core.enums import (
    AccessDecision,
    CameraStatus,
    PatrolStatus,
    VehicleStatus,
    VisitorStatus,
)
from app.core.security.field_encryption import get_field_cipher
from app.models.access import AccessEvent, AccessPoint
from app.models.camera import Camera
from app.models.guard import Guard, Patrol, PatrolScan
from app.models.vehicle import Vehicle, VehicleEvent
from app.models.visitor import Contractor, Visitor
from app.services.crud import CrudService


def _now() -> datetime:
    return datetime.now(UTC)


def _norm_plate(plate: str) -> str:
    return "".join(plate.split()).upper()


# ════════════════════════════════════════════════════════════════
#  Cameras
# ════════════════════════════════════════════════════════════════
class CameraService(CrudService[Camera]):
    model = Camera
    audit_resource = "camera"

    async def heartbeat(self, camera_id: uuid.UUID, *, online: bool,
                        recording: bool | None = None) -> Camera:
        cam = await self.get_or_404(camera_id)
        cam.status = CameraStatus.online if online else CameraStatus.offline
        cam.last_heartbeat_at = _now()
        if recording is not None:
            cam.is_recording = recording
        await self.db.flush()
        return cam

    async def health_summary(self, *, organization_id: uuid.UUID | None = None) -> dict[str, int]:
        rows = await self.list(organization_id=organization_id, limit=10_000)
        total = len(rows)
        online = sum(1 for c in rows if c.status == CameraStatus.online)
        recording = sum(1 for c in rows if c.is_recording)
        return {
            "total": total,
            "online": online,
            "offline": total - online,
            "recording": recording,
        }


# ════════════════════════════════════════════════════════════════
#  Guards & patrols
# ════════════════════════════════════════════════════════════════
class GuardService(CrudService[Guard]):
    model = Guard
    audit_resource = "guard"

    async def update_position(self, guard_id: uuid.UUID, *, lat: float, lng: float) -> Guard:
        guard = await self.get_or_404(guard_id)
        guard.last_lat, guard.last_lng, guard.last_seen_at = lat, lng, _now()
        await self.db.flush()
        return guard

    async def on_duty_count(self, *, organization_id: uuid.UUID | None = None) -> int:
        from app.core.enums import GuardStatus

        stmt = select(func.count()).select_from(Guard).where(Guard.status == GuardStatus.on_duty)
        if organization_id is not None:
            stmt = stmt.where(Guard.organization_id == organization_id)
        return int((await self.db.execute(stmt)).scalar_one())


class PatrolService(CrudService[Patrol]):
    model = Patrol
    audit_resource = "patrol"

    async def start(self, patrol_id: uuid.UUID) -> Patrol:
        patrol = await self.get_or_404(patrol_id)
        patrol.status = PatrolStatus.in_progress
        patrol.started_at = _now()
        await self.db.flush()
        return patrol

    async def record_scan(self, patrol_id: uuid.UUID, *, checkpoint_id: uuid.UUID | None,
                          gps_verified: bool = False, lat: float | None = None,
                          lng: float | None = None) -> PatrolScan:
        patrol = await self.get_or_404(patrol_id)
        scan = PatrolScan(
            id=uuid.uuid4(), patrol_id=patrol.id, checkpoint_id=checkpoint_id,
            scanned_at=_now(), gps_verified=gps_verified, lat=lat, lng=lng,
        )
        self.db.add(scan)
        if patrol.status == PatrolStatus.scheduled:
            patrol.status = PatrolStatus.in_progress
            patrol.started_at = patrol.started_at or _now()
        await self.db.flush()
        return scan

    async def complete(self, patrol_id: uuid.UUID) -> Patrol:
        patrol = await self.get_or_404(patrol_id)
        patrol.status = PatrolStatus.completed
        patrol.completed_at = _now()
        await self.db.flush()
        return patrol


# ════════════════════════════════════════════════════════════════
#  Visitors & contractors
# ════════════════════════════════════════════════════════════════
class VisitorService(CrudService[Visitor]):
    model = Visitor
    audit_resource = "visitor"

    @staticmethod
    def _name_index(name: str | None) -> str | None:
        return get_field_cipher().blind_index(name.strip().lower()) if name else None

    def _pre_create(self, data: dict[str, Any]) -> dict[str, Any]:
        data["name_bidx"] = self._name_index(data.get("full_name"))
        return data

    async def is_blacklisted(self, full_name: str) -> bool:
        idx = self._name_index(full_name)
        if idx is None:
            return False
        row = (await self.db.execute(
            select(Visitor.id).where(
                Visitor.name_bidx == idx, Visitor.status == VisitorStatus.blacklisted
            ).limit(1)
        )).scalar_one_or_none()
        return row is not None

    async def set_status(self, visitor_id: uuid.UUID, status: VisitorStatus, *,
                         actor_id: uuid.UUID | None = None) -> Visitor:
        visitor = await self.get_or_404(visitor_id)
        visitor.status = status
        now = _now()
        if status == VisitorStatus.checked_in:
            visitor.check_in_at = now
            visitor.badge_code = visitor.badge_code or uuid.uuid4().hex[:8].upper()
        elif status == VisitorStatus.checked_out:
            visitor.check_out_at = now
        await self.db.flush()
        await self._audit(f"status:{status}", str(visitor.id), actor_id)
        return visitor

    async def active_today(self, *, organization_id: uuid.UUID | None = None) -> int:
        stmt = select(func.count()).select_from(Visitor).where(
            Visitor.status == VisitorStatus.checked_in
        )
        if organization_id is not None:
            stmt = stmt.where(Visitor.organization_id == organization_id)
        return int((await self.db.execute(stmt)).scalar_one())


class ContractorService(CrudService[Contractor]):
    model = Contractor
    audit_resource = "contractor"


# ════════════════════════════════════════════════════════════════
#  Access control
# ════════════════════════════════════════════════════════════════
class AccessService(CrudService[AccessPoint]):
    model = AccessPoint
    audit_resource = "access_point"

    async def log_event(self, *, organization_id: uuid.UUID, access_point_id: uuid.UUID,
                        credential_type, subject_label: str | None, decision: AccessDecision,
                        reason: str | None = None) -> AccessEvent:
        event = AccessEvent(
            id=uuid.uuid4(), organization_id=organization_id,
            access_point_id=access_point_id, credential_type=credential_type,
            subject_label=subject_label, decision=decision, reason=reason, occurred_at=_now(),
        )
        self.db.add(event)
        await self.db.flush()
        return event

    async def recent_events(self, *, organization_id: uuid.UUID | None = None,
                            limit: int = 100) -> list[AccessEvent]:
        stmt = select(AccessEvent).order_by(AccessEvent.occurred_at.desc()).limit(limit)
        if organization_id is not None:
            stmt = stmt.where(AccessEvent.organization_id == organization_id)
        return list((await self.db.execute(stmt)).scalars().all())


# ════════════════════════════════════════════════════════════════
#  Vehicles & ANPR
# ════════════════════════════════════════════════════════════════
@dataclass(slots=True)
class AnprResult:
    event: VehicleEvent
    vehicle: Vehicle | None
    flagged: bool  # plate is watchlisted/blacklisted


class VehicleService(CrudService[Vehicle]):
    model = Vehicle
    audit_resource = "vehicle"

    @staticmethod
    def _plate_index(plate: str) -> str:
        return get_field_cipher().blind_index(_norm_plate(plate))

    def _pre_create(self, data: dict[str, Any]) -> dict[str, Any]:
        if data.get("plate"):
            data["plate_bidx"] = self._plate_index(data["plate"])
        return data

    async def find_by_plate(self, plate: str) -> Vehicle | None:
        return (await self.db.execute(
            select(Vehicle).where(Vehicle.plate_bidx == self._plate_index(plate))
        )).scalar_one_or_none()

    async def record_anpr(self, *, organization_id: uuid.UUID, plate: str, direction,
                          site_id: uuid.UUID | None = None, camera_id: uuid.UUID | None = None,
                          confidence: str | None = None) -> AnprResult:
        vehicle = await self.find_by_plate(plate)
        flagged = bool(
            vehicle
            and (vehicle.is_watchlisted or vehicle.status in
                 (VehicleStatus.watchlisted, VehicleStatus.blacklisted))
        )
        event = VehicleEvent(
            id=uuid.uuid4(), organization_id=organization_id, site_id=site_id,
            camera_id=camera_id, vehicle_id=vehicle.id if vehicle else None,
            plate=_norm_plate(plate), plate_bidx=self._plate_index(plate),
            direction=direction, authorized=not flagged, confidence=confidence,
            occurred_at=_now(),
        )
        self.db.add(event)
        await self.db.flush()
        return AnprResult(event=event, vehicle=vehicle, flagged=flagged)

    async def recent_events(self, *, organization_id: uuid.UUID | None = None,
                            limit: int = 100) -> list[VehicleEvent]:
        stmt = select(VehicleEvent).order_by(VehicleEvent.occurred_at.desc()).limit(limit)
        if organization_id is not None:
            stmt = stmt.where(VehicleEvent.organization_id == organization_id)
        return list((await self.db.execute(stmt)).scalars().all())
