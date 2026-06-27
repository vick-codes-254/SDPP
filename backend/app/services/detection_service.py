"""AI detection ingestion + threat-intelligence correlation & risk scoring.

Pipeline:
  ingest(detection) -> RiskEngine scores it -> if high/critical, correlate into an
  active Threat for the same site+type (or open a new one) -> Threat can be
  escalated into a formal Incident.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select

from app.core.enums import (
    DetectionStatus,
    DetectionType,
    IncidentSeverity,
    ThreatLevel,
    ThreatStatus,
)
from app.models.detection import Detection, Threat
from app.services.crud import CrudService
from app.services.incident_service import IncidentService


def _now() -> datetime:
    return datetime.now(UTC)


# ── Risk engine ─────────────────────────────────────────────────
class RiskEngine:
    """Maps a detection (type + confidence) to a 0-100 risk score and level."""

    WEIGHTS: dict[DetectionType, int] = {
        DetectionType.weapon: 95,
        DetectionType.fire: 90,
        DetectionType.intrusion: 80,
        DetectionType.perimeter_breach: 80,
        DetectionType.smoke: 70,
        DetectionType.flood: 60,
        DetectionType.tailgating: 55,
        DetectionType.abandoned_object: 55,
        DetectionType.suspicious_object: 50,
        DetectionType.face_match: 50,
        DetectionType.unknown_person: 45,
        DetectionType.removed_object: 40,
        DetectionType.crowd: 40,
        DetectionType.running: 35,
        DetectionType.loitering: 30,
        DetectionType.multiple_persons: 30,
        DetectionType.vehicle: 10,
        DetectionType.person: 10,
    }

    @classmethod
    def score(cls, detection_type: DetectionType, confidence: float) -> int:
        weight = cls.WEIGHTS.get(detection_type, 25)
        conf = min(max(confidence, 0.0), 1.0) or 0.5
        return max(0, min(100, round(weight * conf)))

    @staticmethod
    def level(score: int) -> ThreatLevel:
        if score >= 85:
            return ThreatLevel.critical
        if score >= 65:
            return ThreatLevel.high
        if score >= 40:
            return ThreatLevel.medium
        if score >= 20:
            return ThreatLevel.low
        return ThreatLevel.info


_LEVEL_TO_INCIDENT = {
    ThreatLevel.critical: IncidentSeverity.critical,
    ThreatLevel.high: IncidentSeverity.high,
    ThreatLevel.medium: IncidentSeverity.medium,
    ThreatLevel.low: IncidentSeverity.low,
    ThreatLevel.info: IncidentSeverity.low,
}
_CORRELATION_WINDOW = timedelta(minutes=30)
_AUTO_THREAT_LEVELS = {ThreatLevel.high, ThreatLevel.critical}


class DetectionService(CrudService[Detection]):
    model = Detection
    audit_resource = "detection"

    async def ingest(
        self,
        *,
        organization_id: uuid.UUID,
        detection_type: DetectionType,
        confidence: float = 0.8,
        site_id: uuid.UUID | None = None,
        zone_id: uuid.UUID | None = None,
        camera_id: uuid.UUID | None = None,
        label: str | None = None,
        snapshot_ref: str | None = None,
        meta: dict[str, Any] | None = None,
        actor_id: uuid.UUID | None = None,
    ) -> tuple[Detection, Threat | None]:
        score = RiskEngine.score(detection_type, confidence)
        severity = RiskEngine.level(score)
        det = Detection(
            id=uuid.uuid4(), organization_id=organization_id, site_id=site_id,
            zone_id=zone_id, camera_id=camera_id, detection_type=detection_type,
            confidence=confidence, severity=severity, status=DetectionStatus.new,
            label=label, snapshot_ref=snapshot_ref, meta=meta or {}, detected_at=_now(),
        )
        self.db.add(det)
        await self.db.flush()

        threat: Threat | None = None
        if severity in _AUTO_THREAT_LEVELS:
            threat = await ThreatService(self.db, audit=self.audit).correlate(det, score)
            det.threat_id = threat.id
            await self.db.flush()

        await self._audit("ingest", str(det.id), actor_id,
                          {"type": str(detection_type), "score": score})
        return det, threat

    async def set_status(self, detection_id: uuid.UUID, status: DetectionStatus, *,
                         actor_id: uuid.UUID | None = None) -> Detection:
        det = await self.get_or_404(detection_id)
        det.status = status
        await self.db.flush()
        await self._audit(f"status:{status}", str(det.id), actor_id)
        return det


class ThreatService(CrudService[Threat]):
    model = Threat
    audit_resource = "threat"

    async def correlate(self, detection: Detection, score: int) -> Threat:
        """Attach the detection to a recent active threat of the same kind/site,
        or open a new threat."""
        window_start = _now() - _CORRELATION_WINDOW
        stmt = (
            select(Threat)
            .where(
                Threat.organization_id == detection.organization_id,
                Threat.threat_type == detection.detection_type,
                Threat.status == ThreatStatus.active,
                Threat.last_seen_at >= window_start,
            )
            .order_by(Threat.last_seen_at.desc())
            .limit(1)
        )
        if detection.site_id is not None:
            stmt = stmt.where(Threat.site_id == detection.site_id)
        existing = (await self.db.execute(stmt)).scalar_one_or_none()

        now = _now()
        if existing is not None:
            existing.detection_count += 1
            existing.last_seen_at = now
            existing.score = max(existing.score, score)
            existing.risk_level = RiskEngine.level(existing.score)
            await self.db.flush()
            return existing

        threat = Threat(
            id=uuid.uuid4(), organization_id=detection.organization_id,
            title=f"{detection.detection_type.value.replace('_', ' ').title()} detected",
            threat_type=detection.detection_type, site_id=detection.site_id,
            zone_id=detection.zone_id, score=score, risk_level=RiskEngine.level(score),
            status=ThreatStatus.active, detection_count=1,
            first_seen_at=now, last_seen_at=now,
        )
        self.db.add(threat)
        await self.db.flush()
        await self._audit("open", str(threat.id), None, {"score": score})
        return threat

    async def set_status(self, threat_id: uuid.UUID, status: ThreatStatus, *,
                         actor_id: uuid.UUID | None = None) -> Threat:
        threat = await self.get_or_404(threat_id)
        threat.status = status
        await self.db.flush()
        await self._audit(f"status:{status}", str(threat.id), actor_id)
        return threat

    async def escalate_to_incident(self, threat_id: uuid.UUID, *,
                                   actor_id: uuid.UUID | None = None) -> Threat:
        threat = await self.get_or_404(threat_id)
        if threat.incident_id is not None:
            return threat
        incidents = IncidentService(self.db, audit=self.audit)
        incident = await incidents.create(
            title=threat.title,
            description=f"Auto-escalated from threat {threat.id} "
                        f"(risk {threat.risk_level.value}, score {threat.score}).",
            severity=_LEVEL_TO_INCIDENT[threat.risk_level],
            organization_id=threat.organization_id,
            reporter_id=actor_id,
        )
        threat.incident_id = incident.id
        threat.status = ThreatStatus.escalated
        await self.db.flush()
        await self._audit("escalate", str(threat.id), actor_id,
                          {"incident_id": str(incident.id)})
        return threat

    async def active_summary(self, *, organization_id: uuid.UUID | None = None) -> dict[str, int]:
        stmt = select(Threat.risk_level, func.count()).where(
            Threat.status.in_([ThreatStatus.active, ThreatStatus.monitoring])
        ).group_by(Threat.risk_level)
        if organization_id is not None:
            stmt = stmt.where(Threat.organization_id == organization_id)
        rows = (await self.db.execute(stmt)).all()
        out = {lvl.value: 0 for lvl in ThreatLevel}
        for level, count in rows:
            out[level.value if hasattr(level, "value") else str(level)] = int(count)
        out["total"] = sum(v for k, v in out.items() if k != "total")
        return out
