"""Security monitoring service — dashboard metrics and alert management."""

from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.asset import Asset
from app.models.audit import AuditLog, SecurityAlert
from app.models.enums import (
    AlertSeverity,
    AlertStatus,
    AuditEventType,
    FileStatus,
    IncidentStatus,
    IntegrityResult,
    VulnStatus,
)
from app.models.file import EncryptedFile, File, IntegrityCheck
from app.models.incident import Incident
from app.models.key import KeyRotation
from app.models.scan import DiscoveryScan
from app.models.vuln import Finding, VulnScan


@dataclass(frozen=True, slots=True)
class DashboardMetrics:
    encrypted_files: int
    total_files: int
    quarantined_files: int
    integrity_violations: int
    failed_decryptions: int
    key_rotations: int
    storage_usage_bytes: int
    open_alerts: int
    critical_alerts: int
    encryption_health_score: float
    # ── SOC-wide metrics ────────────────────────────────────────
    total_assets: int
    assets_by_criticality: dict[str, int]
    open_vulnerabilities: int
    vulns_by_severity: dict[str, int]
    open_incidents: int
    discovery_scans: int
    vuln_scans: int
    recent_events: list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class MonitoringService:
    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    async def _count(self, stmt) -> int:  # noqa: ANN001
        return int((await self.db.execute(stmt)).scalar_one() or 0)

    async def dashboard(self) -> DashboardMetrics:
        encrypted_files = await self._count(select(func.count()).select_from(EncryptedFile))
        total_files = await self._count(select(func.count()).select_from(File))
        quarantined = await self._count(
            select(func.count()).select_from(File).where(File.status == FileStatus.quarantined)
        )
        integrity_violations = await self._count(
            select(func.count())
            .select_from(IntegrityCheck)
            .where(IntegrityCheck.result == IntegrityResult.failed)
        )
        failed_decryptions = await self._count(
            select(func.count())
            .select_from(AuditLog)
            .where(AuditLog.event_type == AuditEventType.decrypt_failed)
        )
        key_rotations = await self._count(select(func.count()).select_from(KeyRotation))
        storage_usage = await self._count(
            select(func.coalesce(func.sum(EncryptedFile.ciphertext_size), 0))
        )
        open_alerts = await self._count(
            select(func.count())
            .select_from(SecurityAlert)
            .where(SecurityAlert.status == AlertStatus.open)
        )
        critical_alerts = await self._count(
            select(func.count())
            .select_from(SecurityAlert)
            .where(
                SecurityAlert.status == AlertStatus.open,
                SecurityAlert.severity == AlertSeverity.critical,
            )
        )

        health = self._health_score(
            critical_alerts=critical_alerts,
            open_alerts=open_alerts,
            quarantined=quarantined,
            integrity_violations=integrity_violations,
        )

        # ── SOC-wide metrics ────────────────────────────────────
        total_assets = await self._count(select(func.count()).select_from(Asset))
        assets_by_criticality = await self._group_counts(Asset.criticality)
        open_vulnerabilities = await self._count(
            select(func.count()).select_from(Finding).where(Finding.status == VulnStatus.open)
        )
        vulns_by_severity = await self._group_counts(
            Finding.severity, where=Finding.status == VulnStatus.open
        )
        open_incidents = await self._count(
            select(func.count()).select_from(Incident).where(
                Incident.status.in_(
                    [IncidentStatus.open, IncidentStatus.investigating, IncidentStatus.contained]
                )
            )
        )
        discovery_scans = await self._count(select(func.count()).select_from(DiscoveryScan))
        vuln_scans = await self._count(select(func.count()).select_from(VulnScan))

        recent_rows = (
            await self.db.execute(
                select(AuditLog).order_by(AuditLog.seq.desc()).limit(10)
            )
        ).scalars().all()
        recent_events = [
            {
                "seq": e.seq,
                "event_type": str(e.event_type),
                "outcome": str(e.outcome),
                "actor": e.actor_label,
                "action": e.action,
                "resource": e.resource_id,
                "at": e.created_at.isoformat() if e.created_at else None,
            }
            for e in recent_rows
        ]

        return DashboardMetrics(
            encrypted_files=encrypted_files,
            total_files=total_files,
            quarantined_files=quarantined,
            integrity_violations=integrity_violations,
            failed_decryptions=failed_decryptions,
            key_rotations=key_rotations,
            storage_usage_bytes=storage_usage,
            open_alerts=open_alerts,
            critical_alerts=critical_alerts,
            encryption_health_score=health,
            total_assets=total_assets,
            assets_by_criticality=assets_by_criticality,
            open_vulnerabilities=open_vulnerabilities,
            vulns_by_severity=vulns_by_severity,
            open_incidents=open_incidents,
            discovery_scans=discovery_scans,
            vuln_scans=vuln_scans,
            recent_events=recent_events,
        )

    async def _group_counts(self, column, *, where=None) -> dict[str, int]:  # noqa: ANN001
        stmt = select(column, func.count()).group_by(column)
        if where is not None:
            stmt = stmt.where(where)
        rows = (await self.db.execute(stmt)).all()
        return {getattr(k, "value", str(k)): int(v) for k, v in rows}

    @staticmethod
    def _health_score(
        *, critical_alerts: int, open_alerts: int, quarantined: int, integrity_violations: int
    ) -> float:
        """100 = healthy. Penalize open criticals, quarantines, and violations."""
        penalty = 25 * critical_alerts + 5 * open_alerts + 15 * quarantined + 10 * integrity_violations
        return float(max(0, 100 - penalty))

    # ── Alert management ────────────────────────────────────────
    async def list_alerts(
        self, *, status: AlertStatus | None = None, limit: int = 50
    ) -> list[SecurityAlert]:
        stmt = select(SecurityAlert).order_by(SecurityAlert.created_at.desc()).limit(limit)
        if status is not None:
            stmt = stmt.where(SecurityAlert.status == status)
        return list((await self.db.execute(stmt)).scalars().all())

    async def acknowledge_alert(
        self, alert_id: uuid.UUID, *, actor_id: uuid.UUID
    ) -> SecurityAlert | None:
        alert = (
            await self.db.execute(select(SecurityAlert).where(SecurityAlert.id == alert_id))
        ).scalar_one_or_none()
        if alert is None:
            return None
        alert.status = AlertStatus.acknowledged
        alert.acknowledged_by = actor_id
        alert.acknowledged_at = datetime.now(UTC)
        await self.db.flush()
        return alert

    async def resolve_alert(
        self, alert_id: uuid.UUID, *, actor_id: uuid.UUID, false_positive: bool = False
    ) -> SecurityAlert | None:
        alert = (
            await self.db.execute(select(SecurityAlert).where(SecurityAlert.id == alert_id))
        ).scalar_one_or_none()
        if alert is None:
            return None
        alert.status = AlertStatus.false_positive if false_positive else AlertStatus.resolved
        alert.resolved_at = datetime.now(UTC)
        if alert.acknowledged_by is None:
            alert.acknowledged_by = actor_id
        await self.db.flush()
        return alert
