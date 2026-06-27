"""Vulnerability scanning service.

Scans assets by matching their software inventory against a CVE source, records
findings with severity/CVSS, and summarizes counts. Findings can later be triaged
(confirmed / false-positive / remediated).
"""

from __future__ import annotations

import uuid
from collections import Counter
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.enums import (
    AuditEventType,
    AuditOutcome,
    ScanStatus,
    VulnSeverity,
    VulnStatus,
)
from app.models.asset import Asset
from app.models.vuln import Finding, VulnScan
from app.services.audit_service import AuditService
from app.services.exceptions import NotFoundError
from app.services.vuln import BundledCveSource, VulnSource


class VulnService:
    def __init__(
        self,
        db: AsyncSession,
        *,
        source: VulnSource | None = None,
        audit: AuditService | None = None,
    ) -> None:
        self.db = db
        self.source = source or BundledCveSource()
        self.audit = audit or AuditService(db)

    async def create_scan(
        self,
        *,
        name: str,
        asset_ids: list[uuid.UUID] | None = None,
        actor_id: uuid.UUID | None = None,
    ) -> VulnScan:
        scan = VulnScan(
            id=uuid.uuid4(), name=name,
            scope=[str(a) for a in asset_ids] if asset_ids else None,
            status=ScanStatus.pending, created_by=actor_id,
        )
        self.db.add(scan)
        await self.db.flush()
        return scan

    async def get_scan(self, scan_id: uuid.UUID) -> VulnScan | None:
        return (
            await self.db.execute(select(VulnScan).where(VulnScan.id == scan_id))
        ).scalar_one_or_none()

    async def list_scans(self, *, limit: int = 50) -> list[VulnScan]:
        return list(
            (
                await self.db.execute(
                    select(VulnScan).order_by(VulnScan.created_at.desc()).limit(limit)
                )
            ).scalars().all()
        )

    async def list_findings(
        self,
        *,
        scan_id: uuid.UUID | None = None,
        asset_id: uuid.UUID | None = None,
        status: VulnStatus | None = None,
        limit: int = 200,
    ) -> list[Finding]:
        stmt = select(Finding).order_by(Finding.cvss_score.desc().nullslast())
        if scan_id:
            stmt = stmt.where(Finding.scan_id == scan_id)
        if asset_id:
            stmt = stmt.where(Finding.asset_id == asset_id)
        if status:
            stmt = stmt.where(Finding.status == status)
        return list((await self.db.execute(stmt.limit(limit))).scalars().all())

    async def _assets_in_scope(self, scan: VulnScan) -> list[Asset]:
        stmt = select(Asset).options(selectinload(Asset.software))
        if scan.scope:
            ids = [uuid.UUID(s) for s in scan.scope]
            stmt = stmt.where(Asset.id.in_(ids))
        return list((await self.db.execute(stmt)).scalars().all())

    async def run_scan(self, scan_id: uuid.UUID) -> VulnScan:
        scan = await self.get_scan(scan_id)
        if scan is None:
            raise NotFoundError("Scan not found")

        scan.status = ScanStatus.running
        scan.started_at = datetime.now(UTC)
        await self.db.flush()

        severity_counts: Counter[str] = Counter()
        total = 0
        for asset in await self._assets_in_scope(scan):
            for sw in asset.software:
                if not sw.version:
                    continue
                for match in self.source.lookup(sw.name, sw.version):
                    self.db.add(
                        Finding(
                            id=uuid.uuid4(), scan_id=scan.id, asset_id=asset.id,
                            cve_id=match.cve_id, title=match.title, description=match.description,
                            severity=match.severity, cvss_score=match.cvss_score,
                            affected_software=sw.name, affected_version=match.affected_version,
                            fixed_version=match.fixed_version, remediation=match.remediation,
                            status=VulnStatus.open, references=match.references,
                        )
                    )
                    severity_counts[match.severity.value] += 1
                    total += 1

        scan.status = ScanStatus.completed
        scan.finished_at = datetime.now(UTC)
        scan.summary = {
            "total_findings": total,
            "by_severity": {s.value: severity_counts.get(s.value, 0) for s in VulnSeverity},
        }
        await self.db.flush()
        await self.audit.record(
            event_type=AuditEventType.scan_completed, outcome=AuditOutcome.success,
            actor_id=scan.created_by, resource_type="vuln_scan", resource_id=str(scan.id),
            action="run", detail=scan.summary,
        )
        return scan

    async def set_finding_status(
        self, finding_id: uuid.UUID, status: VulnStatus, *, actor_id: uuid.UUID | None = None
    ) -> Finding:
        finding = (
            await self.db.execute(select(Finding).where(Finding.id == finding_id))
        ).scalar_one_or_none()
        if finding is None:
            raise NotFoundError("Finding not found")
        finding.status = status
        await self.db.flush()
        return finding
