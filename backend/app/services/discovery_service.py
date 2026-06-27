"""Network Discovery service — schedule and run safe port-scan jobs.

Validates and caps targets, runs the pluggable scanner, records discovered hosts
(with encrypted IP/hostname), and optionally registers/refreshes them as Assets.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import AuditEventType, AuditOutcome, ScanStatus
from app.models.scan import DiscoveredHost, DiscoveryScan
from app.services.asset_service import AssetService
from app.services.audit_service import AuditService
from app.services.exceptions import NotFoundError, ValidationError
from app.services.scanning import (
    DEFAULT_PORTS,
    AsyncTcpScanner,
    PortScanner,
    TargetExpansionError,
    expand_targets,
)

_MAX_PORTS = 1000


class DiscoveryService:
    def __init__(
        self,
        db: AsyncSession,
        *,
        scanner: PortScanner | None = None,
        audit: AuditService | None = None,
        asset_service: AssetService | None = None,
        max_hosts: int = 1024,
    ) -> None:
        self.db = db
        self.scanner = scanner or AsyncTcpScanner()
        self.audit = audit or AuditService(db)
        self.assets = asset_service or AssetService(db, audit=self.audit)
        self.max_hosts = max_hosts

    async def create_scan(
        self,
        *,
        name: str,
        targets: list[str],
        ports: list[int] | None = None,
        actor_id: uuid.UUID | None = None,
    ) -> DiscoveryScan:
        ports = sorted(set(ports or DEFAULT_PORTS))
        if len(ports) > _MAX_PORTS:
            raise ValidationError(f"Too many ports (max {_MAX_PORTS})")
        if any(not (0 < p < 65536) for p in ports):
            raise ValidationError("Ports must be in 1..65535")
        # Validate/cap targets up-front (raises if the scope is too broad).
        try:
            expand_targets(targets, max_hosts=self.max_hosts)
        except TargetExpansionError as exc:
            raise ValidationError(str(exc)) from exc

        scan = DiscoveryScan(
            id=uuid.uuid4(), name=name, targets=targets, ports=ports,
            status=ScanStatus.pending, created_by=actor_id,
        )
        self.db.add(scan)
        await self.db.flush()
        return scan

    async def get_scan(self, scan_id: uuid.UUID) -> DiscoveryScan | None:
        return (
            await self.db.execute(select(DiscoveryScan).where(DiscoveryScan.id == scan_id))
        ).scalar_one_or_none()

    async def list_scans(self, *, limit: int = 50) -> list[DiscoveryScan]:
        return list(
            (
                await self.db.execute(
                    select(DiscoveryScan).order_by(DiscoveryScan.created_at.desc()).limit(limit)
                )
            ).scalars().all()
        )

    async def list_hosts(self, scan_id: uuid.UUID) -> list[DiscoveredHost]:
        return list(
            (
                await self.db.execute(
                    select(DiscoveredHost).where(DiscoveredHost.scan_id == scan_id)
                )
            ).scalars().all()
        )

    async def run_scan(
        self, scan_id: uuid.UUID, *, register_assets: bool = True
    ) -> DiscoveryScan:
        scan = await self.get_scan(scan_id)
        if scan is None:
            raise NotFoundError("Scan not found")

        scan.status = ScanStatus.running
        scan.started_at = datetime.now(UTC)
        await self.db.flush()
        await self.audit.record(
            event_type=AuditEventType.scan_started, outcome=AuditOutcome.success,
            actor_id=scan.created_by, resource_type="discovery_scan",
            resource_id=str(scan.id), action="run", detail={"name": scan.name},
        )

        try:
            hosts = expand_targets(scan.targets, max_hosts=self.max_hosts)
            results = await self.scanner.scan(hosts, scan.ports)
        except Exception as exc:  # noqa: BLE001
            scan.status = ScanStatus.failed
            scan.finished_at = datetime.now(UTC)
            scan.summary = {"error": str(exc)}
            await self.db.flush()
            await self.audit.record(
                event_type=AuditEventType.scan_completed, outcome=AuditOutcome.failure,
                actor_id=scan.created_by, resource_type="discovery_scan",
                resource_id=str(scan.id), action="run", detail={"error": str(exc)},
            )
            raise

        now = datetime.now(UTC)
        alive = 0
        for r in results:
            asset_id: uuid.UUID | None = None
            if register_assets and r.is_alive:
                asset, _ = await self.assets.upsert_from_discovery(
                    ip_address=r.ip, hostname=r.hostname, open_ports=r.open_ports
                )
                asset_id = asset.id
            if r.is_alive:
                alive += 1
            self.db.add(
                DiscoveredHost(
                    id=uuid.uuid4(), scan_id=scan.id, ip_address=r.ip, hostname=r.hostname,
                    open_ports=r.open_ports, latency_ms=r.latency_ms, asset_id=asset_id,
                    created_at=now,
                )
            )

        scan.status = ScanStatus.completed
        scan.finished_at = now
        scan.hosts_found = alive
        scan.summary = {"hosts_scanned": len(results), "hosts_alive": alive}
        await self.db.flush()
        await self.audit.record(
            event_type=AuditEventType.scan_completed, outcome=AuditOutcome.success,
            actor_id=scan.created_by, resource_type="discovery_scan",
            resource_id=str(scan.id), action="run",
            detail={"hosts_scanned": len(results), "hosts_alive": alive},
        )
        return scan
