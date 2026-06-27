"""Network Discovery service tests (scanner injected — no real network I/O)."""

from __future__ import annotations

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import ScanStatus
from app.services.asset_service import AssetService
from app.services.discovery_service import DiscoveryService
from app.services.exceptions import ValidationError
from app.services.scanning import HostResult

pytestmark = pytest.mark.integration


class FakeScanner:
    """Deterministic scanner stub returning canned results."""

    def __init__(self, results: list[HostResult]) -> None:
        self._results = results
        self.calls: list[tuple[list[str], list[int]]] = []

    async def scan(self, hosts, ports):  # noqa: ANN001, ANN201
        self.calls.append((hosts, ports))
        return self._results


def _svc(session: AsyncSession, results: list[HostResult]) -> DiscoveryService:
    return DiscoveryService(session, scanner=FakeScanner(results))


class TestScanLifecycle:
    async def test_create_and_run(self, async_session: AsyncSession) -> None:
        results = [
            HostResult(ip="10.0.0.5", hostname="web", open_ports=[80, 443], latency_ms=12.3),
            HostResult(ip="10.0.0.6", open_ports=[], latency_ms=None),  # no open ports
        ]
        svc = _svc(async_session, results)
        scan = await svc.create_scan(name="lab", targets=["10.0.0.5", "10.0.0.6"], ports=[80, 443])
        assert scan.status is ScanStatus.pending

        done = await svc.run_scan(scan.id)
        assert done.status is ScanStatus.completed
        assert done.hosts_found == 1  # only the host with open ports
        assert done.summary["hosts_scanned"] == 2

        hosts = await svc.list_hosts(scan.id)
        assert len(hosts) == 2

    async def test_discovered_host_ip_encrypted(self, async_session: AsyncSession) -> None:
        svc = _svc(async_session, [HostResult(ip="10.0.0.5", open_ports=[22])])
        scan = await svc.create_scan(name="x", targets=["10.0.0.5"], ports=[22])
        await svc.run_scan(scan.id)
        raw = (await async_session.execute(text("SELECT ip_address FROM discovered_hosts"))).first()[0]
        assert "10.0.0.5" not in raw

    async def test_alive_hosts_registered_as_assets(self, async_session: AsyncSession) -> None:
        svc = _svc(async_session, [HostResult(ip="10.0.0.9", hostname="db", open_ports=[5432])])
        scan = await svc.create_scan(name="x", targets=["10.0.0.9"], ports=[5432])
        await svc.run_scan(scan.id)
        # Asset auto-created from discovery, found by IP blind index.
        asset = await AssetService(async_session).find_by_ip("10.0.0.9")
        assert asset is not None
        assert "port:5432" in asset.tags


class TestSafety:
    async def test_overbroad_target_rejected(self, async_session: AsyncSession) -> None:
        svc = _svc(async_session, [])
        with pytest.raises(ValidationError):
            await svc.create_scan(name="huge", targets=["10.0.0.0/8"], ports=[80])

    async def test_invalid_port_rejected(self, async_session: AsyncSession) -> None:
        svc = _svc(async_session, [])
        with pytest.raises(ValidationError):
            await svc.create_scan(name="bad", targets=["10.0.0.1"], ports=[99999])
