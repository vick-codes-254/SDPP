"""Asset Management service tests."""

from __future__ import annotations

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import AssetCriticality, AssetStatus, AssetType, DiscoverySource
from app.services.asset_service import AssetData, AssetService, SoftwareEntry

pytestmark = pytest.mark.integration


def _data(**over) -> AssetData:
    base = dict(
        name="web-01", asset_type=AssetType.server,
        hostname="web-01.corp.local", ip_address="10.0.0.5", mac_address="aa:bb:cc:dd:ee:ff",
        operating_system="Ubuntu", os_version="22.04", criticality=AssetCriticality.high,
        software=[SoftwareEntry("openssl", "3.0.2"), SoftwareEntry("nginx", "1.18.0")],
    )
    base.update(over)
    return AssetData(**base)


class TestCreateAndEncrypt:
    async def test_create_and_software(self, async_session: AsyncSession) -> None:
        svc = AssetService(async_session)
        asset = await svc.create(_data())
        assert asset.ip_address == "10.0.0.5"
        assert {s.name for s in asset.software} == {"openssl", "nginx"}

    async def test_ip_and_hostname_encrypted_at_rest(self, async_session: AsyncSession) -> None:
        svc = AssetService(async_session)
        await svc.create(_data())
        row = (await async_session.execute(text("SELECT ip_address, hostname FROM assets"))).first()
        assert "10.0.0.5" not in row[0]
        assert "web-01.corp.local" not in row[1]


class TestLookup:
    async def test_find_by_ip_blind_index(self, async_session: AsyncSession) -> None:
        svc = AssetService(async_session)
        created = await svc.create(_data())
        found = await svc.find_by_ip("10.0.0.5")
        assert found is not None and found.id == created.id

    async def test_list_filters(self, async_session: AsyncSession) -> None:
        svc = AssetService(async_session)
        await svc.create(_data(name="db-01", ip_address="10.0.0.6", criticality=AssetCriticality.critical))
        await svc.create(_data(name="ws-01", ip_address="10.0.0.7", criticality=AssetCriticality.low))
        crit = await svc.list(criticality=AssetCriticality.critical)
        assert [a.name for a in crit] == ["db-01"]
        search = await svc.list(search="ws")
        assert [a.name for a in search] == ["ws-01"]


class TestUpdateDelete:
    async def test_update_reindexes_ip(self, async_session: AsyncSession) -> None:
        svc = AssetService(async_session)
        a = await svc.create(_data())
        await svc.update(a.id, {"ip_address": "10.0.0.99", "criticality": AssetCriticality.critical})
        assert await svc.find_by_ip("10.0.0.99") is not None
        assert await svc.find_by_ip("10.0.0.5") is None

    async def test_delete(self, async_session: AsyncSession) -> None:
        svc = AssetService(async_session)
        a = await svc.create(_data())
        await svc.delete(a.id)
        assert await svc.get(a.id) is None


class TestDiscoveryUpsert:
    async def test_creates_then_refreshes(self, async_session: AsyncSession) -> None:
        svc = AssetService(async_session)
        asset, created = await svc.upsert_from_discovery(
            ip_address="192.168.1.10", hostname="printer", open_ports=[80, 443]
        )
        assert created is True
        assert asset.discovered_by is DiscoverySource.network_discovery
        assert asset.last_seen_at is not None

        # Second sighting of the same IP refreshes, does not duplicate.
        again, created2 = await svc.upsert_from_discovery(
            ip_address="192.168.1.10", open_ports=[22]
        )
        assert created2 is False
        assert again.id == asset.id
        assert "port:22" in again.tags
        assert (await svc.list(status=AssetStatus.active)) != []
