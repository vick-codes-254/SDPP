"""End-to-end tests for tenancy & physical-security modules.

Covers: org/site hierarchy, camera registration + heartbeat health, guards,
visitor blacklist enforcement (blind index), and vehicle watchlist + ANPR flagging.
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient

from tests.integration.api_helpers import API
from tests.integration.api_helpers import auth as _auth
from tests.integration.api_helpers import token as _token

pytestmark = pytest.mark.integration


async def _demo_org_id(client: AsyncClient, t: str) -> str:
    r = await client.get(f"{API}/organizations", headers=_auth(t))
    assert r.status_code == 200, r.text
    orgs = r.json()
    demo = next(o for o in orgs if o["slug"] == "demo")
    return demo["id"]


async def _make_site(client: AsyncClient, t: str, org_id: str) -> str:
    r = await client.post(
        f"{API}/sites", headers=_auth(t),
        json={"organization_id": org_id, "name": "Test Site", "site_type": "office"},
    )
    assert r.status_code == 201, r.text
    return r.json()["id"]


class TestTenancy:
    async def test_demo_org_seeded_and_site_crud(self, client: AsyncClient) -> None:
        t = await _token(client)
        org_id = await _demo_org_id(client, t)
        site_id = await _make_site(client, t, org_id)

        listing = await client.get(f"{API}/sites?organization_id={org_id}", headers=_auth(t))
        assert listing.status_code == 200
        assert any(s["id"] == site_id for s in listing.json())

        # Zone under the site.
        z = await client.post(
            f"{API}/sites/zones", headers=_auth(t),
            json={"organization_id": org_id, "site_id": site_id,
                  "name": "Server Room", "zone_type": "server_room", "is_restricted": True},
        )
        assert z.status_code == 201, z.text
        assert z.json()["is_restricted"] is True


class TestCameras:
    async def test_register_heartbeat_and_health(self, client: AsyncClient) -> None:
        t = await _token(client)
        org_id = await _demo_org_id(client, t)
        site_id = await _make_site(client, t, org_id)

        cam = await client.post(
            f"{API}/cameras", headers=_auth(t),
            json={"organization_id": org_id, "site_id": site_id, "name": "Lobby Cam",
                  "rtsp_url": "rtsp://10.0.0.5/stream", "manufacturer": "Hikvision"},
        )
        assert cam.status_code == 201, cam.text
        cam_id = cam.json()["id"]
        assert cam.json()["status"] == "offline"
        # RTSP credential is never returned in the response.
        assert "rtsp_url" not in cam.json()

        hb = await client.post(
            f"{API}/cameras/{cam_id}/heartbeat", headers=_auth(t),
            json={"online": True, "recording": True},
        )
        assert hb.status_code == 200
        assert hb.json()["status"] == "online"

        health = await client.get(
            f"{API}/cameras/health?organization_id={org_id}", headers=_auth(t)
        )
        body = health.json()
        assert body["total"] >= 1 and body["online"] >= 1 and body["recording"] >= 1


class TestVisitorBlacklist:
    async def test_blacklisted_visitor_rejected(self, client: AsyncClient) -> None:
        t = await _token(client)
        org_id = await _demo_org_id(client, t)

        v = await client.post(
            f"{API}/visitors", headers=_auth(t),
            json={"organization_id": org_id, "full_name": "Mallory Banned"},
        )
        assert v.status_code == 201, v.text
        vid = v.json()["id"]

        # Blacklist them.
        b = await client.post(
            f"{API}/visitors/{vid}/status", headers=_auth(t),
            json={"status": "blacklisted"},
        )
        assert b.status_code == 200

        # Re-registration of the same identity is blocked (blind-index match).
        again = await client.post(
            f"{API}/visitors", headers=_auth(t),
            json={"organization_id": org_id, "full_name": "Mallory Banned"},
        )
        assert again.status_code == 409, again.text


class TestVehicleAnpr:
    async def test_watchlisted_plate_flagged(self, client: AsyncClient) -> None:
        t = await _token(client)
        org_id = await _demo_org_id(client, t)

        veh = await client.post(
            f"{API}/vehicles", headers=_auth(t),
            json={"organization_id": org_id, "plate": "KAA 123A",
                  "is_watchlisted": True, "watch_reason": "stolen", "status": "watchlisted"},
        )
        assert veh.status_code == 201, veh.text

        # ANPR reads the same plate (different spacing/case) -> matched & flagged.
        anpr = await client.post(
            f"{API}/vehicles/anpr", headers=_auth(t),
            json={"organization_id": org_id, "plate": "kaa123a", "direction": "entry"},
        )
        assert anpr.status_code == 201, anpr.text
        result = anpr.json()
        assert result["flagged"] is True
        assert result["matched_vehicle_id"] is not None
        assert result["event"]["authorized"] is False
