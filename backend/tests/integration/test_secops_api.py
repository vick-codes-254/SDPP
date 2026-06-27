"""SecOps tests: notifications delivery, emergency lockdown, evidence custody, SLA."""

from __future__ import annotations

import pytest
from httpx import AsyncClient

from tests.integration.api_helpers import API
from tests.integration.api_helpers import auth as _auth
from tests.integration.api_helpers import token as _token

pytestmark = pytest.mark.integration


async def _org(client: AsyncClient, t: str) -> str:
    r = await client.get(f"{API}/organizations", headers=_auth(t))
    return next(o for o in r.json() if o["slug"] == "demo")["id"]


class TestNotifications:
    async def test_channel_and_dispatch(self, client: AsyncClient) -> None:
        t = await _token(client)
        org = await _org(client, t)
        ch = await client.post(
            f"{API}/notifications/channels", headers=_auth(t),
            json={"organization_id": org, "name": "Ops email", "channel": "email",
                  "target": "soc@demo.test", "min_severity": "low"},
        )
        assert ch.status_code == 201, ch.text

        d = await client.post(
            f"{API}/notifications/dispatch", headers=_auth(t),
            json={"organization_id": org, "channel": "email", "target": "soc@demo.test",
                  "subject": "Test", "body": "hello"},
        )
        assert d.status_code == 201, d.text
        assert d.json()["status"] == "sent"

        stats = await client.get(f"{API}/notifications/stats?organization_id={org}", headers=_auth(t))
        assert stats.json()["sent"] >= 1


class TestEmergency:
    async def test_lockdown_locks_and_resolve_unlocks(self, client: AsyncClient) -> None:
        t = await _token(client)
        org = await _org(client, t)
        site = (await client.post(
            f"{API}/sites", headers=_auth(t),
            json={"organization_id": org, "name": "Lockdown Site"},
        )).json()["id"]
        point = (await client.post(
            f"{API}/access/points", headers=_auth(t),
            json={"organization_id": org, "site_id": site, "name": "Main Door",
                  "is_locked": False},
        )).json()
        assert point["is_locked"] is False

        # An emergency contact so the fan-out has a recipient.
        await client.post(
            f"{API}/emergency/contacts", headers=_auth(t),
            json={"organization_id": org, "name": "Site Manager", "phone": "+254700000000",
                  "channel": "sms"},
        )

        ev = await client.post(
            f"{API}/emergency/trigger", headers=_auth(t),
            json={"organization_id": org, "event_type": "lockdown", "site_id": site,
                  "message": "Drill"},
        )
        assert ev.status_code == 201, ev.text
        assert ev.json()["notified_count"] >= 1

        points = await client.get(
            f"{API}/access/points?organization_id={org}&site_id={site}", headers=_auth(t)
        )
        assert all(p["is_locked"] for p in points.json())  # locked down

        res = await client.post(
            f"{API}/emergency/events/{ev.json()['id']}/resolve", headers=_auth(t)
        )
        assert res.status_code == 200
        points2 = await client.get(
            f"{API}/access/points?organization_id={org}&site_id={site}", headers=_auth(t)
        )
        assert all(not p["is_locked"] for p in points2.json())  # unlocked


class TestEvidenceCustody:
    async def test_register_and_custody_chain(self, client: AsyncClient) -> None:
        t = await _token(client)
        org = await _org(client, t)
        ev = await client.post(
            f"{API}/evidence", headers=_auth(t),
            json={"organization_id": org, "title": "Lobby footage 22:00",
                  "evidence_type": "video", "sha256": "a" * 64, "source": "Camera 3"},
        )
        assert ev.status_code == 201, ev.text
        eid = ev.json()["id"]

        chain = await client.get(f"{API}/evidence/{eid}/custody", headers=_auth(t))
        assert len(chain.json()) == 1 and chain.json()[0]["action"] == "collected"

        t2 = await client.post(
            f"{API}/evidence/{eid}/custody", headers=_auth(t),
            json={"action": "transferred", "from_party": "SOC", "to_party": "Legal"},
        )
        assert t2.status_code == 201
        chain2 = await client.get(f"{API}/evidence/{eid}/custody", headers=_auth(t))
        assert len(chain2.json()) == 2


class TestIncidentSla:
    async def test_sla_and_acknowledge(self, client: AsyncClient) -> None:
        t = await _token(client)
        inc = await client.post(
            f"{API}/incidents", headers=_auth(t),
            json={"title": "Critical breach", "severity": "critical"},
        )
        assert inc.status_code == 201
        assert inc.json()["sla_due_at"] is not None  # SLA computed on create
        iid = inc.json()["id"]

        ack = await client.post(f"{API}/incidents/{iid}/acknowledge", headers=_auth(t))
        assert ack.status_code == 200
        assert ack.json()["acknowledged_at"] is not None
