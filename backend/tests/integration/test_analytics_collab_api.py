"""Analytics/BI, maps, reports, communication, and workflow-automation tests."""

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


class TestAnalytics:
    async def test_kpis_and_report(self, client: AsyncClient) -> None:
        t = await _token(client)
        org = await _org(client, t)
        kpis = await client.get(f"{API}/analytics/kpis?organization_id={org}", headers=_auth(t))
        assert kpis.status_code == 200
        assert "open_incidents" in kpis.json()

        rep = await client.get(f"{API}/analytics/reports/executive?organization_id={org}", headers=_auth(t))
        assert rep.status_code == 200
        body = rep.json()
        assert body["kind"] == "executive" and "kpis" in body and "response_times" in body

    async def test_map_feed_includes_sites(self, client: AsyncClient) -> None:
        t = await _token(client)
        org = await _org(client, t)
        await client.post(
            f"{API}/sites", headers=_auth(t),
            json={"organization_id": org, "name": "Geo Site", "latitude": -1.29, "longitude": 36.82},
        )
        feed = await client.get(f"{API}/analytics/map?organization_id={org}", headers=_auth(t))
        assert any(s["name"] == "Geo Site" for s in feed.json()["sites"])


class TestComms:
    async def test_announcement_and_chat(self, client: AsyncClient) -> None:
        t = await _token(client)
        org = await _org(client, t)
        a = await client.post(
            f"{API}/comms/announcements", headers=_auth(t),
            json={"organization_id": org, "title": "Shift change", "body": "All hands 6pm"},
        )
        assert a.status_code == 201, a.text

        m = await client.post(
            f"{API}/comms/messages", headers=_auth(t),
            json={"organization_id": org, "room": "general", "body": "Radio check"},
        )
        assert m.status_code == 201
        msgs = await client.get(
            f"{API}/comms/rooms/general/messages?organization_id={org}", headers=_auth(t)
        )
        assert any(x["body"] == "Radio check" for x in msgs.json())


class TestWorkflow:
    async def test_rule_create_and_evaluate_creates_incident(self, client: AsyncClient) -> None:
        t = await _token(client)
        org = await _org(client, t)
        rule = await client.post(
            f"{API}/workflows/rules", headers=_auth(t),
            json={"organization_id": org, "name": "Critical threat -> incident",
                  "trigger": "threat", "condition": {"risk_level": "critical"},
                  "action": "create_incident",
                  "action_config": {"title": "Auto: critical threat"}},
        )
        assert rule.status_code == 201, rule.text

        # Matching event fires the rule.
        ev = await client.post(
            f"{API}/workflows/evaluate", headers=_auth(t),
            json={"organization_id": org, "trigger": "threat",
                  "context": {"risk_level": "critical", "severity": "critical"}},
        )
        assert ev.status_code == 200, ev.text
        executed = ev.json()["executed"]
        assert len(executed) == 1 and executed[0]["result"].startswith("incident:")

        # Non-matching event does nothing.
        ev2 = await client.post(
            f"{API}/workflows/evaluate", headers=_auth(t),
            json={"organization_id": org, "trigger": "threat",
                  "context": {"risk_level": "low"}},
        )
        assert ev2.json()["executed"] == []
