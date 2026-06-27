"""AI detection -> threat correlation -> incident escalation tests."""

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


class TestDetectionPipeline:
    async def test_weapon_detection_opens_critical_threat(self, client: AsyncClient) -> None:
        t = await _token(client)
        org = await _org(client, t)

        r = await client.post(
            f"{API}/detections/ingest", headers=_auth(t),
            json={"organization_id": org, "detection_type": "weapon", "confidence": 0.95},
        )
        assert r.status_code == 201, r.text
        body = r.json()
        assert body["detection"]["severity"] == "critical"
        assert body["threat_id"] is not None

        # Threat shows up in the intelligence center.
        threats = await client.get(
            f"{API}/detections/threats/list?organization_id={org}", headers=_auth(t)
        )
        assert any(th["id"] == body["threat_id"] for th in threats.json())

    async def test_low_risk_detection_no_threat(self, client: AsyncClient) -> None:
        t = await _token(client)
        org = await _org(client, t)
        r = await client.post(
            f"{API}/detections/ingest", headers=_auth(t),
            json={"organization_id": org, "detection_type": "person", "confidence": 0.9},
        )
        assert r.status_code == 201
        assert r.json()["threat_id"] is None  # weight 10 -> info, no threat

    async def test_escalate_threat_to_incident(self, client: AsyncClient) -> None:
        t = await _token(client)
        org = await _org(client, t)
        ing = await client.post(
            f"{API}/detections/ingest", headers=_auth(t),
            json={"organization_id": org, "detection_type": "fire", "confidence": 0.99},
        )
        threat_id = ing.json()["threat_id"]
        assert threat_id is not None

        esc = await client.post(
            f"{API}/detections/threats/{threat_id}/escalate", headers=_auth(t)
        )
        assert esc.status_code == 200, esc.text
        assert esc.json()["status"] == "escalated"
        assert esc.json()["incident_id"] is not None

        # The escalation created a real incident.
        incidents = await client.get(f"{API}/incidents", headers=_auth(t))
        assert any(i["id"] == esc.json()["incident_id"] for i in incidents.json())

    async def test_correlation_groups_repeat_detections(self, client: AsyncClient) -> None:
        t = await _token(client)
        org = await _org(client, t)
        site = (await client.post(
            f"{API}/sites", headers=_auth(t),
            json={"organization_id": org, "name": "Perimeter Site"},
        )).json()["id"]

        ids = set()
        for _ in range(3):
            r = await client.post(
                f"{API}/detections/ingest", headers=_auth(t),
                json={"organization_id": org, "detection_type": "intrusion",
                      "confidence": 0.9, "site_id": site},
            )
            ids.add(r.json()["threat_id"])
        # All three correlate into ONE threat.
        assert len(ids) == 1
