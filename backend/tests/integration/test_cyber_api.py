"""Cybersecurity monitoring tests: brute force, impossible travel, new device, SOC."""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient

from tests.integration.api_helpers import API
from tests.integration.api_helpers import auth as _auth
from tests.integration.api_helpers import token as _token

pytestmark = pytest.mark.integration


class TestBruteForce:
    async def test_repeated_failures_trigger_brute_force(self, client: AsyncClient) -> None:
        t = await _token(client)
        triggered = None
        for _ in range(5):
            r = await client.post(
                f"{API}/cyber/login-events", headers=_auth(t),
                json={"username": "victim", "success": False, "ip_address": "203.0.113.5"},
            )
            assert r.status_code == 201, r.text
            triggered = r.json()["events_triggered"]
        # 5th failure crosses the threshold.
        assert any(e["event_type"] == "brute_force" for e in triggered)

        events = await client.get(f"{API}/cyber/events?event_type=brute_force", headers=_auth(t))
        assert len(events.json()) >= 1

        # The brute-force event raised a SOC alert too.
        alerts = await client.get(f"{API}/alerts", headers=_auth(t))
        assert any(a["alert_type"] == "brute_force" for a in alerts.json())


class TestImpossibleTravel:
    async def test_far_apart_logins_flagged(self, client: AsyncClient) -> None:
        t = await _token(client)
        uid = str(uuid.uuid4())
        # Nairobi
        await client.post(
            f"{API}/cyber/login-events", headers=_auth(t),
            json={"username": "ceo", "success": True, "user_id": uid,
                  "latitude": -1.286389, "longitude": 36.817223,
                  "device_fingerprint": "dev-A", "country": "KE"},
        )
        # London, minutes later -> impossible travel
        r = await client.post(
            f"{API}/cyber/login-events", headers=_auth(t),
            json={"username": "ceo", "success": True, "user_id": uid,
                  "latitude": 51.5072, "longitude": -0.1276,
                  "device_fingerprint": "dev-A", "country": "GB"},
        )
        types = {e["event_type"] for e in r.json()["events_triggered"]}
        assert "impossible_travel" in types


class TestNewDevice:
    async def test_first_device_flagged_then_known(self, client: AsyncClient) -> None:
        t = await _token(client)
        uid = str(uuid.uuid4())
        first = await client.post(
            f"{API}/cyber/login-events", headers=_auth(t),
            json={"username": "u1", "success": True, "user_id": uid,
                  "device_fingerprint": "fp-123", "country": "KE"},
        )
        assert any(e["event_type"] == "new_device" for e in first.json()["events_triggered"])

        second = await client.post(
            f"{API}/cyber/login-events", headers=_auth(t),
            json={"username": "u1", "success": True, "user_id": uid,
                  "device_fingerprint": "fp-123", "country": "KE"},
        )
        assert not any(e["event_type"] == "new_device" for e in second.json()["events_triggered"])

        devices = await client.get(f"{API}/cyber/devices?user_id={uid}", headers=_auth(t))
        assert len(devices.json()) == 1


class TestSoc:
    async def test_soc_summary(self, client: AsyncClient) -> None:
        t = await _token(client)
        await client.post(
            f"{API}/cyber/login-events", headers=_auth(t),
            json={"username": "x", "success": False, "ip_address": "198.51.100.7"},
        )
        soc = await client.get(f"{API}/cyber/soc", headers=_auth(t))
        body = soc.json()
        assert "by_type" in body and body["total_events"] >= 1
