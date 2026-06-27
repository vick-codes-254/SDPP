"""End-to-end SMP API tests (asset -> vuln scan -> alerts -> incident)."""

from __future__ import annotations

import pytest
from httpx import AsyncClient

from tests.integration.api_helpers import API
from tests.integration.api_helpers import auth as _auth
from tests.integration.api_helpers import token as _token

pytestmark = pytest.mark.integration


class TestAssetApi:
    async def test_create_and_list_asset(self, client: AsyncClient) -> None:
        t = await _token(client)
        r = await client.post(
            f"{API}/assets", headers=_auth(t),
            json={"name": "web-01", "asset_type": "server", "ip_address": "10.9.9.9",
                  "criticality": "critical",
                  "software": [{"name": "log4j", "version": "2.14.1"}]},
        )
        assert r.status_code == 201, r.text
        assert r.json()["ip_address"] == "10.9.9.9"
        listing = await client.get(f"{API}/assets", headers=_auth(t))
        assert listing.status_code == 200
        assert any(a["name"] == "web-01" for a in listing.json())


class TestVulnWorkflow:
    async def test_scan_creates_findings_and_alerts(self, client: AsyncClient) -> None:
        t = await _token(client)
        await client.post(
            f"{API}/assets", headers=_auth(t),
            json={"name": "app", "ip_address": "10.9.9.10", "criticality": "critical",
                  "software": [{"name": "log4j", "version": "2.14.1"}]},
        )
        scan = await client.post(
            f"{API}/vulnerabilities/scans", headers=_auth(t), json={"name": "full"}
        )
        scan_id = scan.json()["id"]
        run = await client.post(
            f"{API}/vulnerabilities/scans/{scan_id}/run", headers=_auth(t)
        )
        assert run.status_code == 200
        assert run.json()["summary"]["total_findings"] >= 1

        findings = await client.get(
            f"{API}/vulnerabilities/findings?scan_id={scan_id}", headers=_auth(t)
        )
        assert any(f["cve_id"] == "CVE-2021-44228" for f in findings.json())

        # Alert engine ran automatically -> a vulnerability alert exists.
        alerts = await client.get(f"{API}/alerts", headers=_auth(t))
        assert any(a["alert_type"] == "vulnerability" for a in alerts.json())


class TestDiscoveryApi:
    async def test_create_scan_validates_scope(self, client: AsyncClient) -> None:
        t = await _token(client)
        ok = await client.post(
            f"{API}/discovery/scans", headers=_auth(t),
            json={"name": "lab", "targets": ["10.0.0.1"], "ports": [80, 443]},
        )
        assert ok.status_code == 201
        # Over-broad scope rejected by the safety cap.
        bad = await client.post(
            f"{API}/discovery/scans", headers=_auth(t),
            json={"name": "huge", "targets": ["10.0.0.0/8"], "ports": [80]},
        )
        assert bad.status_code == 422


class TestIncidentAndDashboard:
    async def test_incident_and_dashboard(self, client: AsyncClient) -> None:
        t = await _token(client)
        inc = await client.post(
            f"{API}/incidents", headers=_auth(t),
            json={"title": "Investigate exfil", "severity": "high"},
        )
        assert inc.status_code == 201
        inc_id = inc.json()["id"]
        await client.post(
            f"{API}/incidents/{inc_id}/status", headers=_auth(t),
            json={"status": "investigating"},
        )
        tl = await client.get(f"{API}/incidents/{inc_id}/timeline", headers=_auth(t))
        assert len(tl.json()) >= 2  # created + status change

        dash = await client.get(f"{API}/security-dashboard", headers=_auth(t))
        body = dash.json()
        assert "total_assets" in body
        assert "open_incidents" in body and body["open_incidents"] >= 1


class TestUserManagementApi:
    async def test_list_users(self, client: AsyncClient) -> None:
        t = await _token(client)
        r = await client.get(f"{API}/users", headers=_auth(t))
        assert r.status_code == 200
        assert any(u["username"] == "admin" for u in r.json())
