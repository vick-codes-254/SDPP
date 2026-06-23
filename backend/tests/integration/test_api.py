"""End-to-end API integration tests (httpx ASGI against the real app)."""

from __future__ import annotations

import os

import pytest
from httpx import AsyncClient

from tests.integration.api_helpers import ADMIN_PW, API
from tests.integration.api_helpers import auth as _auth
from tests.integration.api_helpers import token as _token

pytestmark = pytest.mark.integration


class TestHealthAndHeaders:
    async def test_health_public(self, client: AsyncClient) -> None:
        r = await client.get("/health")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"

    async def test_security_headers_present(self, client: AsyncClient) -> None:
        r = await client.get("/health")
        assert r.headers["X-Content-Type-Options"] == "nosniff"
        assert r.headers["X-Frame-Options"] == "DENY"
        assert "Content-Security-Policy" in r.headers


class TestAuthFlow:
    async def test_login_and_me(self, client: AsyncClient) -> None:
        token = await _token(client)
        r = await client.get(f"{API}/auth/me", headers=_auth(token))
        assert r.status_code == 200
        body = r.json()
        assert body["username"] == "admin"
        assert body["is_superuser"] is True
        assert "system:admin" in body["permissions"]

    async def test_bad_login_rejected(self, client: AsyncClient) -> None:
        r = await client.post(f"{API}/auth/login", json={"identifier": "admin", "password": "nope"})
        assert r.status_code == 401

    async def test_protected_requires_token(self, client: AsyncClient) -> None:
        r = await client.get(f"{API}/security-dashboard")
        assert r.status_code == 401

    async def test_refresh_rotation(self, client: AsyncClient) -> None:
        r = await client.post(
            f"{API}/auth/login", json={"identifier": "admin", "password": ADMIN_PW}
        )
        refresh = r.json()["refresh_token"]
        r2 = await client.post(f"{API}/auth/refresh", json={"refresh_token": refresh})
        assert r2.status_code == 200
        # old refresh now revoked
        r3 = await client.post(f"{API}/auth/refresh", json={"refresh_token": refresh})
        assert r3.status_code == 401


class TestRBAC:
    async def test_new_user_without_roles_is_forbidden(self, client: AsyncClient) -> None:
        admin = await _token(client)
        # admin creates a user (no roles assigned by the endpoint)
        r = await client.post(
            f"{API}/auth/register",
            headers=_auth(admin),
            json={"username": "lowpriv", "email": "low@example.com", "password": "L0w-Priv-P@ss!"},
        )
        assert r.status_code == 201, r.text
        token = await _token(client, "lowpriv", "L0w-Priv-P@ss!")
        # no permissions -> 403 on a protected resource
        r2 = await client.get(f"{API}/security-dashboard", headers=_auth(token))
        assert r2.status_code == 403


class TestVaultEndpoints:
    async def test_upload_download_roundtrip(self, client: AsyncClient) -> None:
        token = await _token(client)
        payload = os.urandom(50_000)
        r = await client.post(
            f"{API}/files",
            headers=_auth(token),
            files={"upload": ("evidence.bin", payload, "application/octet-stream")},
            data={"category": "evidence", "description": "case-42 evidence"},
        )
        assert r.status_code == 201, r.text
        file_id = r.json()["file"]["id"]
        assert r.json()["file"]["status"] == "available"

        dl = await client.get(f"{API}/files/{file_id}/download", headers=_auth(token))
        assert dl.status_code == 200
        assert dl.content == payload

        iv = await client.post(f"{API}/files/{file_id}/verify-integrity", headers=_auth(token))
        assert iv.status_code == 200
        assert iv.json()["result"] == "passed"

    async def test_list_files(self, client: AsyncClient) -> None:
        token = await _token(client)
        await client.post(
            f"{API}/files", headers=_auth(token),
            files={"upload": ("a.bin", b"aaa", "application/octet-stream")},
            data={"category": "document"},
        )
        r = await client.get(f"{API}/files", headers=_auth(token))
        assert r.status_code == 200
        assert len(r.json()) >= 1
        assert r.json()[0]["original_filename"] == "a.bin"

    async def test_secure_delete(self, client: AsyncClient) -> None:
        token = await _token(client)
        r = await client.post(
            f"{API}/files", headers=_auth(token),
            files={"upload": ("x.bin", b"shred me", "application/octet-stream")},
            data={"category": "document"},
        )
        file_id = r.json()["file"]["id"]
        d = await client.delete(f"{API}/files/{file_id}?secure=true", headers=_auth(token))
        assert d.status_code == 200
        dl = await client.get(f"{API}/files/{file_id}/download", headers=_auth(token))
        assert dl.status_code == 404


class TestAuditAndDashboard:
    async def test_dashboard(self, client: AsyncClient) -> None:
        token = await _token(client)
        r = await client.get(f"{API}/security-dashboard", headers=_auth(token))
        assert r.status_code == 200
        assert "encryption_health_score" in r.json()

    async def test_audit_logs_and_chain(self, client: AsyncClient) -> None:
        token = await _token(client)
        await client.get(f"{API}/auth/me", headers=_auth(token))  # generate activity
        logs = await client.get(f"{API}/audit-logs", headers=_auth(token))
        assert logs.status_code == 200
        assert len(logs.json()) >= 1
        verify = await client.get(f"{API}/audit-logs/verify", headers=_auth(token))
        assert verify.status_code == 200
        assert verify.json()["ok"] is True


class TestCompliance:
    async def test_generate_and_list_report(self, client: AsyncClient) -> None:
        token = await _token(client)
        r = await client.post(
            f"{API}/compliance/reports", headers=_auth(token),
            json={"framework": "owasp_asvs"},
        )
        assert r.status_code == 201, r.text
        assert r.json()["score"] >= 90
        listed = await client.get(f"{API}/compliance/reports", headers=_auth(token))
        assert listed.status_code == 200
        assert len(listed.json()) >= 1
