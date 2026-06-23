"""Security / attack-simulation tests (OWASP-aligned).

Exercises the running API as an adversary would: broken authentication, token
forgery/expiry/tampering, authorization bypass, injection, replay, brute-force,
and user-enumeration resistance.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import jwt
import pytest
from httpx import AsyncClient

from app.core.security.tokens import TokenManager
from tests.integration.api_helpers import API, auth, token

pytestmark = [pytest.mark.integration, pytest.mark.security]

# Must match the JWT secret the `client` fixture configures.
SECRET = "test-jwt-secret-key-32-bytes-minimum!!"


class TestBrokenAuthentication:
    async def test_no_token_rejected(self, client: AsyncClient) -> None:
        assert (await client.get(f"{API}/security-dashboard")).status_code == 401

    async def test_malformed_token_rejected(self, client: AsyncClient) -> None:
        r = await client.get(f"{API}/security-dashboard", headers=auth("not-a-jwt"))
        assert r.status_code == 401

    async def test_alg_none_forgery_rejected(self, client: AsyncClient) -> None:
        forged = jwt.encode(
            {"sub": "x", "type": "access", "su": True, "perms": ["system:admin"]},
            key="", algorithm="none",
        )
        r = await client.get(f"{API}/security-dashboard", headers=auth(forged))
        assert r.status_code == 401

    async def test_wrong_secret_signature_rejected(self, client: AsyncClient) -> None:
        forger = TokenManager(secret_key="attacker-does-not-know-the-real-secret!!")
        evil = forger.create_access_token("00000000-0000-0000-0000-000000000000",
                                          {"perms": ["system:admin"], "su": True})
        r = await client.get(f"{API}/security-dashboard", headers=auth(evil))
        assert r.status_code == 401

    async def test_expired_token_rejected(self, client: AsyncClient) -> None:
        past = datetime(2020, 1, 1, tzinfo=UTC)
        tm = TokenManager(secret_key=SECRET, access_ttl=timedelta(minutes=1), clock=lambda: past)
        expired = tm.create_access_token("00000000-0000-0000-0000-000000000000")
        r = await client.get(f"{API}/security-dashboard", headers=auth(expired))
        assert r.status_code == 401

    async def test_tampered_token_rejected(self, client: AsyncClient) -> None:
        good = await token(client)
        tampered = good[:-4] + ("aaaa" if not good.endswith("aaaa") else "bbbb")
        r = await client.get(f"{API}/auth/me", headers=auth(tampered))
        assert r.status_code == 401


class TestAuthorizationBypass:
    async def test_low_privilege_user_blocked(self, client: AsyncClient) -> None:
        admin = await token(client)
        await client.post(
            f"{API}/auth/register", headers=auth(admin),
            json={"username": "noperm", "email": "noperm@x.com", "password": "N0Perm-P@ss!!"},
        )
        low = await token(client, "noperm", "N0Perm-P@ss!!")
        # No roles -> no permissions -> forbidden on every protected resource.
        for path in ("/security-dashboard", "/keys", "/audit-logs", "/compliance/reports"):
            r = await client.get(f"{API}{path}", headers=auth(low))
            assert r.status_code == 403, path

    async def test_access_token_cannot_be_used_as_refresh(self, client: AsyncClient) -> None:
        access = await token(client)
        r = await client.post(f"{API}/auth/refresh", json={"refresh_token": access})
        assert r.status_code == 401  # wrong token type


class TestInjection:
    async def test_sql_injection_in_login_is_safe(self, client: AsyncClient) -> None:
        # Parameterized queries -> no bypass, no 500, just invalid credentials.
        r = await client.post(
            f"{API}/auth/login",
            json={"identifier": "admin' OR '1'='1", "password": "' OR '1'='1"},
        )
        assert r.status_code == 401


class TestReplay:
    async def test_revoked_refresh_token_replay_rejected(self, client: AsyncClient) -> None:
        login = await client.post(
            f"{API}/auth/login",
            json={"identifier": "admin", "password": "Adm1n-Str0ng-P@ss!"},
        )
        refresh = login.json()["refresh_token"]
        assert (await client.post(f"{API}/auth/refresh", json={"refresh_token": refresh})).status_code == 200
        # Replaying the now-rotated (revoked) token must fail.
        replay = await client.post(f"{API}/auth/refresh", json={"refresh_token": refresh})
        assert replay.status_code == 401


class TestBruteForce:
    async def test_account_lockout(self, client: AsyncClient) -> None:
        for _ in range(5):  # default MAX_FAILED_LOGINS = 5
            r = await client.post(
                f"{API}/auth/login", json={"identifier": "admin", "password": "wrong"}
            )
            assert r.status_code == 401
        # Account now locked — even the CORRECT password is refused.
        locked = await client.post(
            f"{API}/auth/login", json={"identifier": "admin", "password": "Adm1n-Str0ng-P@ss!"}
        )
        assert locked.status_code == 423


class TestUserEnumeration:
    async def test_unknown_and_wrong_password_indistinguishable(self, client: AsyncClient) -> None:
        unknown = await client.post(
            f"{API}/auth/login", json={"identifier": "ghost", "password": "whatever-12345"}
        )
        wrong = await client.post(
            f"{API}/auth/login", json={"identifier": "admin", "password": "whatever-12345"}
        )
        assert unknown.status_code == wrong.status_code == 401
        assert unknown.json() == wrong.json()  # identical response body
