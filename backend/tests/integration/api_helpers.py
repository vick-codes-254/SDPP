"""Shared helpers for API integration & security tests."""

from __future__ import annotations

from httpx import AsyncClient

ADMIN_PW = "Adm1n-Str0ng-P@ss!"
API = "/api/v1"


async def token(client: AsyncClient, username: str = "admin", password: str = ADMIN_PW) -> str:
    r = await client.post(f"{API}/auth/login", json={"identifier": username, "password": password})
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


def auth(tok: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {tok}"}
