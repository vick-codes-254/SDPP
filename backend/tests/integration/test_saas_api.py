"""SaaS tests: subscription/usage/invoice/payment, feature flags, backups, integrations."""

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


class TestBilling:
    async def test_subscription_invoice_payment_usage(self, client: AsyncClient) -> None:
        t = await _token(client)
        org = await _org(client, t)

        sub = await client.put(
            f"{API}/billing/subscription", headers=_auth(t),
            json={"organization_id": org, "plan": "professional", "seats": 25,
                  "monthly_price": 499.0, "currency": "USD"},
        )
        assert sub.status_code == 200, sub.text
        assert sub.json()["plan"] == "professional"

        inv = await client.post(
            f"{API}/billing/invoices", headers=_auth(t),
            json={"organization_id": org, "amount": 499.0, "currency": "USD"},
        )
        assert inv.status_code == 201, inv.text
        assert inv.json()["number"].startswith("INV-")
        inv_id = inv.json()["id"]

        pay = await client.post(
            f"{API}/billing/invoices/{inv_id}/pay", headers=_auth(t),
            json={"method": "card", "reference": "ch_123"},
        )
        assert pay.status_code == 200
        assert pay.json()["status"] == "completed"

        usage = await client.get(f"{API}/billing/usage?organization_id={org}", headers=_auth(t))
        body = usage.json()
        assert body["plan"] == "professional" and "used" in body and "limits" in body


class TestSystemAdmin:
    async def test_feature_flag_and_backup(self, client: AsyncClient) -> None:
        t = await _token(client)
        org = await _org(client, t)

        f = await client.post(
            f"{API}/admin/feature-flags", headers=_auth(t),
            json={"key": "anpr_beta", "enabled": True, "organization_id": org,
                  "description": "Enable ANPR beta"},
        )
        assert f.status_code == 200, f.text
        assert f.json()["enabled"] is True

        # Idempotent upsert flips the value.
        f2 = await client.post(
            f"{API}/admin/feature-flags", headers=_auth(t),
            json={"key": "anpr_beta", "enabled": False, "organization_id": org},
        )
        assert f2.json()["enabled"] is False

        b = await client.post(
            f"{API}/admin/backups", headers=_auth(t),
            json={"organization_id": org, "note": "nightly"},
        )
        assert b.status_code == 201
        assert b.json()["status"] == "completed"

    async def test_integration_secret_not_exposed(self, client: AsyncClient) -> None:
        t = await _token(client)
        org = await _org(client, t)
        i = await client.post(
            f"{API}/admin/integrations", headers=_auth(t),
            json={"organization_id": org, "name": "Slack SOC", "kind": "slack",
                  "secret": "xoxb-super-secret", "config": {"channel": "#soc"}},
        )
        assert i.status_code == 201, i.text
        assert "secret" not in i.json()  # secret never returned

        act = await client.post(
            f"{API}/admin/integrations/{i.json()['id']}/status", headers=_auth(t),
            json={"active": True},
        )
        assert act.json()["status"] == "active"
