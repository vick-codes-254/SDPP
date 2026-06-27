"""Alert Engine tests."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import AlertRuleType, AlertSeverity, AssetCriticality
from app.models.alert import AlertRule
from app.models.audit import SecurityAlert
from app.services.alert_engine import AlertEngine
from app.services.asset_service import AssetData, AssetService, SoftwareEntry
from app.services.vuln_service import VulnService

pytestmark = pytest.mark.integration


async def _alert_count(session: AsyncSession) -> int:
    return int(
        (await session.execute(select(func.count()).select_from(SecurityAlert))).scalar_one()
    )


class TestAlertEngine:
    async def test_seed_default_rules_idempotent(self, async_session: AsyncSession) -> None:
        eng = AlertEngine(async_session)
        assert await eng.seed_default_rules() == 2
        assert await eng.seed_default_rules() == 0  # no duplicates

    async def test_findings_raise_alerts(self, async_session: AsyncSession) -> None:
        eng = AlertEngine(async_session)
        await eng.seed_default_rules()
        await AssetService(async_session).create(
            AssetData(name="app-01", ip_address="10.2.2.2", criticality=AssetCriticality.critical,
                      software=[SoftwareEntry("log4j", "2.14.1")])
        )
        vsvc = VulnService(async_session)
        scan = await vsvc.run_scan((await vsvc.create_scan(name="s")).id)

        alerts = await eng.run_for_vuln_scan(scan.id)
        assert len(alerts) == 1
        assert alerts[0].severity is AlertSeverity.critical

    async def test_dedup_on_rerun(self, async_session: AsyncSession) -> None:
        eng = AlertEngine(async_session)
        await eng.seed_default_rules()
        await AssetService(async_session).create(
            AssetData(name="x", ip_address="10.2.2.3", software=[SoftwareEntry("openssl", "3.0.2")])
        )
        vsvc = VulnService(async_session)
        scan = await vsvc.run_scan((await vsvc.create_scan(name="s")).id)

        await eng.run_for_vuln_scan(scan.id)
        first = await _alert_count(async_session)
        await eng.run_for_vuln_scan(scan.id)  # again
        assert await _alert_count(async_session) == first  # no duplicates

    async def test_below_threshold_does_not_fire(self, async_session: AsyncSession) -> None:
        # Only a critical-threshold rule; a HIGH finding on a non-critical asset must not alert.
        async_session.add(
            AlertRule(
                id=uuid.uuid4(), name="Critical only", rule_type=AlertRuleType.vuln_severity,
                enabled=True, severity=AlertSeverity.critical, params={"threshold": "critical"},
            )
        )
        await async_session.flush()
        await AssetService(async_session).create(
            AssetData(name="y", ip_address="10.2.2.4", criticality=AssetCriticality.medium,
                      software=[SoftwareEntry("openssl", "3.0.2")])  # CVE-2022-3602 = high
        )
        vsvc = VulnService(async_session)
        scan = await vsvc.run_scan((await vsvc.create_scan(name="s")).id)
        alerts = await AlertEngine(async_session).run_for_vuln_scan(scan.id)
        assert alerts == []
