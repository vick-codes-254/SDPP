"""SOC dashboard rollup + user management tests."""

from __future__ import annotations

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.bootstrap import seed_rbac
from app.core.enums import AssetCriticality, IncidentSeverity
from app.core.security.passwords import PasswordManager, PasswordPolicy
from app.services.asset_service import AssetData, AssetService, SoftwareEntry
from app.services.auth_service import AuthService, user_permissions
from app.services.exceptions import ValidationError
from app.services.incident_service import IncidentService
from app.services.monitoring_service import MonitoringService
from app.services.user_service import UserService
from app.services.vuln_service import VulnService

pytestmark = pytest.mark.integration

_PW = "Str0ng-P@ssw0rd!"


def _fast_auth(session: AsyncSession) -> AuthService:
    pm = PasswordManager(time_cost=1, memory_cost=8192, parallelism=1, policy=PasswordPolicy())
    return AuthService(session, passwords=pm)


class TestDashboardRollup:
    async def test_soc_metrics(self, async_session: AsyncSession) -> None:
        await AssetService(async_session).create(
            AssetData(name="srv", ip_address="10.5.5.5", criticality=AssetCriticality.critical,
                      software=[SoftwareEntry("log4j", "2.14.1")])
        )
        vsvc = VulnService(async_session)
        await vsvc.run_scan((await vsvc.create_scan(name="s")).id)
        await IncidentService(async_session).create(title="inc", severity=IncidentSeverity.high)

        metrics = await MonitoringService(async_session).dashboard()
        assert metrics.total_assets == 1
        assert metrics.assets_by_criticality.get("critical") == 1
        assert metrics.open_vulnerabilities >= 1
        assert metrics.vulns_by_severity.get("critical", 0) >= 1
        assert metrics.open_incidents == 1
        assert metrics.vuln_scans == 1


class TestUserManagement:
    async def test_list_set_roles_activate(self, async_session: AsyncSession) -> None:
        await seed_rbac(async_session)
        auth = _fast_auth(async_session)
        user = await auth.register(username="bob", email="bob@example.com", password=_PW)

        usvc = UserService(async_session)
        assert any(u.id == user.id for u in await usvc.list_users())

        await usvc.set_roles(user.id, ["analyst"], actor_id=user.id)
        refreshed = await auth.get_user(user.id)
        assert "file:upload" in user_permissions(refreshed)

        deactivated = await usvc.set_active(user.id, False)
        assert deactivated.is_active is False

    async def test_unknown_role_rejected(self, async_session: AsyncSession) -> None:
        await seed_rbac(async_session)
        auth = _fast_auth(async_session)
        user = await auth.register(username="carol", email="carol@example.com", password=_PW)
        with pytest.raises(ValidationError):
            await UserService(async_session).set_roles(user.id, ["wizard"])
