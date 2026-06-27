"""Vulnerability scanning service tests."""

from __future__ import annotations

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import VulnSeverity, VulnStatus
from app.services.asset_service import AssetData, AssetService, SoftwareEntry
from app.services.vuln_service import VulnService

pytestmark = pytest.mark.integration


async def _asset_with_software(session: AsyncSession, software: list[SoftwareEntry]):
    return await AssetService(session).create(
        AssetData(name="target", ip_address="10.1.1.1", software=software)
    )


class TestVulnScan:
    async def test_scan_finds_known_cves(self, async_session: AsyncSession) -> None:
        await _asset_with_software(
            async_session,
            [
                SoftwareEntry("openssl", "3.0.2"),   # CVE-2022-3602 (high)
                SoftwareEntry("log4j", "2.14.1"),    # Log4Shell (critical)
                SoftwareEntry("nginx", "1.21.0"),    # patched -> no finding
            ],
        )
        svc = VulnService(async_session)
        scan = await svc.create_scan(name="full")
        done = await svc.run_scan(scan.id)

        assert done.summary["total_findings"] == 2
        assert done.summary["by_severity"]["critical"] == 1
        assert done.summary["by_severity"]["high"] == 1

        findings = await svc.list_findings(scan_id=scan.id)
        cves = {f.cve_id for f in findings}
        assert "CVE-2021-44228" in cves
        assert "CVE-2022-3602" in cves
        # ordered by CVSS desc -> Log4Shell (10.0) first
        assert findings[0].cve_id == "CVE-2021-44228"

    async def test_clean_asset_has_no_findings(self, async_session: AsyncSession) -> None:
        await _asset_with_software(async_session, [SoftwareEntry("openssl", "3.0.7")])
        svc = VulnService(async_session)
        scan = await svc.run_scan((await svc.create_scan(name="clean")).id)
        assert scan.summary["total_findings"] == 0

    async def test_triage_finding_status(self, async_session: AsyncSession) -> None:
        await _asset_with_software(async_session, [SoftwareEntry("bash", "4.2")])
        svc = VulnService(async_session)
        scan = await svc.run_scan((await svc.create_scan(name="x")).id)
        finding = (await svc.list_findings(scan_id=scan.id))[0]
        updated = await svc.set_finding_status(finding.id, VulnStatus.false_positive)
        assert updated.status is VulnStatus.false_positive

    async def test_scoped_scan(self, async_session: AsyncSession) -> None:
        a1 = await _asset_with_software(async_session, [SoftwareEntry("log4j", "2.10.0")])
        await _asset_with_software(async_session, [SoftwareEntry("sudo", "1.8.30")])
        svc = VulnService(async_session)
        scan = await svc.run_scan((await svc.create_scan(name="scoped", asset_ids=[a1.id])).id)
        findings = await svc.list_findings(scan_id=scan.id)
        # Only a1's log4j should be scanned.
        assert all(f.asset_id == a1.id for f in findings)
        assert {f.cve_id for f in findings} == {"CVE-2021-44228"}
