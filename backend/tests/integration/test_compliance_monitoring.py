"""Compliance report generation & monitoring dashboard tests."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.compliance.evaluator import ComplianceEvaluator
from app.core.enums import ComplianceFramework
from app.models.audit import SecurityAlert
from app.models.enums import AlertSeverity, AlertStatus, AlertType
from app.services.compliance_service import ComplianceService
from app.services.monitoring_service import MonitoringService

pytestmark = pytest.mark.integration


class TestComplianceEvaluator:
    def test_every_framework_scores_in_range(self) -> None:
        ev = ComplianceEvaluator()
        for fw in ComplianceFramework:
            results = ev.evaluate(fw)
            assert results
            score = ev.score(results)
            assert 0.0 <= score <= 100.0


class TestComplianceService:
    async def test_generate_report(self, async_session: AsyncSession) -> None:
        svc = ComplianceService(async_session)
        report = await svc.generate(ComplianceFramework.owasp_asvs)
        assert report.score is not None and float(report.score) >= 90.0
        assert report.summary["total_controls"] > 0
        assert "controls" in report.content
        assert report.content["controls"][0]["evidence"]

    async def test_generate_all_frameworks(self, async_session: AsyncSession) -> None:
        svc = ComplianceService(async_session)
        reports = await svc.generate_all()
        assert len(reports) == len(list(ComplianceFramework))
        listed = await svc.list_reports()
        assert len(listed) >= len(reports)


class TestMonitoringDashboard:
    async def test_empty_dashboard_is_healthy(self, async_session: AsyncSession) -> None:
        metrics = await MonitoringService(async_session).dashboard()
        assert metrics.encrypted_files == 0
        assert metrics.encryption_health_score == 100.0
        assert metrics.recent_events == []

    async def test_critical_alert_lowers_health(self, async_session: AsyncSession) -> None:
        async_session.add(
            SecurityAlert(
                id=uuid.uuid4(), alert_type=AlertType.brute_force,
                severity=AlertSeverity.critical, status=AlertStatus.open,
                title="Brute force detected",
            )
        )
        await async_session.flush()
        svc = MonitoringService(async_session)
        metrics = await svc.dashboard()
        assert metrics.open_alerts == 1
        assert metrics.critical_alerts == 1
        assert metrics.encryption_health_score < 100.0

    async def test_acknowledge_and_resolve_alert(self, async_session: AsyncSession) -> None:
        alert = SecurityAlert(
            id=uuid.uuid4(), alert_type=AlertType.anomaly,
            severity=AlertSeverity.medium, status=AlertStatus.open, title="Anomaly",
        )
        async_session.add(alert)
        await async_session.flush()

        svc = MonitoringService(async_session)
        actor = uuid.uuid4()
        ack = await svc.acknowledge_alert(alert.id, actor_id=actor)
        assert ack and ack.status is AlertStatus.acknowledged
        resolved = await svc.resolve_alert(alert.id, actor_id=actor)
        assert resolved and resolved.status is AlertStatus.resolved
