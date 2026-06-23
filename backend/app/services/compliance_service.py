"""Compliance reporting service — generates scored framework reports."""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.compliance.evaluator import ComplianceEvaluator
from app.core.config import Settings, get_settings
from app.core.enums import ComplianceFramework
from app.models.compliance import ComplianceReport
from app.models.enums import AuditEventType, AuditOutcome, ReportStatus
from app.services.audit_service import AuditService


class ComplianceService:
    def __init__(
        self,
        db: AsyncSession,
        *,
        settings: Settings | None = None,
        audit: AuditService | None = None,
    ) -> None:
        self.db = db
        self.settings = settings or get_settings()
        self.audit = audit or AuditService(db)
        self.evaluator = ComplianceEvaluator(self.settings)

    async def generate(
        self,
        framework: ComplianceFramework,
        *,
        actor_id: uuid.UUID | None = None,
        title: str | None = None,
    ) -> ComplianceReport:
        results = self.evaluator.evaluate(framework)
        score = self.evaluator.score(results)
        passed = sum(1 for r in results if r.passed)

        summary = {
            "framework": str(framework),
            "total_controls": len(results),
            "passed": passed,
            "failed": len(results) - passed,
            "score": score,
        }
        content = {
            "controls": [
                {
                    "id": r.control.id,
                    "title": r.control.title,
                    "description": r.control.description,
                    "severity": r.control.severity,
                    "passed": r.passed,
                    "evidence": r.evidence,
                }
                for r in results
            ]
        }

        report = ComplianceReport(
            id=uuid.uuid4(),
            framework=framework,
            title=title or f"{framework.value} compliance report",
            status=ReportStatus.final,
            score=score,
            summary=summary,
            content=content,
            generated_by=actor_id,
        )
        self.db.add(report)
        await self.audit.record(
            event_type=AuditEventType.report_generated,
            outcome=AuditOutcome.success,
            actor_id=actor_id,
            resource_type="compliance_report",
            resource_id=str(report.id),
            action="generate_report",
            detail={"framework": str(framework), "score": score},
        )
        await self.db.flush()
        return report

    async def generate_all(
        self, *, actor_id: uuid.UUID | None = None
    ) -> list[ComplianceReport]:
        return [await self.generate(fw, actor_id=actor_id) for fw in ComplianceFramework]

    async def get_report(self, report_id: uuid.UUID) -> ComplianceReport | None:
        return (
            await self.db.execute(
                select(ComplianceReport).where(ComplianceReport.id == report_id)
            )
        ).scalar_one_or_none()

    async def list_reports(self, *, limit: int = 50) -> list[ComplianceReport]:
        return list(
            (
                await self.db.execute(
                    select(ComplianceReport)
                    .order_by(ComplianceReport.created_at.desc())
                    .limit(limit)
                )
            )
            .scalars()
            .all()
        )
