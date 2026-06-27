"""Alert Engine — turns findings and discovery results into security alerts.

Evaluates configurable :class:`AlertRule` rows against vulnerability findings (and
newly discovered hosts), raising de-duplicated :class:`SecurityAlert` rows that
surface on the dashboard and can be escalated into incidents.
"""

from __future__ import annotations

import uuid

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import (
    AlertRuleType,
    AlertSeverity,
    AlertStatus,
    AlertType,
    AuditEventType,
    AuditOutcome,
    AssetCriticality,
)
from app.models.alert import AlertRule
from app.models.asset import Asset
from app.models.audit import SecurityAlert
from app.models.vuln import Finding
from app.services.audit_service import AuditService

_SEV_ORDER = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Default rule set seeded on first run.
_DEFAULT_RULES = [
    {
        "name": "High+ vulnerability", "rule_type": AlertRuleType.vuln_severity,
        "severity": AlertSeverity.high, "params": {"threshold": "high"},
        "description": "Raise an alert for any finding of severity high or above.",
    },
    {
        "name": "Vulnerability on critical asset", "rule_type": AlertRuleType.critical_asset_vuln,
        "severity": AlertSeverity.critical, "params": {},
        "description": "Any vulnerability on a critical-criticality asset.",
    },
]


def _finding_to_alert_severity(sev: str) -> AlertSeverity:
    return {
        "critical": AlertSeverity.critical, "high": AlertSeverity.high,
        "medium": AlertSeverity.medium, "low": AlertSeverity.low, "none": AlertSeverity.low,
    }[sev]


class AlertEngine:
    def __init__(self, db: AsyncSession, *, audit: AuditService | None = None) -> None:
        self.db = db
        self.audit = audit or AuditService(db)

    async def seed_default_rules(self, *, actor_id: uuid.UUID | None = None) -> int:
        existing = {
            r.name for r in (await self.db.execute(select(AlertRule))).scalars().all()
        }
        created = 0
        for spec in _DEFAULT_RULES:
            if spec["name"] in existing:
                continue
            self.db.add(AlertRule(id=uuid.uuid4(), created_by=actor_id, enabled=True, **spec))
            created += 1
        await self.db.flush()
        return created

    async def _enabled_rules(self) -> list[AlertRule]:
        return list(
            (
                await self.db.execute(select(AlertRule).where(AlertRule.enabled.is_(True)))
            ).scalars().all()
        )

    async def _exists(self, source_ref: str) -> bool:
        count = await self.db.execute(
            select(func.count()).select_from(SecurityAlert).where(
                SecurityAlert.source_ref == source_ref
            )
        )
        return (count.scalar_one() or 0) > 0

    def _match(self, rule: AlertRule, finding: Finding, asset: Asset) -> AlertSeverity | None:
        """Return the alert severity if the rule fires for this finding, else None."""
        if rule.rule_type is AlertRuleType.vuln_severity:
            threshold = (rule.params or {}).get("threshold", "high")
            if _SEV_ORDER[finding.severity.value] >= _SEV_ORDER.get(threshold, 3):
                return _finding_to_alert_severity(finding.severity.value)
        elif rule.rule_type is AlertRuleType.critical_asset_vuln:
            if asset.criticality is AssetCriticality.critical:
                return AlertSeverity.critical
        return None

    async def evaluate_finding(
        self, finding: Finding, asset: Asset, rules: list[AlertRule]
    ) -> SecurityAlert | None:
        # Highest severity any rule assigns wins; one alert per finding (dedup).
        best: AlertSeverity | None = None
        for rule in rules:
            sev = self._match(rule, finding, asset)
            if sev and (best is None or _SEV_ORDER[sev.value] > _SEV_ORDER[best.value]):
                best = sev
        if best is None:
            return None

        source_ref = f"finding:{finding.id}"
        if await self._exists(source_ref):
            return None

        alert = SecurityAlert(
            id=uuid.uuid4(),
            alert_type=AlertType.vulnerability,
            severity=best,
            status=AlertStatus.open,
            title=f"{finding.severity.value.upper()} vuln {finding.cve_id} on {asset.name}",
            description=(
                f"{finding.title} affecting {finding.affected_software} "
                f"{finding.affected_version}. {finding.remediation or ''}".strip()
            ),
            related_asset_id=asset.id,
            source_ref=source_ref,
        )
        self.db.add(alert)
        await self.audit.record(
            event_type=AuditEventType.alert_triggered, outcome=AuditOutcome.success,
            resource_type="security_alert", resource_id=str(alert.id), action="raise",
            detail={"cve": finding.cve_id, "severity": best.value, "asset": str(asset.id)},
        )
        return alert

    async def run_for_vuln_scan(self, scan_id: uuid.UUID) -> list[SecurityAlert]:
        rules = await self._enabled_rules()
        if not rules:
            return []
        findings = list(
            (
                await self.db.execute(select(Finding).where(Finding.scan_id == scan_id))
            ).scalars().all()
        )
        # Preload the assets referenced by these findings.
        asset_ids = {f.asset_id for f in findings}
        assets = {
            a.id: a
            for a in (
                await self.db.execute(select(Asset).where(Asset.id.in_(asset_ids)))
            ).scalars().all()
        }
        raised: list[SecurityAlert] = []
        for finding in findings:
            asset = assets.get(finding.asset_id)
            if asset is None:
                continue
            alert = await self.evaluate_finding(finding, asset, rules)
            if alert is not None:
                raised.append(alert)
        await self.db.flush()
        return raised
