"""Workflow automation engine.

Rules subscribe to a trigger type; when an event is evaluated, rules whose simple
key=value ``condition`` matches the event context fire their action (notify,
auto-create incident, escalate, or log). Used to wire detections/threats/cyber
events to automatic response without code changes.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select

from app.core.enums import AutomationAction, AutomationTrigger, IncidentSeverity
from app.models.automation import AutomationRule
from app.services.crud import CrudService
from app.services.incident_service import IncidentService
from app.services.notification_service import NotificationService

_SEV = {
    "critical": IncidentSeverity.critical, "high": IncidentSeverity.high,
    "medium": IncidentSeverity.medium, "low": IncidentSeverity.low,
}


def _now() -> datetime:
    return datetime.now(UTC)


class WorkflowService(CrudService[AutomationRule]):
    model = AutomationRule
    audit_resource = "automation_rule"

    @staticmethod
    def _matches(condition: dict | None, context: dict) -> bool:
        if not condition:
            return True
        return all(str(context.get(k)) == str(v) for k, v in condition.items())

    async def evaluate(
        self,
        *,
        trigger: AutomationTrigger,
        context: dict[str, Any],
        organization_id: uuid.UUID,
        actor_id: uuid.UUID | None = None,
    ) -> list[dict]:
        rules = list((await self.db.execute(
            select(AutomationRule).where(
                AutomationRule.organization_id == organization_id,
                AutomationRule.trigger == trigger,
                AutomationRule.is_active.is_(True),
            )
        )).scalars().all())

        executed: list[dict] = []
        for rule in rules:
            if not self._matches(rule.condition, context):
                continue
            result = await self._run_action(rule, context, organization_id, actor_id)
            rule.trigger_count += 1
            rule.last_triggered_at = _now()
            executed.append({"rule_id": str(rule.id), "name": rule.name,
                             "action": rule.action.value, "result": result})
        await self.db.flush()
        if executed:
            await self._audit(f"evaluate:{trigger.value}", str(organization_id), actor_id,
                              {"fired": len(executed)})
        return executed

    async def _run_action(self, rule: AutomationRule, context: dict,
                          organization_id: uuid.UUID, actor_id: uuid.UUID | None) -> str:
        cfg = rule.action_config or {}
        severity = str(context.get("severity", "low"))
        if rule.action == AutomationAction.notify:
            count = await NotificationService(self.db, audit=self.audit).fan_out(
                organization_id=organization_id,
                subject=cfg.get("subject", f"Automation: {rule.name}"),
                body=cfg.get("body", f"Triggered by {context}"),
                severity=severity,
            )
            return f"notified:{count}"
        if rule.action == AutomationAction.create_incident:
            inc = await IncidentService(self.db, audit=self.audit).create(
                title=cfg.get("title", rule.name),
                description=cfg.get("body", f"Auto-created by rule {rule.name}"),
                severity=_SEV.get(severity, IncidentSeverity.medium),
                organization_id=organization_id, reporter_id=actor_id,
            )
            return f"incident:{inc.id}"
        return "logged"
