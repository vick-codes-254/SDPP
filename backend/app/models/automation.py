"""Workflow automation: trigger/escalation rules.

A rule fires when an event of ``trigger`` type matches ``condition`` (a simple
key=value match against the event context) and runs ``action`` with
``action_config`` (e.g. notify a channel, auto-create an incident, escalate).
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Enum, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.enums import AutomationAction, AutomationTrigger
from app.db.base import Base, TenantMixin, TimestampMixin, UUIDPrimaryKeyMixin
from app.db.types import JSONType


class AutomationRule(Base, UUIDPrimaryKeyMixin, TenantMixin, TimestampMixin):
    __tablename__ = "automation_rules"

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    trigger: Mapped[AutomationTrigger] = mapped_column(
        Enum(AutomationTrigger, name="automation_trigger"), nullable=False, index=True
    )
    condition: Mapped[dict | None] = mapped_column(JSONType)
    action: Mapped[AutomationAction] = mapped_column(
        Enum(AutomationAction, name="automation_action"), nullable=False
    )
    action_config: Mapped[dict | None] = mapped_column(JSONType)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, index=True)
    trigger_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_triggered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
