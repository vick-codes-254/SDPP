"""Alert engine rule model (SecurityAlert itself lives in models/audit.py)."""

from __future__ import annotations

import uuid

from sqlalchemy import Boolean, Enum, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.enums import AlertRuleType, AlertSeverity
from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin
from app.db.types import GUID, JSONType


class AlertRule(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "alert_rules"

    name: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    rule_type: Mapped[AlertRuleType] = mapped_column(
        Enum(AlertRuleType, name="alert_rule_type"), nullable=False
    )
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    # Severity assigned to alerts this rule raises (may be overridden per-finding).
    severity: Mapped[AlertSeverity] = mapped_column(
        Enum(AlertSeverity, name="alert_rule_severity"), nullable=False, default=AlertSeverity.medium
    )
    # Rule-specific parameters, e.g. {"threshold": "high"} or {"ports": [23, 3389]}.
    params: Mapped[dict | None] = mapped_column(JSONType)
    description: Mapped[str | None] = mapped_column(String(255))
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        GUID, ForeignKey("users.id", ondelete="SET NULL")
    )
