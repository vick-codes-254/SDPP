"""Multi-channel notification delivery.

Pluggable provider layer (like the KMS abstraction): email/SMS/WhatsApp/push/
webhook. The default providers are **safe simulators** — they record a delivery
attempt and mark it sent without making external calls, so the platform is fully
functional offline and real providers (Twilio, SES, FCM, ...) can be wired in
later behind the same interface. Targets are decrypted only at send time.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Protocol

from sqlalchemy import func, select

from app.core.enums import NotificationChannel, NotificationStatus
from app.core.logging import get_logger
from app.models.alert_delivery import (
    AlertTemplate,
    Notification,
    NotificationChannelConfig,
)
from app.services.crud import CrudService

logger = get_logger("notifications")

_SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _now() -> datetime:
    return datetime.now(UTC)


class NotificationProvider(Protocol):
    name: str

    def send(self, *, target: str, subject: str | None, body: str) -> None:
        """Deliver a message. Raise on failure."""


class SimulatedProvider:
    """Records the send and logs it; never contacts an external service."""

    def __init__(self, channel: NotificationChannel) -> None:
        self.name = f"simulated:{channel.value}"
        self.channel = channel

    def send(self, *, target: str, subject: str | None, body: str) -> None:
        logger.info("notification_sent", channel=self.channel.value, provider=self.name,
                    target_masked=_mask(target), subject=subject)


def _mask(target: str) -> str:
    if "@" in target:
        user, _, domain = target.partition("@")
        return f"{user[:2]}***@{domain}"
    return target[:3] + "***" + target[-2:] if len(target) > 5 else "***"


class NotificationService(CrudService[NotificationChannelConfig]):
    """CRUD for channels + the dispatch/fan-out engine."""

    model = NotificationChannelConfig
    audit_resource = "notification_channel"

    _PROVIDERS: dict[NotificationChannel, NotificationProvider] = {
        ch: SimulatedProvider(ch) for ch in NotificationChannel
    }

    # ── Channels ────────────────────────────────────────────────
    async def list_channels(self, *, organization_id: uuid.UUID | None = None,
                            ) -> list[NotificationChannelConfig]:
        return await self.list(organization_id=organization_id)

    # ── Templates ───────────────────────────────────────────────
    async def list_templates(self, *, organization_id: uuid.UUID | None = None,
                             ) -> list[AlertTemplate]:
        stmt = select(AlertTemplate).order_by(AlertTemplate.key)
        if organization_id is not None:
            stmt = stmt.where(AlertTemplate.organization_id == organization_id)
        return list((await self.db.execute(stmt)).scalars().all())

    async def create_template(self, data: dict, *, actor_id: uuid.UUID | None = None) -> AlertTemplate:
        tpl = AlertTemplate(id=uuid.uuid4(), **data)
        self.db.add(tpl)
        await self.db.flush()
        await self._audit("template:create", str(tpl.id), actor_id)
        return tpl

    # ── Dispatch ────────────────────────────────────────────────
    async def dispatch(
        self,
        *,
        organization_id: uuid.UUID,
        channel: NotificationChannel,
        target: str,
        body: str,
        subject: str | None = None,
        related_alert_id: uuid.UUID | None = None,
        related_emergency_id: uuid.UUID | None = None,
    ) -> Notification:
        note = Notification(
            id=uuid.uuid4(), organization_id=organization_id, channel=channel,
            target=target, subject=subject, body=body,
            status=NotificationStatus.queued, attempts=0,
            related_alert_id=related_alert_id, related_emergency_id=related_emergency_id,
        )
        provider = self._PROVIDERS.get(channel)
        note.provider = provider.name if provider else None
        note.attempts = 1
        try:
            if provider is None:
                raise RuntimeError(f"No provider for channel {channel}")
            provider.send(target=target, subject=subject, body=body)
            note.status = NotificationStatus.sent
            note.sent_at = _now()
        except Exception as exc:  # noqa: BLE001 - delivery failure is recorded, not fatal
            note.status = NotificationStatus.failed
            note.error = str(exc)[:255]
        self.db.add(note)
        await self.db.flush()
        return note

    async def fan_out(
        self,
        *,
        organization_id: uuid.UUID,
        subject: str,
        body: str,
        severity: str = "low",
        related_alert_id: uuid.UUID | None = None,
        related_emergency_id: uuid.UUID | None = None,
    ) -> int:
        """Send to every active channel for the org whose min_severity is met."""
        sev_rank = _SEVERITY_ORDER.get(severity, 0)
        channels = [
            c for c in await self.list_channels(organization_id=organization_id)
            if c.is_active and _SEVERITY_ORDER.get(c.min_severity, 0) <= sev_rank
        ]
        sent = 0
        for ch in channels:
            await self.dispatch(
                organization_id=organization_id, channel=ch.channel, target=ch.target,
                subject=subject, body=body, related_alert_id=related_alert_id,
                related_emergency_id=related_emergency_id,
            )
            sent += 1
        return sent

    async def history(self, *, organization_id: uuid.UUID | None = None,
                      limit: int = 100) -> list[Notification]:
        stmt = select(Notification).order_by(Notification.created_at.desc()).limit(limit)
        if organization_id is not None:
            stmt = stmt.where(Notification.organization_id == organization_id)
        return list((await self.db.execute(stmt)).scalars().all())

    async def delivery_stats(self, *, organization_id: uuid.UUID | None = None) -> dict[str, int]:
        stmt = select(Notification.status, func.count()).group_by(Notification.status)
        if organization_id is not None:
            stmt = stmt.where(Notification.organization_id == organization_id)
        rows = (await self.db.execute(stmt)).all()
        out = {s.value: 0 for s in NotificationStatus}
        for status, count in rows:
            out[status.value if hasattr(status, "value") else str(status)] = int(count)
        return out
