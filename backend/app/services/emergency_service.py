"""Emergency response: panic, lockdown, evacuation, broadcast.

Triggering an emergency records an EmergencyEvent, fans out notifications to the
tenant's channels and emergency contacts, and (for lockdown) locks the site's
access points. High-severity emergencies also raise a SecurityAlert.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import select, update

from app.core.enums import (
    AlertSeverity,
    AlertStatus,
    AlertType,
    EmergencyStatus,
    EmergencyType,
    NotificationChannel,
)
from app.models.access import AccessPoint
from app.models.audit import SecurityAlert
from app.models.emergency import EmergencyContact, EmergencyEvent
from app.services.crud import CrudService
from app.services.notification_service import NotificationService

_CRITICAL_TYPES = {
    EmergencyType.panic, EmergencyType.fire, EmergencyType.lockdown, EmergencyType.evacuation,
}


def _now() -> datetime:
    return datetime.now(UTC)


class EmergencyService(CrudService[EmergencyEvent]):
    model = EmergencyEvent
    audit_resource = "emergency"

    # ── Contacts ────────────────────────────────────────────────
    async def list_contacts(self, *, organization_id: uuid.UUID | None = None,
                            ) -> list[EmergencyContact]:
        stmt = select(EmergencyContact).order_by(EmergencyContact.priority)
        if organization_id is not None:
            stmt = stmt.where(EmergencyContact.organization_id == organization_id)
        return list((await self.db.execute(stmt)).scalars().all())

    async def add_contact(self, data: dict, *, actor_id: uuid.UUID | None = None) -> EmergencyContact:
        contact = EmergencyContact(id=uuid.uuid4(), **data)
        self.db.add(contact)
        await self.db.flush()
        await self._audit("contact:add", str(contact.id), actor_id)
        return contact

    # ── Trigger / resolve ───────────────────────────────────────
    async def trigger(
        self,
        *,
        organization_id: uuid.UUID,
        event_type: EmergencyType,
        site_id: uuid.UUID | None = None,
        zone_id: uuid.UUID | None = None,
        message: str | None = None,
        actor_id: uuid.UUID | None = None,
    ) -> EmergencyEvent:
        event = EmergencyEvent(
            id=uuid.uuid4(), organization_id=organization_id, event_type=event_type,
            status=EmergencyStatus.active, site_id=site_id, zone_id=zone_id,
            message=message, triggered_by=actor_id,
        )
        self.db.add(event)
        await self.db.flush()

        # Lockdown physically locks the site's access points.
        if event_type == EmergencyType.lockdown and site_id is not None:
            await self.db.execute(
                update(AccessPoint).where(AccessPoint.site_id == site_id)
                .values(is_locked=True)
            )

        # Raise a security alert for high-severity emergencies.
        if event_type in _CRITICAL_TYPES:
            self.db.add(SecurityAlert(
                id=uuid.uuid4(), alert_type=AlertType.anomaly, severity=AlertSeverity.critical,
                status=AlertStatus.open,
                title=f"EMERGENCY: {event_type.value.upper()}",
                description=message or f"{event_type.value} triggered",
                source_ref=f"emergency:{event.id}",
            ))

        # Fan out notifications: org channels + each emergency contact.
        notifier = NotificationService(self.db, audit=self.audit)
        subject = f"EMERGENCY: {event_type.value.upper()}"
        body = message or f"A {event_type.value} emergency was triggered."
        count = await notifier.fan_out(
            organization_id=organization_id, subject=subject, body=body,
            severity="critical", related_emergency_id=event.id,
        )
        for contact in await self.list_contacts(organization_id=organization_id):
            target = contact.phone or contact.email
            if target:
                await notifier.dispatch(
                    organization_id=organization_id,
                    channel=contact.channel or NotificationChannel.sms,
                    target=target, subject=subject, body=body,
                    related_emergency_id=event.id,
                )
                count += 1

        event.notified_count = count
        await self.db.flush()
        await self._audit(f"trigger:{event_type}", str(event.id), actor_id,
                          {"notified": count, "site_id": str(site_id) if site_id else None})
        return event

    async def acknowledge(self, event_id: uuid.UUID, *, actor_id: uuid.UUID | None = None,
                          ) -> EmergencyEvent:
        event = await self.get_or_404(event_id)
        event.status = EmergencyStatus.acknowledged
        await self.db.flush()
        await self._audit("acknowledge", str(event.id), actor_id)
        return event

    async def resolve(self, event_id: uuid.UUID, *, actor_id: uuid.UUID | None = None,
                      unlock: bool = True) -> EmergencyEvent:
        event = await self.get_or_404(event_id)
        event.status = EmergencyStatus.resolved
        event.resolved_at = _now()
        if unlock and event.event_type == EmergencyType.lockdown and event.site_id:
            await self.db.execute(
                update(AccessPoint).where(AccessPoint.site_id == event.site_id)
                .values(is_locked=False)
            )
        await self.db.flush()
        await self._audit("resolve", str(event.id), actor_id)
        return event
