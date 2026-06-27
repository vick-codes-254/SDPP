"""Incident management service.

Create/triage incidents, maintain an encrypted timeline, link alerts and affected
assets, and attach encrypted evidence files from the SDPP vault. Status changes
and assignments are recorded both as timeline notes and in the audit log.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.enums import (
    AuditEventType,
    AuditOutcome,
    IncidentSeverity,
    IncidentStatus,
)
from app.models.asset import Asset
from app.models.audit import SecurityAlert
from app.models.file import File
from app.models.incident import Incident, IncidentNote
from app.services.audit_service import AuditService
from app.services.exceptions import NotFoundError

_CLOSED_STATES = {IncidentStatus.resolved, IncidentStatus.closed}

# SLA target (time-to-resolve, hours) by severity.
_SLA_HOURS = {
    IncidentSeverity.critical: 1,
    IncidentSeverity.high: 4,
    IncidentSeverity.medium: 24,
    IncidentSeverity.low: 72,
}


class IncidentService:
    def __init__(self, db: AsyncSession, *, audit: AuditService | None = None) -> None:
        self.db = db
        self.audit = audit or AuditService(db)

    async def _add_note(
        self, incident_id: uuid.UUID, body: str, *, note_type: str = "comment",
        author_id: uuid.UUID | None = None,
    ) -> IncidentNote:
        note = IncidentNote(
            id=uuid.uuid4(), incident_id=incident_id, author_id=author_id,
            note_type=note_type, body=body, created_at=datetime.now(UTC),
        )
        self.db.add(note)
        return note

    # ── Reads ───────────────────────────────────────────────────
    async def get(self, incident_id: uuid.UUID) -> Incident | None:
        return (
            await self.db.execute(
                select(Incident).where(Incident.id == incident_id).options(
                    selectinload(Incident.notes)
                )
            )
        ).scalar_one_or_none()

    async def get_or_404(self, incident_id: uuid.UUID) -> Incident:
        inc = await self.get(incident_id)
        if inc is None:
            raise NotFoundError("Incident not found")
        return inc

    async def list(
        self,
        *,
        status: IncidentStatus | None = None,
        severity: IncidentSeverity | None = None,
        assignee_id: uuid.UUID | None = None,
        limit: int = 100,
    ) -> list[Incident]:
        stmt = select(Incident).order_by(Incident.created_at.desc())
        if status:
            stmt = stmt.where(Incident.status == status)
        if severity:
            stmt = stmt.where(Incident.severity == severity)
        if assignee_id:
            stmt = stmt.where(Incident.assignee_id == assignee_id)
        return list((await self.db.execute(stmt.limit(limit))).scalars().all())

    async def timeline(self, incident_id: uuid.UUID) -> list[IncidentNote]:
        return list(
            (
                await self.db.execute(
                    select(IncidentNote).where(IncidentNote.incident_id == incident_id)
                    .order_by(IncidentNote.created_at)
                )
            ).scalars().all()
        )

    # ── Writes ──────────────────────────────────────────────────
    async def create(
        self,
        *,
        title: str,
        description: str | None = None,
        severity: IncidentSeverity = IncidentSeverity.medium,
        reporter_id: uuid.UUID | None = None,
        organization_id: uuid.UUID | None = None,
        alert_ids: list[uuid.UUID] | None = None,
        asset_ids: list[uuid.UUID] | None = None,
    ) -> Incident:
        incident = Incident(
            id=uuid.uuid4(), title=title, description=description, severity=severity,
            status=IncidentStatus.open, reporter_id=reporter_id,
            organization_id=organization_id,
            sla_due_at=datetime.now(UTC) + timedelta(hours=_SLA_HOURS.get(severity, 24)),
        )
        if alert_ids:
            incident.alerts = list(
                (await self.db.execute(
                    select(SecurityAlert).where(SecurityAlert.id.in_(alert_ids))
                )).scalars().all()
            )
        if asset_ids:
            incident.assets = list(
                (await self.db.execute(select(Asset).where(Asset.id.in_(asset_ids)))).scalars().all()
            )
        self.db.add(incident)
        await self.db.flush()
        await self._add_note(
            incident.id, f"Incident created (severity {severity.value}).",
            note_type="system", author_id=reporter_id,
        )
        await self.audit.record(
            event_type=AuditEventType.incident_created, outcome=AuditOutcome.success,
            actor_id=reporter_id, resource_type="incident", resource_id=str(incident.id),
            action="create", detail={"severity": severity.value},
        )
        await self.db.flush()
        return incident

    async def add_comment(
        self, incident_id: uuid.UUID, body: str, *, author_id: uuid.UUID | None = None
    ) -> IncidentNote:
        await self.get_or_404(incident_id)
        note = await self._add_note(incident_id, body, note_type="comment", author_id=author_id)
        await self.db.flush()
        return note

    async def assign(
        self, incident_id: uuid.UUID, assignee_id: uuid.UUID, *, actor_id: uuid.UUID | None = None
    ) -> Incident:
        incident = await self.get_or_404(incident_id)
        incident.assignee_id = assignee_id
        await self._add_note(
            incident_id, f"Assigned to {assignee_id}.", note_type="assignment", author_id=actor_id
        )
        await self.audit.record(
            event_type=AuditEventType.incident_updated, outcome=AuditOutcome.success,
            actor_id=actor_id, resource_type="incident", resource_id=str(incident_id),
            action="assign",
        )
        await self.db.flush()
        return incident

    async def acknowledge(
        self, incident_id: uuid.UUID, *, actor_id: uuid.UUID | None = None
    ) -> Incident:
        incident = await self.get_or_404(incident_id)
        if incident.acknowledged_at is None:
            incident.acknowledged_at = datetime.now(UTC)
            await self._add_note(
                incident_id, "Incident acknowledged.", note_type="system", author_id=actor_id
            )
            await self.audit.record(
                event_type=AuditEventType.incident_updated, outcome=AuditOutcome.success,
                actor_id=actor_id, resource_type="incident", resource_id=str(incident_id),
                action="acknowledge",
            )
        await self.db.flush()
        return incident

    async def transition(
        self,
        incident_id: uuid.UUID,
        status: IncidentStatus,
        *,
        actor_id: uuid.UUID | None = None,
        resolution: str | None = None,
    ) -> Incident:
        incident = await self.get_or_404(incident_id)
        previous = incident.status
        incident.status = status
        if status in _CLOSED_STATES:
            incident.resolved_at = datetime.now(UTC)
            if resolution:
                incident.resolution = resolution
        await self._add_note(
            incident_id, f"Status changed {previous.value} -> {status.value}.",
            note_type="status_change", author_id=actor_id,
        )
        await self.audit.record(
            event_type=AuditEventType.incident_updated, outcome=AuditOutcome.success,
            actor_id=actor_id, resource_type="incident", resource_id=str(incident_id),
            action="status_change", detail={"from": previous.value, "to": status.value},
        )
        await self.db.flush()
        return incident

    async def link_alert(self, incident_id: uuid.UUID, alert_id: uuid.UUID) -> Incident:
        incident = await self.get_or_404(incident_id)
        alert = (
            await self.db.execute(select(SecurityAlert).where(SecurityAlert.id == alert_id))
        ).scalar_one_or_none()
        if alert is None:
            raise NotFoundError("Alert not found")
        if alert not in incident.alerts:
            incident.alerts.append(alert)
            await self._add_note(incident_id, f"Linked alert {alert_id}.", note_type="system")
        await self.db.flush()
        return incident

    async def attach_evidence(
        self, incident_id: uuid.UUID, file_id: uuid.UUID, *, actor_id: uuid.UUID | None = None
    ) -> Incident:
        """Attach an already-encrypted vault file as incident evidence."""
        incident = await self.get_or_404(incident_id)
        file = (
            await self.db.execute(select(File).where(File.id == file_id))
        ).scalar_one_or_none()
        if file is None:
            raise NotFoundError("Evidence file not found")
        if file not in incident.evidence:
            incident.evidence.append(file)
            await self._add_note(
                incident_id, f"Attached encrypted evidence '{file.original_filename}'.",
                note_type="evidence", author_id=actor_id,
            )
        await self.db.flush()
        return incident
