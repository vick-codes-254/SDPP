"""Evidence management with an append-only chain of custody."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import select

from app.core.enums import CustodyAction, EvidenceStatus, EvidenceType
from app.models.evidence import CustodyEntry, Evidence
from app.services.crud import CrudService


def _now() -> datetime:
    return datetime.now(UTC)


class EvidenceService(CrudService[Evidence]):
    model = Evidence
    audit_resource = "evidence"

    async def register(
        self,
        *,
        organization_id: uuid.UUID,
        title: str,
        evidence_type: EvidenceType = EvidenceType.other,
        incident_id: uuid.UUID | None = None,
        file_id: uuid.UUID | None = None,
        sha256: str | None = None,
        source: str | None = None,
        description: str | None = None,
        tags: list[str] | None = None,
        actor_id: uuid.UUID | None = None,
    ) -> Evidence:
        now = _now()
        evidence = Evidence(
            id=uuid.uuid4(), organization_id=organization_id, title=title,
            evidence_type=evidence_type, status=EvidenceStatus.collected,
            incident_id=incident_id, file_id=file_id, sha256=sha256, source=source,
            description=description, tags=tags or [], collected_by=actor_id,
            collected_at=now,
        )
        self.db.add(evidence)
        await self.db.flush()
        # First link in the custody chain.
        self.db.add(CustodyEntry(
            id=uuid.uuid4(), evidence_id=evidence.id, action=CustodyAction.collected,
            actor_id=actor_id, notes=source, occurred_at=now,
        ))
        await self.db.flush()
        await self._audit("register", str(evidence.id), actor_id, {"type": str(evidence_type)})
        return evidence

    async def log_custody(
        self,
        evidence_id: uuid.UUID,
        *,
        action: CustodyAction,
        actor_id: uuid.UUID | None = None,
        from_party: str | None = None,
        to_party: str | None = None,
        notes: str | None = None,
    ) -> CustodyEntry:
        evidence = await self.get_or_404(evidence_id)
        entry = CustodyEntry(
            id=uuid.uuid4(), evidence_id=evidence.id, action=action, actor_id=actor_id,
            from_party=from_party, to_party=to_party, notes=notes, occurred_at=_now(),
        )
        self.db.add(entry)
        # Keep evidence status in sync with terminal custody actions.
        if action == CustodyAction.sealed:
            evidence.status = EvidenceStatus.sealed
        elif action == CustodyAction.released:
            evidence.status = EvidenceStatus.released
        elif action == CustodyAction.destroyed:
            evidence.status = EvidenceStatus.destroyed
        await self.db.flush()
        await self._audit(f"custody:{action}", str(evidence.id), actor_id)
        return entry

    async def chain(self, evidence_id: uuid.UUID) -> list[CustodyEntry]:
        return list((await self.db.execute(
            select(CustodyEntry).where(CustodyEntry.evidence_id == evidence_id)
            .order_by(CustodyEntry.occurred_at)
        )).scalars().all())
