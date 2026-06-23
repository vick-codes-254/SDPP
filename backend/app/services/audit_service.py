"""Audit logging service — append-only, hash-chained, tamper-evident.

Every security-relevant action is recorded here. Entries are linked into a
SHA-256 hash chain (see :mod:`app.core.security.audit_chain`) so any tampering is
detectable. The PostgreSQL deployment additionally blocks UPDATE/DELETE via a
trigger (migration ``audit0001``).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security.audit_chain import GENESIS_HASH, compute_entry_hash
from app.models.audit import AuditLog
from app.models.enums import AuditEventType, AuditOutcome

# Stable key for the PostgreSQL advisory lock that serializes chain writers.
_AUDIT_LOCK_KEY = 0x5D99_4170  # "SDPP AUD" mnemonic


@dataclass(frozen=True, slots=True)
class ChainVerification:
    ok: bool
    entries_checked: int
    first_broken_seq: int | None = None
    detail: str = "chain intact"


class AuditService:
    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    @property
    def _is_postgres(self) -> bool:
        bind = self.db.get_bind()
        return bind.dialect.name == "postgresql"

    async def _last_hash(self) -> str:
        result = await self.db.execute(
            select(AuditLog.entry_hash).order_by(AuditLog.seq.desc()).limit(1)
        )
        return result.scalar_one_or_none() or GENESIS_HASH

    async def record(
        self,
        *,
        event_type: AuditEventType,
        outcome: AuditOutcome,
        actor_id: uuid.UUID | None = None,
        actor_label: str | None = None,
        resource_type: str | None = None,
        resource_id: str | None = None,
        action: str | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
        detail: dict[str, Any] | None = None,
    ) -> AuditLog:
        """Append a new audit entry, chained to the latest one.

        Flushes (so ``seq``/``entry_hash`` are assigned) but does not commit —
        the surrounding request transaction owns the commit, keeping the audit
        write atomic with the action it records.
        """
        # Serialize chain writers under concurrency (no-op on SQLite).
        if self._is_postgres:
            await self.db.execute(
                text("SELECT pg_advisory_xact_lock(:k)"), {"k": _AUDIT_LOCK_KEY}
            )

        created_at = datetime.now(UTC)
        prev_hash = await self._last_hash()
        entry_hash = compute_entry_hash(
            event_type=str(event_type),
            outcome=str(outcome),
            actor_id=str(actor_id) if actor_id else None,
            actor_label=actor_label,
            resource_type=resource_type,
            resource_id=resource_id,
            action=action,
            ip_address=ip_address,
            user_agent=user_agent,
            detail=detail,
            created_at=created_at,
            prev_hash=prev_hash,
        )
        entry = AuditLog(
            id=uuid.uuid4(),
            event_type=event_type,
            outcome=outcome,
            actor_id=actor_id,
            actor_label=actor_label,
            resource_type=resource_type,
            resource_id=resource_id,
            action=action,
            ip_address=ip_address,
            user_agent=user_agent,
            detail=detail,
            created_at=created_at,
            prev_hash=prev_hash,
            entry_hash=entry_hash,
        )
        self.db.add(entry)
        await self.db.flush()
        return entry

    async def list_entries(self, *, limit: int = 100, offset: int = 0) -> list[AuditLog]:
        result = await self.db.execute(
            select(AuditLog).order_by(AuditLog.seq.desc()).limit(limit).offset(offset)
        )
        return list(result.scalars().all())

    async def verify_chain(self) -> ChainVerification:
        """Re-walk the entire chain and detect any break (tampering)."""
        result = await self.db.execute(select(AuditLog).order_by(AuditLog.seq.asc()))
        entries = result.scalars().all()

        prev_hash = GENESIS_HASH
        for entry in entries:
            if entry.prev_hash != prev_hash:
                return ChainVerification(
                    ok=False,
                    entries_checked=entry.seq,
                    first_broken_seq=entry.seq,
                    detail=f"prev_hash mismatch at seq={entry.seq} (reorder/insert/delete)",
                )
            expected = compute_entry_hash(
                event_type=str(entry.event_type),
                outcome=str(entry.outcome),
                actor_id=str(entry.actor_id) if entry.actor_id else None,
                actor_label=entry.actor_label,
                resource_type=entry.resource_type,
                resource_id=entry.resource_id,
                action=entry.action,
                ip_address=entry.ip_address,
                user_agent=entry.user_agent,
                detail=entry.detail,
                created_at=entry.created_at,
                prev_hash=prev_hash,
            )
            if entry.entry_hash != expected:
                return ChainVerification(
                    ok=False,
                    entries_checked=entry.seq,
                    first_broken_seq=entry.seq,
                    detail=f"entry_hash mismatch at seq={entry.seq} (content tampered)",
                )
            prev_hash = entry.entry_hash

        return ChainVerification(ok=True, entries_checked=len(entries))
