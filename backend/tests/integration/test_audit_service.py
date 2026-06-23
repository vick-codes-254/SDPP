"""Audit service: hash-chain integrity & tamper detection."""

from __future__ import annotations

import pytest
from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security.audit_chain import GENESIS_HASH, compute_entry_hash
from app.models.audit import AuditLog
from app.models.enums import AuditEventType, AuditOutcome
from app.services.audit_service import AuditService

pytestmark = pytest.mark.integration


async def _seed(svc: AuditService, n: int = 5) -> None:
    for i in range(n):
        await svc.record(
            event_type=AuditEventType.login,
            outcome=AuditOutcome.success,
            actor_label=f"user{i}",
            action="login",
            detail={"i": i},
        )


class TestChaining:
    async def test_first_entry_chains_from_genesis(self, async_session: AsyncSession) -> None:
        svc = AuditService(async_session)
        entry = await svc.record(
            event_type=AuditEventType.login, outcome=AuditOutcome.success, actor_label="a"
        )
        assert entry.prev_hash == GENESIS_HASH
        assert len(entry.entry_hash) == 64

    async def test_entries_link_together(self, async_session: AsyncSession) -> None:
        svc = AuditService(async_session)
        e1 = await svc.record(event_type=AuditEventType.login, outcome=AuditOutcome.success)
        e2 = await svc.record(event_type=AuditEventType.logout, outcome=AuditOutcome.success)
        assert e2.prev_hash == e1.entry_hash
        assert e2.seq > e1.seq


class TestVerification:
    async def test_intact_chain_verifies(self, async_session: AsyncSession) -> None:
        svc = AuditService(async_session)
        await _seed(svc, 6)
        await async_session.commit()
        result = await svc.verify_chain()
        assert result.ok
        assert result.entries_checked == 6

    async def test_empty_chain_verifies(self, async_session: AsyncSession) -> None:
        result = await AuditService(async_session).verify_chain()
        assert result.ok
        assert result.entries_checked == 0

    async def test_content_tampering_detected(self, async_session: AsyncSession) -> None:
        svc = AuditService(async_session)
        await _seed(svc, 4)
        await async_session.commit()

        # Simulate an attacker editing a historical row's content in place
        # (bypassing the service; the PG trigger would block this in prod).
        await async_session.execute(
            update(AuditLog)
            .where(AuditLog.seq == 2)
            .values(actor_label="attacker-modified")
        )
        await async_session.commit()

        result = await svc.verify_chain()
        assert not result.ok
        assert result.first_broken_seq == 2
        assert "tampered" in result.detail

    async def test_hash_recompute_is_deterministic(self) -> None:
        kwargs = dict(
            event_type="login", outcome="success", actor_id=None, actor_label="x",
            resource_type=None, resource_id=None, action="login", ip_address=None,
            user_agent=None, detail={"a": 1}, created_at="2026-01-01T00:00:00+00:00",
            prev_hash=GENESIS_HASH,
        )
        assert compute_entry_hash(**kwargs) == compute_entry_hash(**kwargs)
