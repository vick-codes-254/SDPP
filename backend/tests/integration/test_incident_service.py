"""Incident Management service tests."""

from __future__ import annotations

import io
import os
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest
import pytest_asyncio
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import (
    AlertSeverity,
    AlertStatus,
    AlertType,
    FileCategory,
    IncidentSeverity,
    IncidentStatus,
)
from app.core.kms.local import LocalMasterKeyProvider
from app.models.audit import SecurityAlert
from app.models.user import User
from app.services.incident_service import IncidentService
from app.services.key_service import KeyService
from app.services.storage import LocalFileSystemStorage
from app.services.vault_service import VaultService

pytestmark = pytest.mark.integration


@pytest_asyncio.fixture
async def reporter(async_session: AsyncSession) -> uuid.UUID:
    user = User(
        id=uuid.uuid4(), username="ir-lead", email="ir@example.com", email_bidx="ir@example.com",
        hashed_password="x", is_active=True, password_changed_at=datetime.now(UTC), roles=[],
    )
    async_session.add(user)
    await async_session.flush()
    return user.id


class TestIncidentLifecycle:
    async def test_create_with_timeline_and_encrypted_description(
        self, async_session: AsyncSession, reporter: uuid.UUID
    ) -> None:
        svc = IncidentService(async_session)
        inc = await svc.create(
            title="Suspicious exfiltration", description="Sensitive notes about the breach",
            severity=IncidentSeverity.high, reporter_id=reporter,
        )
        assert inc.status is IncidentStatus.open
        timeline = await svc.timeline(inc.id)
        assert len(timeline) == 1 and timeline[0].note_type == "system"

        raw = (await async_session.execute(text("SELECT description FROM incidents"))).first()[0]
        assert "Sensitive notes" not in raw  # encrypted at rest

    async def test_comment_assign_resolve(
        self, async_session: AsyncSession, reporter: uuid.UUID
    ) -> None:
        svc = IncidentService(async_session)
        inc = await svc.create(title="t", reporter_id=reporter)
        await svc.add_comment(inc.id, "Investigating logs", author_id=reporter)
        await svc.assign(inc.id, reporter, actor_id=reporter)
        resolved = await svc.transition(
            inc.id, IncidentStatus.resolved, actor_id=reporter, resolution="Patched and rotated keys"
        )
        assert resolved.status is IncidentStatus.resolved
        assert resolved.resolved_at is not None
        # timeline: created + comment + assignment + status_change
        assert len(await svc.timeline(inc.id)) == 4

    async def test_link_alert(self, async_session: AsyncSession) -> None:
        alert = SecurityAlert(
            id=uuid.uuid4(), alert_type=AlertType.vulnerability, severity=AlertSeverity.high,
            status=AlertStatus.open, title="High vuln",
        )
        async_session.add(alert)
        await async_session.flush()

        svc = IncidentService(async_session)
        inc = await svc.create(title="from-alert", alert_ids=[alert.id])
        assert len(inc.alerts) == 1
        # linking again is idempotent
        await svc.link_alert(inc.id, alert.id)
        refreshed = await svc.get(inc.id)
        assert len(refreshed.alerts) == 1


class TestEvidence:
    async def test_attach_encrypted_vault_evidence(
        self, async_session: AsyncSession, reporter: uuid.UUID, tmp_path: Path
    ) -> None:
        # Upload a real encrypted file into the vault, then attach it as evidence.
        vault = VaultService(
            async_session,
            storage=LocalFileSystemStorage(tmp_path / "vault"),
            key_service=KeyService(async_session, provider=LocalMasterKeyProvider(os.urandom(32))),
        )
        up = await vault.upload(
            owner_id=reporter, filename="capture.pcap", content_type="application/octet-stream",
            category=FileCategory.evidence, source=io.BytesIO(b"packet capture bytes"),
        )

        svc = IncidentService(async_session)
        inc = await svc.create(title="net intrusion", reporter_id=reporter)
        await svc.attach_evidence(inc.id, up.file.id, actor_id=reporter)

        refreshed = await svc.get(inc.id)
        assert len(refreshed.evidence) == 1
        assert refreshed.evidence[0].original_filename == "capture.pcap"
        assert any(n.note_type == "evidence" for n in await svc.timeline(inc.id))
