"""Secure File Vault integration tests."""

from __future__ import annotations

import io
import os
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.kms.local import LocalMasterKeyProvider
from app.models.audit import SecurityAlert
from app.models.enums import AlertType, FileCategory, FileStatus
from app.models.user import User
from app.services.exceptions import IntegrityViolationError, NotFoundError
from app.services.key_service import KeyService
from app.services.storage import LocalFileSystemStorage
from app.services.vault_service import VaultService

pytestmark = pytest.mark.integration


@pytest_asyncio.fixture
async def owner_id(async_session: AsyncSession) -> uuid.UUID:
    user = User(
        id=uuid.uuid4(), username="owner", email="owner@example.com",
        email_bidx="owner@example.com", hashed_password="x", is_active=True,
        password_changed_at=datetime.now(UTC), roles=[],
    )
    async_session.add(user)
    await async_session.flush()
    return user.id


@pytest_asyncio.fixture
def vault(async_session: AsyncSession, tmp_path: Path) -> VaultService:
    provider = LocalMasterKeyProvider(os.urandom(32))
    keys = KeyService(async_session, provider=provider)
    storage = LocalFileSystemStorage(tmp_path / "vault")
    return VaultService(async_session, storage=storage, key_service=keys)


async def _upload(vault: VaultService, owner_id: uuid.UUID, data: bytes, name: str = "f.bin"):
    return await vault.upload(
        owner_id=owner_id, filename=name, content_type="application/octet-stream",
        category=FileCategory.evidence, source=io.BytesIO(data),
        description="sensitive evidence", chunk_size=64 * 1024,
    )


class TestUploadDownload:
    @pytest.mark.parametrize("size", [0, 1, 1024, 200_000, 1_500_000])
    async def test_round_trip(self, vault: VaultService, owner_id: uuid.UUID, size: int) -> None:
        data = os.urandom(size)
        result = await _upload(vault, owner_id, data, "evidence.mp4")
        assert result.file.status is FileStatus.available
        assert result.file.size_bytes == size

        out = io.BytesIO()
        await vault.download(file_id=result.file.id, dest=out, requester_id=owner_id)
        assert out.getvalue() == data

    async def test_blob_on_disk_is_ciphertext(
        self, vault: VaultService, owner_id: uuid.UUID
    ) -> None:
        secret = b"PLAINTEXT-NEEDLE-should-not-appear" * 100
        result = await _upload(vault, owner_id, secret)
        blob_path = vault.storage._path(result.encrypted.storage_key)  # type: ignore[attr-defined]
        raw = blob_path.read_bytes()
        assert b"PLAINTEXT-NEEDLE" not in raw
        assert raw[:4] == b"SDPP"  # streaming AEAD header

    async def test_metadata_filename_encrypted(
        self, vault: VaultService, owner_id: uuid.UUID, async_session: AsyncSession
    ) -> None:
        from sqlalchemy import text

        await _upload(vault, owner_id, b"data", name="top-secret-name.pdf")
        raw = (
            await async_session.execute(text("SELECT original_filename FROM files"))
        ).first()[0]
        assert "top-secret-name" not in raw


class TestIntegrity:
    async def test_verify_passes_for_intact_file(
        self, vault: VaultService, owner_id: uuid.UUID
    ) -> None:
        result = await _upload(vault, owner_id, b"intact data" * 1000)
        check = await vault.verify_integrity(result.file.id, requester_id=owner_id)
        assert check.result.value == "passed"

    async def test_tamper_detected_and_quarantined(
        self, vault: VaultService, owner_id: uuid.UUID, async_session: AsyncSession
    ) -> None:
        result = await _upload(vault, owner_id, b"Q" * 5000)
        blob_path = vault.storage._path(result.encrypted.storage_key)  # type: ignore[attr-defined]
        blob = bytearray(blob_path.read_bytes())
        blob[-1] ^= 0x01  # corrupt the stored ciphertext
        blob_path.write_bytes(bytes(blob))

        # download must block on integrity failure
        with pytest.raises(IntegrityViolationError):
            await vault.download(file_id=result.file.id, dest=io.BytesIO(), requester_id=owner_id)

        # file is quarantined and a critical alert was raised
        await async_session.refresh(result.file)
        assert result.file.status is FileStatus.quarantined
        alerts = (
            await async_session.execute(
                select(SecurityAlert).where(SecurityAlert.related_file_id == result.file.id)
            )
        ).scalars().all()
        assert any(a.alert_type is AlertType.integrity_violation for a in alerts)


class TestDeletion:
    async def test_soft_delete_then_restore(
        self, vault: VaultService, owner_id: uuid.UUID
    ) -> None:
        result = await _upload(vault, owner_id, b"restorable data")
        await vault.soft_delete(result.file.id, actor_id=owner_id)
        with pytest.raises(NotFoundError):
            await vault.download(file_id=result.file.id, dest=io.BytesIO())
        await vault.restore(result.file.id, actor_id=owner_id)
        out = io.BytesIO()
        await vault.download(file_id=result.file.id, dest=out, requester_id=owner_id)
        assert out.getvalue() == b"restorable data"

    async def test_secure_delete_crypto_shred(
        self, vault: VaultService, owner_id: uuid.UUID
    ) -> None:
        result = await _upload(vault, owner_id, b"destroy me forever")
        storage_key = result.encrypted.storage_key
        await vault.secure_delete(result.file.id, actor_id=owner_id)
        # DEK destroyed and blob removed -> unrecoverable.
        assert not vault.storage.exists(storage_key)
        with pytest.raises(NotFoundError):
            await vault.download(file_id=result.file.id, dest=io.BytesIO())
