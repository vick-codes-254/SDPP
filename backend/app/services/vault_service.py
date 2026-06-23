"""Secure File Vault service.

Implements the platform's primary workflow:

    upload → generate DEK → AES-256-GCM encrypt → wrap DEK → store blob →
    record SHA-256 (plaintext + ciphertext) → audit

and the inverse for download (verify integrity *before* decrypt). Also handles
secure (crypto-shred) deletion, soft delete + restore, and on-demand integrity
verification with automatic quarantine + alerting on tamper.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass
from typing import BinaryIO

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.config import Settings, get_settings
from app.core.security.crypto import DEFAULT_CHUNK_SIZE
from app.core.security.hashing import hash_stream
from app.models.enums import (
    AlertSeverity,
    AlertType,
    AuditEventType,
    AuditOutcome,
    FileCategory,
    FileStatus,
    IntegrityResult,
    IntegrityTarget,
)
from app.models.audit import SecurityAlert
from app.models.file import EncryptedFile, File, IntegrityCheck
from app.services.audit_service import AuditService
from app.services.exceptions import IntegrityViolationError, NotFoundError, ValidationError
from app.services.key_service import KeyService
from app.services.storage import VaultStorage, get_default_storage


class _HashingWriter:
    """Wrap a writable stream, computing SHA-256 of everything written."""

    def __init__(self, fileobj: BinaryIO) -> None:
        self._f = fileobj
        self._h = hashlib.sha256()

    def write(self, data: bytes) -> int:
        self._h.update(data)
        return self._f.write(data)

    def hexdigest(self) -> str:
        return self._h.hexdigest()


@dataclass(frozen=True, slots=True)
class UploadResult:
    file: File
    encrypted: EncryptedFile


class VaultService:
    def __init__(
        self,
        db: AsyncSession,
        *,
        storage: VaultStorage | None = None,
        key_service: KeyService | None = None,
        audit: AuditService | None = None,
        settings: Settings | None = None,
    ) -> None:
        self.db = db
        self.settings = settings or get_settings()
        self.storage = storage or get_default_storage()
        self.keys = key_service or KeyService(db, audit=audit)
        self.audit = audit or self.keys.audit
        self.envelope = self.keys.envelope

    # ── Upload → encrypt → store ────────────────────────────────
    async def upload(
        self,
        *,
        owner_id: uuid.UUID,
        filename: str,
        content_type: str,
        category: FileCategory,
        source: BinaryIO,
        description: str | None = None,
        ip_address: str | None = None,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
    ) -> UploadResult:
        file = File(
            id=uuid.uuid4(),
            owner_id=owner_id,
            original_filename=filename,
            content_type=content_type,
            category=category,
            description=description,
            status=FileStatus.uploaded,
        )
        self.db.add(file)
        await self.db.flush()  # assign file.id (used as AEAD associated data)

        aad = file.id.bytes
        storage_key = self.storage.new_key()
        writer = self.storage.open_write(storage_key)
        hashing_writer = _HashingWriter(writer)
        try:
            meta = self.envelope.encrypt_file(
                source, hashing_writer, aad=aad, chunk_size=chunk_size
            )
        finally:
            writer.close()
        ciphertext_sha256 = hashing_writer.hexdigest()

        key_record = await self.keys.persist_wrapped_dek(meta.wrapped_dek, actor_id=owner_id)

        encrypted = EncryptedFile(
            id=uuid.uuid4(),
            file_id=file.id,
            storage_key=storage_key,
            algorithm=meta.algorithm,
            chunk_size=chunk_size,
            ciphertext_size=meta.ciphertext_size,
            encryption_key_id=key_record.id,
            ciphertext_sha256=ciphertext_sha256,
        )
        self.db.add(encrypted)

        file.size_bytes = meta.plaintext_size
        file.plaintext_sha256 = meta.plaintext_sha256
        file.status = FileStatus.available

        self.db.add(
            IntegrityCheck(
                id=uuid.uuid4(), file_id=file.id, target=IntegrityTarget.ciphertext,
                expected_sha256=ciphertext_sha256, actual_sha256=ciphertext_sha256,
                result=IntegrityResult.passed, checked_by=owner_id,
            )
        )
        await self.audit.record(
            event_type=AuditEventType.upload, outcome=AuditOutcome.success,
            actor_id=owner_id, resource_type="file", resource_id=str(file.id),
            action="upload_encrypt", ip_address=ip_address,
            detail={"category": str(category), "size": meta.plaintext_size, "chunks": meta.chunks},
        )
        await self.db.flush()
        return UploadResult(file=file, encrypted=encrypted)

    # ── Retrieve → verify → decrypt ─────────────────────────────
    async def _load(self, file_id: uuid.UUID, *, include_deleted: bool = False) -> File:
        file = (
            await self.db.execute(
                select(File).where(File.id == file_id).options(selectinload(File.encrypted))
            )
        ).scalar_one_or_none()
        if file is None:
            raise NotFoundError("File not found")
        if file.status is FileStatus.deleted and not include_deleted:
            raise NotFoundError("File not found")
        return file

    async def download(
        self,
        *,
        file_id: uuid.UUID,
        dest: BinaryIO,
        requester_id: uuid.UUID | None = None,
        ip_address: str | None = None,
    ) -> File:
        file = await self._load(file_id)
        encrypted = file.encrypted
        if encrypted is None:
            raise NotFoundError("Encrypted blob not found")

        # Verify ciphertext integrity BEFORE decryption (tamper/bit-rot detection).
        await self._verify_ciphertext(file, encrypted, requester_id, ip_address)

        key_record = await self.keys.get_key(encrypted.encryption_key_id)
        if key_record is None or not key_record.wrapped_key:
            raise NotFoundError("Encryption key unavailable (revoked or destroyed)")

        wrapped = self.keys.load_wrapped(key_record)
        with self.storage.open_read(encrypted.storage_key) as fh:
            self.envelope.decrypt_file(wrapped, fh, dest, aad=file.id.bytes)

        await self.audit.record(
            event_type=AuditEventType.download, outcome=AuditOutcome.success,
            actor_id=requester_id, resource_type="file", resource_id=str(file.id),
            action="download_decrypt", ip_address=ip_address,
        )
        await self.db.flush()
        return file

    # ── Integrity verification ──────────────────────────────────
    async def verify_integrity(
        self, file_id: uuid.UUID, *, requester_id: uuid.UUID | None = None
    ) -> IntegrityCheck:
        file = await self._load(file_id, include_deleted=True)
        if file.encrypted is None:
            raise NotFoundError("Encrypted blob not found")
        return await self._verify_ciphertext(file, file.encrypted, requester_id, None)

    async def _verify_ciphertext(
        self,
        file: File,
        encrypted: EncryptedFile,
        requester_id: uuid.UUID | None,
        ip_address: str | None,
    ) -> IntegrityCheck:
        if not self.storage.exists(encrypted.storage_key):
            actual = None
            result = IntegrityResult.error
        else:
            with self.storage.open_read(encrypted.storage_key) as fh:
                actual = hash_stream(fh)
            result = (
                IntegrityResult.passed
                if actual == encrypted.ciphertext_sha256
                else IntegrityResult.failed
            )

        check = IntegrityCheck(
            id=uuid.uuid4(), file_id=file.id, target=IntegrityTarget.ciphertext,
            expected_sha256=encrypted.ciphertext_sha256, actual_sha256=actual,
            result=result, checked_by=requester_id,
            detail=None if result is IntegrityResult.passed else "ciphertext digest mismatch",
        )
        self.db.add(check)

        if result is not IntegrityResult.passed:
            file.status = FileStatus.quarantined
            self.db.add(
                SecurityAlert(
                    id=uuid.uuid4(),
                    alert_type=AlertType.integrity_violation,
                    severity=AlertSeverity.critical,
                    title=f"Integrity violation on file {file.id}",
                    description="Stored ciphertext SHA-256 does not match the recorded value; "
                    "possible tampering or corruption. File quarantined.",
                    source_ip=ip_address,
                    related_file_id=file.id,
                    related_user_id=requester_id,
                )
            )
            await self.audit.record(
                event_type=AuditEventType.integrity_violation, outcome=AuditOutcome.failure,
                actor_id=requester_id, resource_type="file", resource_id=str(file.id),
                action="verify_integrity", ip_address=ip_address,
                detail={"expected": encrypted.ciphertext_sha256, "actual": actual},
            )
            await self.db.flush()
            raise IntegrityViolationError(
                f"Integrity check failed for file {file.id}; access blocked and quarantined"
            )

        await self.audit.record(
            event_type=AuditEventType.integrity_check, outcome=AuditOutcome.success,
            actor_id=requester_id, resource_type="file", resource_id=str(file.id),
            action="verify_integrity",
        )
        await self.db.flush()
        return check

    # ── Delete / restore ────────────────────────────────────────
    async def soft_delete(
        self, file_id: uuid.UUID, *, actor_id: uuid.UUID | None = None
    ) -> None:
        from datetime import UTC, datetime

        file = await self._load(file_id)
        file.status = FileStatus.deleted
        file.deleted_at = datetime.now(UTC)
        await self.audit.record(
            event_type=AuditEventType.delete, outcome=AuditOutcome.success,
            actor_id=actor_id, resource_type="file", resource_id=str(file.id),
            action="soft_delete",
        )
        await self.db.flush()

    async def restore(self, file_id: uuid.UUID, *, actor_id: uuid.UUID | None = None) -> File:
        file = await self._load(file_id, include_deleted=True)
        if file.status is not FileStatus.deleted:
            raise ValidationError("Only soft-deleted files can be restored")
        if file.encrypted is None or not self.storage.exists(file.encrypted.storage_key):
            raise ValidationError("Underlying ciphertext is gone; file cannot be restored")
        file.status = FileStatus.available
        file.deleted_at = None
        await self.audit.record(
            event_type=AuditEventType.restore, outcome=AuditOutcome.success,
            actor_id=actor_id, resource_type="file", resource_id=str(file.id),
            action="restore",
        )
        await self.db.flush()
        return file

    async def secure_delete(
        self, file_id: uuid.UUID, *, actor_id: uuid.UUID | None = None
    ) -> None:
        """Crypto-shred: destroy the DEK and the ciphertext blob (irreversible)."""
        from datetime import UTC, datetime

        file = await self._load(file_id, include_deleted=True)
        if file.encrypted is not None:
            key_record = await self.keys.get_key(file.encrypted.encryption_key_id)
            if key_record is not None:
                await self.keys.destroy(key_record, reason="secure file delete", actor_id=actor_id)
            self.storage.delete(file.encrypted.storage_key)

        file.status = FileStatus.deleted
        file.deleted_at = datetime.now(UTC)
        await self.audit.record(
            event_type=AuditEventType.delete, outcome=AuditOutcome.success,
            actor_id=actor_id, resource_type="file", resource_id=str(file.id),
            action="secure_delete_crypto_shred",
        )
        await self.db.flush()
