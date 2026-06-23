"""Key Management Service — DEK lifecycle, field-key bootstrap, rotation, revocation.

Wraps the KMS :class:`MasterKeyProvider` with database-backed key lifecycle:
* bootstrap the process-wide field-encryption key (wrapped by the master key),
* persist wrapped per-file DEKs,
* rotate the master key by re-wrapping DEKs (no data re-encryption),
* revoke / crypto-shred keys (destroying a DEK renders its ciphertext unrecoverable).
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.kms.base import MasterKeyProvider, WrappedKey
from app.core.kms.factory import get_master_key_provider
from app.core.security.envelope import EnvelopeEncryptor
from app.core.security.exceptions import KeyManagementError
from app.core.security.field_encryption import FieldCipher, set_field_cipher
from app.models.enums import AuditEventType, AuditOutcome, KeyStatus, KeyType, RotationType
from app.models.key import EncryptionKey, KeyRotation
from app.services.audit_service import AuditService


class KeyService:
    def __init__(
        self,
        db: AsyncSession,
        *,
        provider: MasterKeyProvider | None = None,
        audit: AuditService | None = None,
    ) -> None:
        self.db = db
        self.provider = provider or get_master_key_provider()
        self.envelope = EnvelopeEncryptor(self.provider)
        self.audit = audit or AuditService(db)

    # ── Serialization helpers ───────────────────────────────────
    @staticmethod
    def serialize(wrapped: WrappedKey) -> str:
        return json.dumps(wrapped.to_dict(), separators=(",", ":"))

    @staticmethod
    def load_wrapped(record: EncryptionKey) -> WrappedKey:
        return WrappedKey.from_dict(json.loads(record.wrapped_key))

    # ── Field-encryption key bootstrap ──────────────────────────
    async def bootstrap_field_cipher(self) -> FieldCipher:
        """Ensure an active field key exists, unwrap it, and install the cipher.

        Called once at application startup. The field key is itself a DEK wrapped
        by the master key; only the wrapped form is persisted.
        """
        record = (
            await self.db.execute(
                select(EncryptionKey)
                .where(
                    EncryptionKey.key_type == KeyType.field,
                    EncryptionKey.status == KeyStatus.active,
                )
                .order_by(EncryptionKey.created_at.desc())
                .limit(1)
            )
        ).scalar_one_or_none()

        if record is not None:
            dek = self.provider.unwrap(self.load_wrapped(record))
        else:
            dek, wrapped = self.provider.generate_data_key()
            record = EncryptionKey(
                id=uuid.uuid4(),
                key_type=KeyType.field,
                purpose="database-field-encryption",
                wrapped_key=self.serialize(wrapped),
                provider=wrapped.provider,
                master_key_id=wrapped.master_key_id,
                algorithm=wrapped.algorithm,
                status=KeyStatus.active,
            )
            self.db.add(record)
            await self.db.flush()
            await self.audit.record(
                event_type=AuditEventType.key_generated,
                outcome=AuditOutcome.success,
                resource_type="encryption_key",
                resource_id=str(record.id),
                action="generate_field_key",
            )

        cipher = FieldCipher(dek)
        set_field_cipher(cipher)
        return cipher

    # ── Per-file DEK records ────────────────────────────────────
    async def persist_wrapped_dek(
        self,
        wrapped: WrappedKey,
        *,
        purpose: str = "file-encryption",
        actor_id: uuid.UUID | None = None,
    ) -> EncryptionKey:
        record = EncryptionKey(
            id=uuid.uuid4(),
            key_type=KeyType.data,
            purpose=purpose,
            wrapped_key=self.serialize(wrapped),
            provider=wrapped.provider,
            master_key_id=wrapped.master_key_id,
            algorithm=wrapped.algorithm,
            status=KeyStatus.active,
        )
        self.db.add(record)
        await self.db.flush()
        await self.audit.record(
            event_type=AuditEventType.key_generated,
            outcome=AuditOutcome.success,
            actor_id=actor_id,
            resource_type="encryption_key",
            resource_id=str(record.id),
            action="generate_dek",
        )
        return record

    async def get_key(self, key_id: uuid.UUID) -> EncryptionKey | None:
        return (
            await self.db.execute(select(EncryptionKey).where(EncryptionKey.id == key_id))
        ).scalar_one_or_none()

    async def list_keys(self, *, limit: int = 100) -> list[EncryptionKey]:
        return list(
            (
                await self.db.execute(
                    select(EncryptionKey).order_by(EncryptionKey.created_at.desc()).limit(limit)
                )
            )
            .scalars()
            .all()
        )

    # ── Master-key rotation (re-wrap, no data re-encryption) ────
    async def rotate_master_key(
        self, record: EncryptionKey, *, actor_id: uuid.UUID | None = None
    ) -> EncryptionKey:
        if record.status != KeyStatus.active:
            raise KeyManagementError("Only active keys can be rotated")

        old_master = record.master_key_id
        rewrapped = self.envelope.rewrap_dek(self.load_wrapped(record))

        record.wrapped_key = self.serialize(rewrapped)
        record.master_key_id = rewrapped.master_key_id
        record.version += 1
        record.rotated_at = datetime.now(UTC)

        self.db.add(
            KeyRotation(
                id=uuid.uuid4(),
                rotation_type=RotationType.master_key_rotation,
                old_key_id=record.id,
                new_key_id=record.id,
                old_master_key_id=old_master,
                new_master_key_id=rewrapped.master_key_id,
                reason="master key rotation",
                performed_by=actor_id,
            )
        )
        await self.audit.record(
            event_type=AuditEventType.key_rotation,
            outcome=AuditOutcome.success,
            actor_id=actor_id,
            resource_type="encryption_key",
            resource_id=str(record.id),
            action="rotate_master_key",
            detail={"old_master_key_id": old_master, "new_master_key_id": rewrapped.master_key_id},
        )
        await self.db.flush()
        return record

    # ── Revocation / crypto-shred ───────────────────────────────
    async def revoke(
        self, record: EncryptionKey, *, reason: str, actor_id: uuid.UUID | None = None
    ) -> None:
        record.status = KeyStatus.revoked
        record.revoked_at = datetime.now(UTC)
        await self.audit.record(
            event_type=AuditEventType.key_revoked,
            outcome=AuditOutcome.success,
            actor_id=actor_id,
            resource_type="encryption_key",
            resource_id=str(record.id),
            action="revoke",
            detail={"reason": reason},
        )
        await self.db.flush()

    async def destroy(
        self, record: EncryptionKey, *, reason: str, actor_id: uuid.UUID | None = None
    ) -> None:
        """Crypto-shred: irreversibly destroy the wrapped DEK.

        Once the wrapped key material is gone, the data it protected can never be
        decrypted again — a fast, guaranteed "secure delete" for encrypted blobs.
        """
        record.wrapped_key = ""  # destroy key material
        record.status = KeyStatus.destroyed
        record.revoked_at = datetime.now(UTC)
        await self.audit.record(
            event_type=AuditEventType.key_revoked,
            outcome=AuditOutcome.success,
            actor_id=actor_id,
            resource_type="encryption_key",
            resource_id=str(record.id),
            action="crypto_shred",
            detail={"reason": reason},
        )
        await self.db.flush()
