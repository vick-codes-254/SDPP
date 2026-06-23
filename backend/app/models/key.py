"""Key management models: encryption keys (wrapped DEKs) and rotation events."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Enum, ForeignKey, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin
from app.models.enums import KeyStatus, KeyType, RotationType


class EncryptionKey(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """A managed key. For DEKs, only the *wrapped* form is ever persisted.

    The wrapped key is a serialized :class:`~app.core.kms.base.WrappedKey`
    (provider, master_key_id, algorithm, base64 ciphertext). The plaintext DEK
    exists only transiently in memory during encrypt/decrypt operations.
    """

    __tablename__ = "encryption_keys"

    key_type: Mapped[KeyType] = mapped_column(
        Enum(KeyType, name="key_type"), nullable=False, default=KeyType.data, index=True
    )
    purpose: Mapped[str | None] = mapped_column(String(128))

    # Serialized wrapped key (JSON of WrappedKey.to_dict()).
    wrapped_key: Mapped[str] = mapped_column(Text, nullable=False)
    provider: Mapped[str] = mapped_column(String(32), nullable=False, default="local")
    master_key_id: Mapped[str] = mapped_column(String(64), nullable=False)
    algorithm: Mapped[str] = mapped_column(String(32), nullable=False, default="AES-256-GCM")

    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    status: Mapped[KeyStatus] = mapped_column(
        Enum(KeyStatus, name="key_status"), nullable=False, default=KeyStatus.active, index=True
    )

    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    rotated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    rotations_from: Mapped[list[KeyRotation]] = relationship(
        back_populates="old_key", foreign_keys="KeyRotation.old_key_id"
    )

    @property
    def is_usable(self) -> bool:
        return self.status is KeyStatus.active


class KeyRotation(Base, UUIDPrimaryKeyMixin):
    """Audit record of a key rotation (DEK, field key, or master key)."""

    __tablename__ = "key_rotations"

    rotation_type: Mapped[RotationType] = mapped_column(
        Enum(RotationType, name="rotation_type"), nullable=False
    )
    old_key_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("encryption_keys.id", ondelete="SET NULL"), index=True
    )
    new_key_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("encryption_keys.id", ondelete="SET NULL")
    )
    old_master_key_id: Mapped[str | None] = mapped_column(String(64))
    new_master_key_id: Mapped[str | None] = mapped_column(String(64))

    reason: Mapped[str | None] = mapped_column(String(255))
    performed_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    detail: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    old_key: Mapped[EncryptionKey | None] = relationship(
        back_populates="rotations_from", foreign_keys=[old_key_id]
    )
    new_key: Mapped[EncryptionKey | None] = relationship(foreign_keys=[new_key_id])
