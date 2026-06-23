"""Secure file vault models: logical files, encrypted blobs, integrity checks."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.security.field_encryption import EncryptedString, EncryptedText
from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin
from app.models.enums import (
    FileCategory,
    FileStatus,
    IntegrityResult,
    IntegrityTarget,
)


class File(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Logical record describing an uploaded file (metadata, not the bytes)."""

    __tablename__ = "files"

    owner_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False, index=True
    )

    # Original filename can leak case details / PII -> encrypted at rest.
    original_filename: Mapped[str] = mapped_column(
        EncryptedString(context="files.original_filename"), nullable=False
    )
    content_type: Mapped[str] = mapped_column(String(128), nullable=False)
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    category: Mapped[FileCategory] = mapped_column(
        Enum(FileCategory, name="file_category"), nullable=False, default=FileCategory.other
    )
    description: Mapped[str | None] = mapped_column(EncryptedText(context="files.description"))

    status: Mapped[FileStatus] = mapped_column(
        Enum(FileStatus, name="file_status"), nullable=False, default=FileStatus.uploaded, index=True
    )

    # SHA-256 of the original plaintext (integrity anchor).
    plaintext_sha256: Mapped[str | None] = mapped_column(String(64))

    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    encrypted: Mapped[EncryptedFile | None] = relationship(
        back_populates="file", cascade="all, delete-orphan", uselist=False, lazy="selectin"
    )
    integrity_checks: Mapped[list[IntegrityCheck]] = relationship(
        back_populates="file", cascade="all, delete-orphan"
    )


class EncryptedFile(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Storage details of the AES-256-GCM ciphertext blob for a :class:`File`."""

    __tablename__ = "encrypted_files"

    file_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("files.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,  # one-to-one
    )
    # Opaque object key/path of the ciphertext in the vault backend.
    storage_key: Mapped[str] = mapped_column(String(512), nullable=False)
    algorithm: Mapped[str] = mapped_column(String(32), nullable=False, default="AES-256-GCM")
    chunk_size: Mapped[int] = mapped_column(Integer, nullable=False)
    ciphertext_size: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)

    # The DEK that protects this file (wrapped form lives in encryption_keys).
    encryption_key_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("encryption_keys.id", ondelete="RESTRICT"), nullable=False
    )

    # SHA-256 of the stored ciphertext: detects at-rest tampering WITHOUT decryption.
    ciphertext_sha256: Mapped[str] = mapped_column(String(64), nullable=False)

    file: Mapped[File] = relationship(back_populates="encrypted")
    encryption_key: Mapped["EncryptionKey"] = relationship()  # noqa: F821


class IntegrityCheck(Base, UUIDPrimaryKeyMixin):
    """Record of a single integrity verification (pass/fail) for a file."""

    __tablename__ = "integrity_checks"

    file_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("files.id", ondelete="CASCADE"), nullable=False, index=True
    )
    target: Mapped[IntegrityTarget] = mapped_column(
        Enum(IntegrityTarget, name="integrity_target"), nullable=False
    )
    expected_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    actual_sha256: Mapped[str | None] = mapped_column(String(64))
    result: Mapped[IntegrityResult] = mapped_column(
        Enum(IntegrityResult, name="integrity_result"), nullable=False, index=True
    )
    checked_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    detail: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    file: Mapped[File] = relationship(back_populates="integrity_checks")
