"""Envelope encryption — the platform's primary data-protection workflow.

    Generate DEK  →  Encrypt data with DEK (AES-256-GCM)  →  Wrap DEK with
    master key (KMS)  →  Persist {ciphertext, wrapped DEK, SHA-256, metadata}

Each file/payload gets a **unique** Data Encryption Key. The DEK is never stored
in the clear — only its wrapped form (encrypted by the master key) is persisted.
This means a database compromise alone never exposes plaintext, and the master
key can be rotated by re-wrapping DEKs without re-encrypting terabytes of data.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import BinaryIO

from app.core.kms.base import MasterKeyProvider, WrappedKey
from app.core.security.crypto import (
    DEFAULT_CHUNK_SIZE,
    StreamResult,
    decrypt_bytes,
    decrypt_stream,
    encrypt_bytes,
    encrypt_stream,
)

ENVELOPE_ALGORITHM = "AES-256-GCM"


@dataclass(frozen=True, slots=True)
class EnvelopeMetadata:
    """Everything needed to later decrypt and integrity-check an encrypted file."""

    wrapped_dek: WrappedKey
    algorithm: str
    plaintext_sha256: str
    plaintext_size: int
    ciphertext_size: int
    chunks: int


class _HashingReader:
    """Wrap a binary stream, computing SHA-256 of everything read (single pass)."""

    def __init__(self, fileobj: BinaryIO) -> None:
        self._f = fileobj
        self._h = hashlib.sha256()

    def read(self, size: int = -1) -> bytes:
        data = self._f.read(size)
        self._h.update(data)
        return data

    def hexdigest(self) -> str:
        return self._h.hexdigest()


class EnvelopeEncryptor:
    """High-level envelope encryption over a :class:`MasterKeyProvider`."""

    def __init__(self, provider: MasterKeyProvider) -> None:
        self._provider = provider

    # ── Files (streaming, bounded memory) ───────────────────────
    def encrypt_file(
        self,
        src: BinaryIO,
        dst: BinaryIO,
        *,
        aad: bytes | None = None,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
    ) -> EnvelopeMetadata:
        """Stream-encrypt ``src`` → ``dst`` with a fresh DEK; return the envelope.

        The plaintext SHA-256 is computed in the same pass for integrity records.
        """
        dek, wrapped = self._provider.generate_data_key(aad)
        try:
            reader = _HashingReader(src)
            result = encrypt_stream(
                dek, reader, dst, chunk_size=chunk_size, associated_data=aad  # type: ignore[arg-type]
            )
        finally:
            del dek  # best-effort; CPython bytes are immutable (see SECURITY.md)
        return EnvelopeMetadata(
            wrapped_dek=wrapped,
            algorithm=ENVELOPE_ALGORITHM,
            plaintext_sha256=reader.hexdigest(),
            plaintext_size=result.plaintext_bytes,
            ciphertext_size=result.ciphertext_bytes,
            chunks=result.chunks,
        )

    def decrypt_file(
        self,
        wrapped_dek: WrappedKey,
        src: BinaryIO,
        dst: BinaryIO,
        *,
        aad: bytes | None = None,
    ) -> StreamResult:
        """Unwrap the DEK and stream-decrypt ``src`` → ``dst``."""
        dek = self._provider.unwrap(wrapped_dek, aad)
        try:
            return decrypt_stream(dek, src, dst, associated_data=aad)
        finally:
            del dek

    # ── Small payloads (one-shot) ───────────────────────────────
    def encrypt_payload(
        self, plaintext: bytes, *, aad: bytes | None = None
    ) -> tuple[bytes, WrappedKey]:
        """Encrypt a small payload; return ``(ciphertext_blob, wrapped_dek)``."""
        dek, wrapped = self._provider.generate_data_key(aad)
        try:
            return encrypt_bytes(dek, plaintext, aad), wrapped
        finally:
            del dek

    def decrypt_payload(
        self, ciphertext: bytes, wrapped_dek: WrappedKey, *, aad: bytes | None = None
    ) -> bytes:
        dek = self._provider.unwrap(wrapped_dek, aad)
        try:
            return decrypt_bytes(dek, ciphertext, aad)
        finally:
            del dek

    # ── Master-key rotation ─────────────────────────────────────
    def rewrap_dek(self, wrapped_dek: WrappedKey, *, aad: bytes | None = None) -> WrappedKey:
        """Re-wrap a DEK under the *current* master key (master-key rotation).

        The encrypted file/data is untouched — only the tiny envelope is rewritten.
        This makes master-key rotation O(number of keys), not O(bytes of data).
        """
        dek = self._provider.unwrap(wrapped_dek, aad)
        try:
            return self._provider.wrap(dek, aad)
        finally:
            del dek
