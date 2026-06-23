"""Transparent application-layer encryption for sensitive database columns.

Encrypts PII and sensitive fields (names, emails, phone numbers, incident notes,
evidence descriptions, IP addresses, hostnames, device metadata) *before* they
reach the database, so the data at rest is AES-256-GCM ciphertext even if the DB
files, backups, or replicas are stolen.

Two SQLAlchemy column types are provided:

* :class:`EncryptedString` / :class:`EncryptedText` — confidential, randomized
  ciphertext (AES-256-GCM with a random nonce per write). Not searchable.
* :class:`BlindIndex` — a deterministic keyed HMAC of the *normalized* value,
  enabling exact-match lookups (e.g. "find user by email") without revealing the
  plaintext. Store it alongside the encrypted column.

The field key is a 256-bit Data Encryption Key, wrapped by the KMS master key and
held only in memory at runtime. It is installed via :func:`set_field_cipher`
during application startup.
"""

from __future__ import annotations

import base64

from sqlalchemy import String, Text
from sqlalchemy.types import TypeDecorator

from app.core.security.crypto import KEY_SIZE, decrypt_bytes, encrypt_bytes
from app.core.security.exceptions import KeyManagementError
from app.core.security.hashing import hmac_sha256


class FieldCipher:
    """Encrypt/decrypt and blind-index individual field values.

    ``context`` (typically ``"table.column"``) is bound as AES-GCM associated
    data, so a ciphertext from one column cannot be transplanted into another.
    """

    def __init__(self, key: bytes) -> None:
        if len(key) != KEY_SIZE:
            raise KeyManagementError(f"Field key must be {KEY_SIZE} bytes")
        self._key = key

    def encrypt(self, plaintext: str | None, context: str = "") -> str | None:
        if plaintext is None:
            return None
        aad = context.encode("utf-8") if context else None
        blob = encrypt_bytes(self._key, plaintext.encode("utf-8"), aad)
        return base64.b64encode(blob).decode("ascii")

    def decrypt(self, token: str | None, context: str = "") -> str | None:
        if token is None:
            return None
        aad = context.encode("utf-8") if context else None
        blob = base64.b64decode(token)
        return decrypt_bytes(self._key, blob, aad).decode("utf-8")

    def blind_index(self, value: str | None) -> str | None:
        """Deterministic, keyed equality token (lookup without decryption)."""
        if value is None:
            return None
        normalized = value.strip().lower().encode("utf-8")
        return hmac_sha256(self._key, normalized)


# ── Runtime cipher registry ─────────────────────────────────────
_active_cipher: FieldCipher | None = None


def set_field_cipher(cipher: FieldCipher) -> None:
    """Install the process-wide field cipher (called at application startup)."""
    global _active_cipher
    _active_cipher = cipher


def get_field_cipher() -> FieldCipher:
    if _active_cipher is None:
        raise KeyManagementError(
            "Field cipher not initialized — call set_field_cipher() at startup"
        )
    return _active_cipher


def is_field_cipher_set() -> bool:
    return _active_cipher is not None


# ── SQLAlchemy column types ─────────────────────────────────────
class _EncryptedType(TypeDecorator):
    """Base for encrypted column types. Stores base64(nonce‖ct‖tag) as text."""

    cache_ok = True

    def __init__(self, context: str | None = None, **kwargs: object) -> None:
        self.context = context or ""
        super().__init__(**kwargs)

    def process_bind_param(self, value: str | None, dialect: object) -> str | None:
        return get_field_cipher().encrypt(value, self.context)

    def process_result_value(self, value: str | None, dialect: object) -> str | None:
        return get_field_cipher().decrypt(value, self.context)


class EncryptedString(_EncryptedType):
    impl = String
    cache_ok = True


class EncryptedText(_EncryptedType):
    impl = Text
    cache_ok = True


class BlindIndex(TypeDecorator):
    """Deterministic keyed-HMAC column for exact-match search over encrypted data.

    Assign the *plaintext* value to the attribute; it is transparently converted
    to its blind index on write. Query with ``Model.email_bidx == raw_email``.
    """

    impl = String(64)
    cache_ok = True

    def process_bind_param(self, value: str | None, dialect: object) -> str | None:
        return get_field_cipher().blind_index(value)

    def process_result_value(self, value: str | None, dialect: object) -> str | None:
        return value  # opaque token; never reversible to plaintext
