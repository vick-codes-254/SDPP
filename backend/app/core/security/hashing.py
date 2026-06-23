"""Integrity hashing (SHA-256) and keyed HMAC.

Used to:
* fingerprint files on upload and verify them before every access (tamper
  detection),
* derive deterministic blind-indexes / lookup tokens for encrypted DB fields,
* provide constant-time comparison of digests to avoid timing oracles.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import BinaryIO

from app.core.security.exceptions import IntegrityError

_HASH_READ_CHUNK = 1024 * 1024  # 1 MiB
DIGEST_ALGORITHM = "sha256"
DIGEST_HEX_LEN = 64


def hash_bytes(data: bytes) -> str:
    """Return the lowercase hex SHA-256 digest of ``data``."""
    return hashlib.sha256(data).hexdigest()


def hash_stream(src: BinaryIO) -> str:
    """Return the hex SHA-256 digest of a file-like object, streaming in chunks.

    Memory use is bounded regardless of file size; suitable for multi-GB files.
    """
    digest = hashlib.sha256()
    while True:
        block = src.read(_HASH_READ_CHUNK)
        if not block:
            break
        digest.update(block)
    return digest.hexdigest()


def hash_file(path: str) -> str:
    """Return the hex SHA-256 digest of the file at ``path``."""
    with open(path, "rb") as fh:
        return hash_stream(fh)


def constant_time_equal(a: str, b: str) -> bool:
    """Compare two hex digests in constant time (timing-attack resistant)."""
    return hmac.compare_digest(a, b)


def verify_digest(expected_hex: str, actual_hex: str) -> None:
    """Raise :class:`IntegrityError` if digests differ (constant-time check)."""
    if not constant_time_equal(expected_hex, actual_hex):
        raise IntegrityError("Integrity check failed: SHA-256 digest mismatch")


def hmac_sha256(key: bytes, message: bytes) -> str:
    """Keyed HMAC-SHA256, hex-encoded. Used for blind-index lookup tokens."""
    return hmac.new(key, message, hashlib.sha256).hexdigest()
