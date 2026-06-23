"""AES-256-GCM authenticated encryption.

This module is the cryptographic foundation of SDPP. It provides:

* one-shot AEAD for small secrets (DEKs, database fields) — :func:`encrypt_bytes`
  / :func:`decrypt_bytes`
* a streaming/chunked AEAD construction for arbitrarily large files with bounded
  memory, per-chunk tamper detection, and protection against **truncation** and
  **reordering** attacks — :func:`encrypt_stream` / :func:`decrypt_stream`

Design notes
------------
* Algorithm: AES-256 in Galois/Counter Mode (GCM) — confidentiality + integrity
  (authenticated encryption with associated data, AEAD).
* Keys: 256-bit (32 bytes), generated from the OS CSPRNG (``os.urandom``).
* Nonces: 96-bit (12 bytes). For one-shot encryption a fresh random nonce is
  generated per call; the 2^32 birthday bound is never approached because each
  DEK encrypts at most one payload.
* Streaming nonce construction (after Google Tink's *STREAM*): each chunk uses
  ``nonce = prefix(7) || counter(4, big-endian) || last_flag(1)``. The per-file
  random ``prefix`` guarantees nonce uniqueness across files; the ``counter``
  guarantees uniqueness across chunks; the ``last_flag`` makes the final chunk's
  nonce distinct, so an attacker cannot silently truncate the ciphertext.
* The serialized file header is fed as Associated Data to every chunk, so any
  tampering with the header (version, chunk size, nonce prefix) is detected.

This module is intentionally free of application/config/database imports so it
can be exhaustively unit- and property-tested in isolation.
"""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass
from typing import BinaryIO

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.core.security.exceptions import DecryptionError, EncryptionError

# ── Algorithm constants ─────────────────────────────────────────
KEY_SIZE = 32  # AES-256
NONCE_SIZE = 12  # 96-bit GCM nonce (recommended)
TAG_SIZE = 16  # 128-bit GCM authentication tag

# ── Streaming construction constants ────────────────────────────
_MAGIC = b"SDPP"
_STREAM_VERSION = 1
_NONCE_PREFIX_SIZE = 7
_COUNTER_SIZE = 4
_LAST_FLAG_SIZE = 1
DEFAULT_CHUNK_SIZE = 1024 * 1024  # 1 MiB of plaintext per chunk

assert _NONCE_PREFIX_SIZE + _COUNTER_SIZE + _LAST_FLAG_SIZE == NONCE_SIZE

# Header layout: MAGIC(4) | VERSION(1) | CHUNK_SIZE(4, BE) | NONCE_PREFIX(7) == 16 bytes
_HEADER_STRUCT = struct.Struct(f">4sB I {_NONCE_PREFIX_SIZE}s")
HEADER_SIZE = _HEADER_STRUCT.size
_MAX_COUNTER = (1 << (_COUNTER_SIZE * 8)) - 1


# ════════════════════════════════════════════════════════════════
#  Key / nonce generation
# ════════════════════════════════════════════════════════════════
def generate_key() -> bytes:
    """Return a fresh 256-bit key from the OS CSPRNG."""
    return os.urandom(KEY_SIZE)


def generate_nonce() -> bytes:
    """Return a fresh 96-bit nonce from the OS CSPRNG."""
    return os.urandom(NONCE_SIZE)


def _require_key(key: bytes) -> None:
    if not isinstance(key, (bytes, bytearray)) or len(key) != KEY_SIZE:
        raise EncryptionError(
            f"AES-256-GCM requires a {KEY_SIZE}-byte key (got "
            f"{len(key) if isinstance(key, (bytes, bytearray)) else type(key).__name__})"
        )


# ════════════════════════════════════════════════════════════════
#  One-shot AEAD (small payloads: DEKs, DB fields, metadata)
# ════════════════════════════════════════════════════════════════
def encrypt_bytes(key: bytes, plaintext: bytes, associated_data: bytes | None = None) -> bytes:
    """Encrypt ``plaintext`` with AES-256-GCM.

    Returns ``nonce(12) || ciphertext || tag(16)`` as a single opaque blob.
    A random nonce is generated per call.
    """
    _require_key(key)
    nonce = generate_nonce()
    try:
        ciphertext = AESGCM(key).encrypt(nonce, plaintext, associated_data)
    except Exception as exc:  # noqa: BLE001 - normalise to typed error
        raise EncryptionError("AES-256-GCM encryption failed") from exc
    return nonce + ciphertext


def decrypt_bytes(key: bytes, blob: bytes, associated_data: bytes | None = None) -> bytes:
    """Decrypt a blob produced by :func:`encrypt_bytes`.

    Raises :class:`DecryptionError` if the key is wrong or the data/AAD has been
    tampered with (GCM tag mismatch). The two cases are indistinguishable.
    """
    _require_key(key)
    if len(blob) < NONCE_SIZE + TAG_SIZE:
        raise DecryptionError("Ciphertext too short to be valid")
    nonce, ciphertext = blob[:NONCE_SIZE], blob[NONCE_SIZE:]
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, associated_data)
    except InvalidTag as exc:
        raise DecryptionError(
            "Authentication failed: wrong key or tampered ciphertext"
        ) from exc
    except Exception as exc:  # noqa: BLE001
        raise DecryptionError("Decryption failed") from exc


# ════════════════════════════════════════════════════════════════
#  Streaming / chunked AEAD (large files)
# ════════════════════════════════════════════════════════════════
@dataclass(frozen=True, slots=True)
class StreamResult:
    """Outcome of a streaming encryption/decryption pass."""

    plaintext_bytes: int
    ciphertext_bytes: int
    chunks: int


def _build_header(chunk_size: int, nonce_prefix: bytes) -> bytes:
    return _HEADER_STRUCT.pack(_MAGIC, _STREAM_VERSION, chunk_size, nonce_prefix)


def _parse_header(header: bytes) -> tuple[int, bytes]:
    if len(header) != HEADER_SIZE:
        raise DecryptionError("Invalid stream header length")
    magic, version, chunk_size, nonce_prefix = _HEADER_STRUCT.unpack(header)
    if magic != _MAGIC:
        raise DecryptionError("Invalid stream magic (not an SDPP encrypted file)")
    if version != _STREAM_VERSION:
        raise DecryptionError(f"Unsupported stream version: {version}")
    if not (0 < chunk_size <= 64 * 1024 * 1024):
        raise DecryptionError("Invalid/unsafe chunk size in header")
    return chunk_size, nonce_prefix


def _stream_nonce(prefix: bytes, counter: int, last: bool) -> bytes:
    return prefix + counter.to_bytes(_COUNTER_SIZE, "big") + (b"\x01" if last else b"\x00")


def encrypt_stream(
    key: bytes,
    src: BinaryIO,
    dst: BinaryIO,
    *,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    associated_data: bytes | None = None,
) -> StreamResult:
    """Stream-encrypt ``src`` into ``dst`` using chunked AES-256-GCM.

    Memory use is bounded by ``chunk_size`` regardless of file size. Always emits
    at least one (possibly empty) chunk so zero-byte files round-trip correctly.
    The on-disk header is authenticated as associated data for every chunk.
    """
    _require_key(key)
    if chunk_size <= 0:
        raise EncryptionError("chunk_size must be positive")

    nonce_prefix = os.urandom(_NONCE_PREFIX_SIZE)
    header = _build_header(chunk_size, nonce_prefix)
    aad = header if associated_data is None else header + associated_data

    dst.write(header)
    aes = AESGCM(key)

    counter = 0
    pt_total = 0
    ct_total = HEADER_SIZE
    chunks = 0

    current = src.read(chunk_size)
    while True:
        lookahead = src.read(chunk_size)
        is_last = len(lookahead) == 0
        if counter > _MAX_COUNTER:
            raise EncryptionError("File exceeds maximum supported chunk count")
        nonce = _stream_nonce(nonce_prefix, counter, is_last)
        try:
            enc = aes.encrypt(nonce, current, aad)
        except Exception as exc:  # noqa: BLE001
            raise EncryptionError("Streaming encryption failed") from exc
        dst.write(enc)

        pt_total += len(current)
        ct_total += len(enc)
        chunks += 1
        counter += 1

        if is_last:
            break
        current = lookahead

    return StreamResult(plaintext_bytes=pt_total, ciphertext_bytes=ct_total, chunks=chunks)


def decrypt_stream(
    key: bytes,
    src: BinaryIO,
    dst: BinaryIO,
    *,
    associated_data: bytes | None = None,
) -> StreamResult:
    """Stream-decrypt ``src`` (produced by :func:`encrypt_stream`) into ``dst``.

    Detects wrong keys, tampered chunks, reordered chunks, and truncated files.
    Raises :class:`DecryptionError` on any authentication failure.
    """
    _require_key(key)

    header = src.read(HEADER_SIZE)
    chunk_size, nonce_prefix = _parse_header(header)
    aad = header if associated_data is None else header + associated_data

    enc_chunk_size = chunk_size + TAG_SIZE
    aes = AESGCM(key)

    counter = 0
    pt_total = 0
    ct_total = HEADER_SIZE
    chunks = 0

    current = src.read(enc_chunk_size)
    if not current:
        # A valid stream always has >= 1 chunk; an empty body is a truncation.
        raise DecryptionError("Truncated stream: missing chunk data")

    while True:
        lookahead = src.read(enc_chunk_size)
        is_last = len(lookahead) == 0
        nonce = _stream_nonce(nonce_prefix, counter, is_last)
        try:
            pt = aes.decrypt(nonce, current, aad)
        except InvalidTag as exc:
            raise DecryptionError(
                f"Authentication failed at chunk {counter}: "
                "wrong key, tampering, truncation, or reordering"
            ) from exc
        except Exception as exc:  # noqa: BLE001
            raise DecryptionError("Streaming decryption failed") from exc
        dst.write(pt)

        pt_total += len(pt)
        ct_total += len(current)
        chunks += 1
        counter += 1

        if is_last:
            break
        current = lookahead

    return StreamResult(plaintext_bytes=pt_total, ciphertext_bytes=ct_total, chunks=chunks)
