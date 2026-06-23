"""Cryptographic correctness & invariants for AES-256-GCM.

Covers the requirements:
* verify AES-256-GCM implementation (round-trip)
* verify nonce uniqueness
* verify authentication tags (tamper detection)
* verify encryption randomness
* wrong-key decryption fails
* streaming: truncation & reordering detection, large/empty files
"""

from __future__ import annotations

import io

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from app.core.security import crypto
from app.core.security.crypto import (
    KEY_SIZE,
    NONCE_SIZE,
    TAG_SIZE,
    decrypt_bytes,
    decrypt_stream,
    encrypt_bytes,
    encrypt_stream,
    generate_key,
    generate_nonce,
)
from app.core.security.exceptions import DecryptionError, EncryptionError

pytestmark = pytest.mark.crypto


# ════════════════════════════════════════════════════════════════
#  Key / nonce generation
# ════════════════════════════════════════════════════════════════
class TestKeyGeneration:
    def test_key_is_256_bit(self) -> None:
        assert len(generate_key()) == KEY_SIZE == 32

    def test_nonce_is_96_bit(self) -> None:
        assert len(generate_nonce()) == NONCE_SIZE == 12

    def test_keys_are_unique(self) -> None:
        keys = {generate_key() for _ in range(1000)}
        assert len(keys) == 1000  # no collisions => high-entropy CSPRNG

    def test_nonces_are_unique(self) -> None:
        nonces = {generate_nonce() for _ in range(10000)}
        assert len(nonces) == 10000


# ════════════════════════════════════════════════════════════════
#  One-shot AEAD
# ════════════════════════════════════════════════════════════════
class TestOneShotAEAD:
    def test_round_trip(self) -> None:
        key = generate_key()
        pt = b"top-secret evidence payload"
        assert decrypt_bytes(key, encrypt_bytes(key, pt)) == pt

    def test_round_trip_empty(self) -> None:
        key = generate_key()
        assert decrypt_bytes(key, encrypt_bytes(key, b"")) == b""

    def test_ciphertext_differs_from_plaintext(self) -> None:
        key = generate_key()
        pt = b"A" * 64
        assert encrypt_bytes(key, pt)[NONCE_SIZE:] != pt

    def test_nonce_randomness_same_input(self) -> None:
        """Encrypting identical plaintext twice yields different ciphertext (random nonce)."""
        key = generate_key()
        pt = b"same input"
        a, b = encrypt_bytes(key, pt), encrypt_bytes(key, pt)
        assert a != b
        assert a[:NONCE_SIZE] != b[:NONCE_SIZE]  # different nonces
        assert decrypt_bytes(key, a) == decrypt_bytes(key, b) == pt

    def test_wrong_key_fails(self) -> None:
        blob = encrypt_bytes(generate_key(), b"secret")
        with pytest.raises(DecryptionError):
            decrypt_bytes(generate_key(), blob)

    def test_tampered_ciphertext_detected(self) -> None:
        key = generate_key()
        blob = bytearray(encrypt_bytes(key, b"secret payload"))
        blob[-1] ^= 0x01  # flip one bit in the tag
        with pytest.raises(DecryptionError):
            decrypt_bytes(key, bytes(blob))

    def test_tampered_body_detected(self) -> None:
        key = generate_key()
        blob = bytearray(encrypt_bytes(key, b"secret payload"))
        blob[NONCE_SIZE + 1] ^= 0x80  # flip a ciphertext bit
        with pytest.raises(DecryptionError):
            decrypt_bytes(key, bytes(blob))

    def test_aad_binding(self) -> None:
        key = generate_key()
        blob = encrypt_bytes(key, b"data", associated_data=b"file-id-123")
        assert decrypt_bytes(key, blob, associated_data=b"file-id-123") == b"data"
        with pytest.raises(DecryptionError):
            decrypt_bytes(key, blob, associated_data=b"file-id-999")

    def test_short_ciphertext_rejected(self) -> None:
        with pytest.raises(DecryptionError):
            decrypt_bytes(generate_key(), b"too-short")

    @pytest.mark.parametrize("bad_len", [0, 1, 16, 31, 33, 64])
    def test_invalid_key_length_rejected(self, bad_len: int) -> None:
        with pytest.raises(EncryptionError):
            encrypt_bytes(b"\x00" * bad_len, b"data")

    @settings(max_examples=200, suppress_health_check=[HealthCheck.function_scoped_fixture])
    @given(pt=st.binary(min_size=0, max_size=4096), aad=st.binary(max_size=64))
    def test_property_round_trip(self, pt: bytes, aad: bytes) -> None:
        key = generate_key()
        blob = encrypt_bytes(key, pt, associated_data=aad)
        assert decrypt_bytes(key, blob, associated_data=aad) == pt


# ════════════════════════════════════════════════════════════════
#  Streaming AEAD
# ════════════════════════════════════════════════════════════════
def _round_trip_stream(key: bytes, data: bytes, chunk_size: int) -> bytes:
    enc = io.BytesIO()
    encrypt_stream(key, io.BytesIO(data), enc, chunk_size=chunk_size)
    enc.seek(0)
    dec = io.BytesIO()
    decrypt_stream(key, enc, dec)
    return dec.getvalue()


class TestStreamingAEAD:
    @pytest.mark.parametrize(
        "size",
        [0, 1, 15, 16, 17, 1024, 4096, 100_000, 1_048_576, 1_048_577, 3_000_000],
    )
    def test_round_trip_various_sizes(self, size: int) -> None:
        key = generate_key()
        data = bytes((i * 7) % 256 for i in range(size))
        chunk = 64 * 1024
        assert _round_trip_stream(key, data, chunk) == data

    def test_round_trip_tiny_chunks(self) -> None:
        key = generate_key()
        data = b"streaming across many small chunks" * 50
        assert _round_trip_stream(key, data, chunk_size=8) == data

    def test_ciphertext_header_present(self) -> None:
        key = generate_key()
        enc = io.BytesIO()
        encrypt_stream(key, io.BytesIO(b"hello"), enc, chunk_size=1024)
        assert enc.getvalue()[:4] == b"SDPP"

    def test_wrong_key_fails(self) -> None:
        enc = io.BytesIO()
        encrypt_stream(generate_key(), io.BytesIO(b"data" * 100), enc, chunk_size=64)
        enc.seek(0)
        with pytest.raises(DecryptionError):
            decrypt_stream(generate_key(), enc, io.BytesIO())

    def test_tampered_chunk_detected(self) -> None:
        key = generate_key()
        enc = io.BytesIO()
        encrypt_stream(key, io.BytesIO(b"X" * 5000), enc, chunk_size=1024)
        blob = bytearray(enc.getvalue())
        blob[-5] ^= 0x01  # corrupt a byte in the last chunk
        with pytest.raises(DecryptionError):
            decrypt_stream(key, io.BytesIO(bytes(blob)), io.BytesIO())

    def test_truncation_detected(self) -> None:
        """Dropping the final chunk must fail (last-flag nonce binding)."""
        key = generate_key()
        enc = io.BytesIO()
        encrypt_stream(key, io.BytesIO(b"Y" * 5000), enc, chunk_size=1024)
        blob = enc.getvalue()
        from app.core.security.crypto import HEADER_SIZE

        enc_chunk = 1024 + TAG_SIZE
        truncated = blob[: HEADER_SIZE + enc_chunk * 2]  # keep only first 2 chunks
        with pytest.raises(DecryptionError):
            decrypt_stream(key, io.BytesIO(truncated), io.BytesIO())

    def test_reordering_detected(self) -> None:
        """Swapping two ciphertext chunks must fail (counter nonce binding)."""
        key = generate_key()
        enc = io.BytesIO()
        encrypt_stream(key, io.BytesIO(b"Z" * 4000), enc, chunk_size=1024)
        from app.core.security.crypto import HEADER_SIZE

        blob = bytearray(enc.getvalue())
        ec = 1024 + TAG_SIZE
        c0 = blob[HEADER_SIZE : HEADER_SIZE + ec]
        c1 = blob[HEADER_SIZE + ec : HEADER_SIZE + 2 * ec]
        blob[HEADER_SIZE : HEADER_SIZE + ec] = c1
        blob[HEADER_SIZE + ec : HEADER_SIZE + 2 * ec] = c0
        with pytest.raises(DecryptionError):
            decrypt_stream(key, io.BytesIO(bytes(blob)), io.BytesIO())

    def test_header_tamper_detected(self) -> None:
        key = generate_key()
        enc = io.BytesIO()
        encrypt_stream(key, io.BytesIO(b"W" * 2000), enc, chunk_size=1024)
        blob = bytearray(enc.getvalue())
        blob[5] ^= 0x01  # corrupt the version/chunk-size header (authenticated as AAD)
        with pytest.raises(DecryptionError):
            decrypt_stream(key, io.BytesIO(bytes(blob)), io.BytesIO())

    def test_not_sdpp_stream_rejected(self) -> None:
        with pytest.raises(DecryptionError):
            decrypt_stream(generate_key(), io.BytesIO(b"NOPE" + b"\x00" * 100), io.BytesIO())

    def test_stream_nonce_uniqueness_across_chunks(self) -> None:
        """Every chunk in a stream uses a distinct nonce."""
        prefix = b"1234567"
        nonces = {crypto._stream_nonce(prefix, i, i == 9) for i in range(10)}
        assert len(nonces) == 10

    @settings(max_examples=60, suppress_health_check=[HealthCheck.function_scoped_fixture])
    @given(data=st.binary(min_size=0, max_size=20_000), chunk=st.integers(8, 4096))
    def test_property_stream_round_trip(self, data: bytes, chunk: int) -> None:
        key = generate_key()
        assert _round_trip_stream(key, data, chunk) == data
