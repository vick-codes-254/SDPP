"""SHA-256 integrity hashing tests."""

from __future__ import annotations

import hashlib
import io

import pytest
from hypothesis import given
from hypothesis import strategies as st

from app.core.security.exceptions import IntegrityError
from app.core.security.hashing import (
    constant_time_equal,
    hash_bytes,
    hash_stream,
    hmac_sha256,
    verify_digest,
)

pytestmark = pytest.mark.crypto


class TestHashing:
    def test_known_vector_empty(self) -> None:
        # SHA-256("") well-known test vector
        assert hash_bytes(b"") == (
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )

    def test_known_vector_abc(self) -> None:
        assert hash_bytes(b"abc") == (
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        )

    def test_stream_matches_oneshot(self) -> None:
        data = b"integrity" * 100_000
        assert hash_stream(io.BytesIO(data)) == hashlib.sha256(data).hexdigest()

    def test_stream_empty(self) -> None:
        assert hash_stream(io.BytesIO(b"")) == hash_bytes(b"")

    def test_single_bit_change_changes_digest(self) -> None:
        a = hash_bytes(b"evidence-file-v1")
        b = hash_bytes(b"evidence-file-v2")
        assert a != b

    @given(data=st.binary(max_size=2048))
    def test_property_matches_hashlib(self, data: bytes) -> None:
        assert hash_bytes(data) == hashlib.sha256(data).hexdigest()


class TestVerification:
    def test_verify_digest_ok(self) -> None:
        d = hash_bytes(b"data")
        verify_digest(d, d)  # no raise

    def test_verify_digest_mismatch_raises(self) -> None:
        with pytest.raises(IntegrityError):
            verify_digest(hash_bytes(b"a"), hash_bytes(b"b"))

    def test_constant_time_equal(self) -> None:
        assert constant_time_equal("abc", "abc")
        assert not constant_time_equal("abc", "abd")


class TestHMAC:
    def test_deterministic(self) -> None:
        key = b"k" * 32
        assert hmac_sha256(key, b"msg") == hmac_sha256(key, b"msg")

    def test_key_dependent(self) -> None:
        assert hmac_sha256(b"k1" * 16, b"m") != hmac_sha256(b"k2" * 16, b"m")
