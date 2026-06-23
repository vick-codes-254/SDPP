"""Field-level encryption (FieldCipher) tests."""

from __future__ import annotations

import os

import pytest

from app.core.security.crypto import KEY_SIZE
from app.core.security.exceptions import DecryptionError, KeyManagementError
from app.core.security.field_encryption import FieldCipher

pytestmark = pytest.mark.crypto


@pytest.fixture
def cipher() -> FieldCipher:
    return FieldCipher(os.urandom(KEY_SIZE))


class TestFieldCipher:
    def test_round_trip(self, cipher: FieldCipher) -> None:
        token = cipher.encrypt("alice@example.com", context="users.email")
        assert token is not None
        assert cipher.decrypt(token, context="users.email") == "alice@example.com"

    def test_none_passthrough(self, cipher: FieldCipher) -> None:
        assert cipher.encrypt(None) is None
        assert cipher.decrypt(None) is None
        assert cipher.blind_index(None) is None

    def test_ciphertext_is_not_plaintext(self, cipher: FieldCipher) -> None:
        token = cipher.encrypt("secret-note", context="notes.body")
        assert "secret-note" not in token

    def test_randomized_ciphertext(self, cipher: FieldCipher) -> None:
        a = cipher.encrypt("same", context="t.c")
        b = cipher.encrypt("same", context="t.c")
        assert a != b  # random nonce per write
        assert cipher.decrypt(a, "t.c") == cipher.decrypt(b, "t.c") == "same"

    def test_context_binding_prevents_column_swap(self, cipher: FieldCipher) -> None:
        token = cipher.encrypt("1.2.3.4", context="events.ip_address")
        # Same key, different column context -> authentication fails.
        with pytest.raises(DecryptionError):
            cipher.decrypt(token, context="users.phone")

    def test_unicode(self, cipher: FieldCipher) -> None:
        value = "日本語 — café — 🔐"
        token = cipher.encrypt(value, context="x.y")
        assert cipher.decrypt(token, context="x.y") == value

    def test_invalid_key_length(self) -> None:
        with pytest.raises(KeyManagementError):
            FieldCipher(b"short")


class TestBlindIndex:
    def test_deterministic(self, cipher: FieldCipher) -> None:
        assert cipher.blind_index("alice@example.com") == cipher.blind_index(
            "alice@example.com"
        )

    def test_normalization(self, cipher: FieldCipher) -> None:
        assert cipher.blind_index("  Alice@Example.COM ") == cipher.blind_index(
            "alice@example.com"
        )

    def test_distinct_values_differ(self, cipher: FieldCipher) -> None:
        assert cipher.blind_index("a@x.com") != cipher.blind_index("b@x.com")

    def test_index_is_not_reversible_plaintext(self, cipher: FieldCipher) -> None:
        idx = cipher.blind_index("alice@example.com")
        assert "alice" not in idx
        assert len(idx) == 64  # hex sha256
