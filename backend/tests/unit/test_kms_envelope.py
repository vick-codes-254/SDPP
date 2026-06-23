"""KMS provider + envelope encryption tests."""

from __future__ import annotations

import io
import os

import pytest

from app.core.kms.base import WrappedKey
from app.core.kms.local import LocalMasterKeyProvider, _derive_key_id
from app.core.security.crypto import KEY_SIZE, generate_key
from app.core.security.envelope import EnvelopeEncryptor
from app.core.security.exceptions import DecryptionError, KeyManagementError

pytestmark = pytest.mark.crypto


@pytest.fixture
def master_key() -> bytes:
    return os.urandom(KEY_SIZE)


@pytest.fixture
def provider(master_key: bytes) -> LocalMasterKeyProvider:
    return LocalMasterKeyProvider(master_key)


class TestLocalProvider:
    def test_wrap_unwrap_round_trip(self, provider: LocalMasterKeyProvider) -> None:
        dek = generate_key()
        wrapped = provider.wrap(dek)
        assert provider.unwrap(wrapped) == dek

    def test_wrapped_dek_is_not_plaintext(self, provider: LocalMasterKeyProvider) -> None:
        dek = generate_key()
        wrapped = provider.wrap(dek)
        assert dek not in wrapped.ciphertext

    def test_generate_data_key(self, provider: LocalMasterKeyProvider) -> None:
        dek, wrapped = provider.generate_data_key()
        assert len(dek) == KEY_SIZE
        assert provider.unwrap(wrapped) == dek

    def test_key_id_is_stable_and_non_secret(self, master_key: bytes) -> None:
        assert _derive_key_id(master_key) == _derive_key_id(master_key)
        assert master_key.hex() not in _derive_key_id(master_key)

    def test_unwrap_with_wrong_master_fails(self) -> None:
        p1 = LocalMasterKeyProvider(os.urandom(KEY_SIZE))
        p2 = LocalMasterKeyProvider(os.urandom(KEY_SIZE))
        wrapped = p1.wrap(generate_key())
        with pytest.raises(KeyManagementError):
            # p2 doesn't have the master key id referenced by `wrapped`
            p2.unwrap(wrapped)

    def test_invalid_master_key_length(self) -> None:
        with pytest.raises(KeyManagementError):
            LocalMasterKeyProvider(b"too-short")

    def test_provider_mismatch_rejected(self, provider: LocalMasterKeyProvider) -> None:
        foreign = WrappedKey("aws", "k", "AWS_KMS", b"x")
        with pytest.raises(KeyManagementError):
            provider.unwrap(foreign)

    def test_previous_keys_supported_for_rotation(self) -> None:
        old_key = os.urandom(KEY_SIZE)
        new_key = os.urandom(KEY_SIZE)
        old_provider = LocalMasterKeyProvider(old_key)
        wrapped_old = old_provider.wrap(generate_key())
        # After rotation: new key current, old key still available to unwrap.
        rotated = LocalMasterKeyProvider(new_key, previous_keys=[old_key])
        assert rotated.unwrap(wrapped_old)  # does not raise


class TestWrappedKeySerialization:
    def test_dict_round_trip(self, provider: LocalMasterKeyProvider) -> None:
        wrapped = provider.wrap(generate_key())
        restored = WrappedKey.from_dict(wrapped.to_dict())
        assert restored == wrapped
        assert provider.unwrap(restored)


class TestEnvelopePayload:
    def test_payload_round_trip(self, provider: LocalMasterKeyProvider) -> None:
        enc = EnvelopeEncryptor(provider)
        ct, wrapped = enc.encrypt_payload(b"sensitive incident note")
        assert enc.decrypt_payload(ct, wrapped) == b"sensitive incident note"

    def test_each_payload_uses_unique_dek(self, provider: LocalMasterKeyProvider) -> None:
        enc = EnvelopeEncryptor(provider)
        _, w1 = enc.encrypt_payload(b"a")
        _, w2 = enc.encrypt_payload(b"b")
        assert w1.ciphertext != w2.ciphertext  # different wrapped DEKs

    def test_wrong_wrapped_key_fails(self, provider: LocalMasterKeyProvider) -> None:
        enc = EnvelopeEncryptor(provider)
        ct, _ = enc.encrypt_payload(b"data")
        _, other_wrapped = enc.encrypt_payload(b"other")
        with pytest.raises(DecryptionError):
            enc.decrypt_payload(ct, other_wrapped)


class TestEnvelopeFile:
    @pytest.mark.parametrize("size", [0, 1, 1024, 200_000, 2_500_000])
    def test_file_round_trip(self, provider: LocalMasterKeyProvider, size: int) -> None:
        enc = EnvelopeEncryptor(provider)
        data = os.urandom(size)
        ciphertext = io.BytesIO()
        meta = enc.encrypt_file(io.BytesIO(data), ciphertext, chunk_size=64 * 1024)

        assert meta.plaintext_size == size
        from app.core.security.hashing import hash_bytes

        assert meta.plaintext_sha256 == hash_bytes(data)

        ciphertext.seek(0)
        out = io.BytesIO()
        enc.decrypt_file(meta.wrapped_dek, ciphertext, out)
        assert out.getvalue() == data

    def test_tampered_file_detected(self, provider: LocalMasterKeyProvider) -> None:
        enc = EnvelopeEncryptor(provider)
        ciphertext = io.BytesIO()
        meta = enc.encrypt_file(io.BytesIO(b"Q" * 10000), ciphertext, chunk_size=1024)
        blob = bytearray(ciphertext.getvalue())
        blob[-1] ^= 0x01
        with pytest.raises(DecryptionError):
            enc.decrypt_file(meta.wrapped_dek, io.BytesIO(bytes(blob)), io.BytesIO())


class TestMasterKeyRotation:
    def test_rewrap_keeps_data_decryptable(self) -> None:
        old_key = os.urandom(KEY_SIZE)
        new_key = os.urandom(KEY_SIZE)
        old_provider = LocalMasterKeyProvider(old_key)
        enc_old = EnvelopeEncryptor(old_provider)

        ct, wrapped_old = enc_old.encrypt_payload(b"long-lived evidence")

        # Rotate master key; rewrap the DEK envelope (data untouched).
        rotated_provider = LocalMasterKeyProvider(new_key, previous_keys=[old_key])
        enc_new = EnvelopeEncryptor(rotated_provider)
        wrapped_new = enc_new.rewrap_dek(wrapped_old)

        # New envelope is bound to the new master key id, data still decrypts.
        assert wrapped_new.master_key_id == _derive_key_id(new_key)
        assert enc_new.decrypt_payload(ct, wrapped_new) == b"long-lived evidence"
