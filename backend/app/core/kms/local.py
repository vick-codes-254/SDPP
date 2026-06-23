"""Local symmetric master-key provider.

The master key is a 256-bit AES key supplied via the environment (``MASTER_KEY``)
and sourced from a KMS/secret manager at deploy time. DEKs are wrapped with
AES-256-GCM under the master key.

Supports multiple master keys (current + previous) keyed by a stable, non-secret
key id, so DEKs wrapped under an old master key can still be unwrapped during a
master-key rotation window.
"""

from __future__ import annotations

import hashlib

from app.core.kms.base import MasterKeyProvider, WrappedKey
from app.core.security.crypto import KEY_SIZE, decrypt_bytes, encrypt_bytes
from app.core.security.exceptions import KeyManagementError

_ALGORITHM = "AES-256-GCM"
_KEY_ID_DOMAIN = b"sdpp-master-key-id-v1"


def _derive_key_id(key: bytes) -> str:
    """Stable, non-reversible identifier for a master key.

    It is a domain-separated SHA-256 of the key, truncated. It identifies which
    master key wrapped a DEK without revealing key material.
    """
    return hashlib.sha256(_KEY_ID_DOMAIN + key).hexdigest()[:16]


class LocalMasterKeyProvider(MasterKeyProvider):
    provider_name = "local"

    def __init__(self, current_key: bytes, previous_keys: list[bytes] | None = None) -> None:
        if len(current_key) != KEY_SIZE:
            raise KeyManagementError(f"Master key must be {KEY_SIZE} bytes")
        self._keys: dict[str, bytes] = {}
        self._current_id = _derive_key_id(current_key)
        self._keys[self._current_id] = current_key
        for key in previous_keys or []:
            if len(key) != KEY_SIZE:
                raise KeyManagementError(f"Previous master key must be {KEY_SIZE} bytes")
            self._keys.setdefault(_derive_key_id(key), key)

    def current_key_id(self) -> str:
        return self._current_id

    def wrap(self, dek: bytes, aad: bytes | None = None) -> WrappedKey:
        if len(dek) != KEY_SIZE:
            raise KeyManagementError(f"DEK must be {KEY_SIZE} bytes")
        master = self._keys[self._current_id]
        bound_aad = self._bind_aad(self._current_id, aad)
        ciphertext = encrypt_bytes(master, dek, bound_aad)
        return WrappedKey(
            provider=self.provider_name,
            master_key_id=self._current_id,
            algorithm=_ALGORITHM,
            ciphertext=ciphertext,
        )

    def unwrap(self, wrapped: WrappedKey, aad: bytes | None = None) -> bytes:
        if wrapped.provider != self.provider_name:
            raise KeyManagementError(
                f"Provider mismatch: key wrapped by '{wrapped.provider}', "
                f"this provider is '{self.provider_name}'"
            )
        master = self._keys.get(wrapped.master_key_id)
        if master is None:
            raise KeyManagementError(
                f"Master key '{wrapped.master_key_id}' is not available "
                "(revoked or not configured)"
            )
        bound_aad = self._bind_aad(wrapped.master_key_id, aad)
        return decrypt_bytes(master, wrapped.ciphertext, bound_aad)

    @staticmethod
    def _bind_aad(key_id: str, aad: bytes | None) -> bytes:
        """Bind the master key id (and optional caller AAD) into the GCM AAD."""
        prefix = key_id.encode("ascii")
        return prefix if aad is None else prefix + b"|" + aad
