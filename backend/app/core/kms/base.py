"""KMS provider interface and the wrapped-key envelope record."""

from __future__ import annotations

import base64
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class WrappedKey:
    """A Data Encryption Key (DEK) encrypted by a master key (KEK).

    This is the persisted "envelope": it records *which* master key wrapped the
    DEK and *how*, so the correct provider/key can unwrap it later — even across
    master-key rotations.
    """

    provider: str
    master_key_id: str
    algorithm: str
    ciphertext: bytes  # the wrapped/encrypted DEK

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "master_key_id": self.master_key_id,
            "algorithm": self.algorithm,
            "ciphertext": base64.b64encode(self.ciphertext).decode("ascii"),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> WrappedKey:
        return cls(
            provider=data["provider"],
            master_key_id=data["master_key_id"],
            algorithm=data["algorithm"],
            ciphertext=base64.b64decode(data["ciphertext"]),
        )


class MasterKeyProvider(ABC):
    """Abstract master-key provider.

    Implementations protect DEKs without exposing the master key to the rest of
    the application. Cloud implementations keep the master key inside an HSM and
    never return it.
    """

    provider_name: str

    @abstractmethod
    def current_key_id(self) -> str:
        """Identifier of the master key currently used for new wrap operations."""

    @abstractmethod
    def wrap(self, dek: bytes, aad: bytes | None = None) -> WrappedKey:
        """Encrypt (wrap) a DEK with the current master key."""

    @abstractmethod
    def unwrap(self, wrapped: WrappedKey, aad: bytes | None = None) -> bytes:
        """Decrypt (unwrap) a DEK using the master key referenced in ``wrapped``."""

    def generate_data_key(self, aad: bytes | None = None) -> tuple[bytes, WrappedKey]:
        """Generate a fresh 256-bit DEK and return ``(plaintext_dek, wrapped_dek)``.

        Mirrors AWS KMS ``GenerateDataKey``. The plaintext DEK is used immediately
        to encrypt data and then discarded; only the wrapped form is persisted.
        Cloud providers override this to generate the key inside the HSM.
        """
        from app.core.security.crypto import generate_key

        dek = generate_key()
        return dek, self.wrap(dek, aad)
