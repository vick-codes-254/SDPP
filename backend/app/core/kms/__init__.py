"""Key Management Service (KMS) abstraction layer.

Provides a uniform interface for protecting Data Encryption Keys (DEKs) with a
Master Key (Key-Encrypting-Key, KEK), regardless of where the master key lives:

* ``local`` — symmetric master key from the environment (dev / on-prem / air-gapped)
* ``aws``   — AWS KMS (master key never leaves the HSM)
* ``azure`` — Azure Key Vault
* ``vault`` — HashiCorp Vault (Transit secrets engine)

The :class:`~app.core.kms.base.MasterKeyProvider` interface mirrors the AWS KMS
"GenerateDataKey / Encrypt / Decrypt" model so envelope encryption code is
provider-agnostic.
"""

from app.core.kms.base import MasterKeyProvider, WrappedKey
from app.core.kms.factory import build_master_key_provider

__all__ = ["MasterKeyProvider", "WrappedKey", "build_master_key_provider"]
