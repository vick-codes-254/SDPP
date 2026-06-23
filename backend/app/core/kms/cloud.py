"""Cloud / external KMS provider integrations.

These implement :class:`MasterKeyProvider` against managed key services where the
master key never leaves the HSM. The data-key model is identical to AWS KMS:

    GenerateDataKey -> (plaintext_dek, ciphertext_dek)
    Decrypt(ciphertext_dek) -> plaintext_dek

The corresponding SDKs (``boto3``, ``azure-keyvault-keys``, ``hvac``) are
*optional* runtime dependencies — they are imported lazily so the core platform
runs without them. Each provider documents the exact API calls it makes and
raises :class:`KeyManagementError` with actionable guidance when unconfigured.
"""

from __future__ import annotations

from app.core.kms.base import MasterKeyProvider, WrappedKey
from app.core.security.exceptions import KeyManagementError


class AWSKMSProvider(MasterKeyProvider):
    """AWS KMS-backed master key.

    Uses ``kms.generate_data_key`` for envelope DEKs and ``kms.encrypt`` /
    ``kms.decrypt`` for wrapping externally-supplied DEKs. The encryption context
    (``aad``) is passed as the KMS ``EncryptionContext`` for additional binding.
    """

    provider_name = "aws"
    _ALGORITHM = "AWS_KMS"

    def __init__(self, key_id: str, region: str) -> None:
        if not key_id:
            raise KeyManagementError("AWS_KMS_KEY_ID is required for the aws provider")
        self._key_id = key_id
        self._region = region
        self._client = self._make_client()

    def _make_client(self):  # type: ignore[no-untyped-def]
        try:
            import boto3  # type: ignore[import-not-found]
        except ImportError as exc:  # pragma: no cover - optional dep
            raise KeyManagementError(
                "boto3 is required for the AWS KMS provider: pip install boto3"
            ) from exc
        return boto3.client("kms", region_name=self._region)

    @staticmethod
    def _context(aad: bytes | None) -> dict[str, str]:
        return {"sdpp_aad": aad.hex()} if aad else {}

    def current_key_id(self) -> str:
        return self._key_id

    def generate_data_key(self, aad: bytes | None = None) -> tuple[bytes, WrappedKey]:
        resp = self._client.generate_data_key(
            KeyId=self._key_id, KeySpec="AES_256", EncryptionContext=self._context(aad)
        )
        wrapped = WrappedKey(
            provider=self.provider_name,
            master_key_id=self._key_id,
            algorithm=self._ALGORITHM,
            ciphertext=resp["CiphertextBlob"],
        )
        return resp["Plaintext"], wrapped

    def wrap(self, dek: bytes, aad: bytes | None = None) -> WrappedKey:
        resp = self._client.encrypt(
            KeyId=self._key_id, Plaintext=dek, EncryptionContext=self._context(aad)
        )
        return WrappedKey(
            provider=self.provider_name,
            master_key_id=self._key_id,
            algorithm=self._ALGORITHM,
            ciphertext=resp["CiphertextBlob"],
        )

    def unwrap(self, wrapped: WrappedKey, aad: bytes | None = None) -> bytes:
        resp = self._client.decrypt(
            CiphertextBlob=wrapped.ciphertext, EncryptionContext=self._context(aad)
        )
        return resp["Plaintext"]


class AzureKeyVaultProvider(MasterKeyProvider):
    """Azure Key Vault-backed master key (wrap/unwrap key operations)."""

    provider_name = "azure"
    _ALGORITHM = "RSA-OAEP-256"

    def __init__(self, vault_url: str, key_name: str) -> None:
        if not vault_url or not key_name:
            raise KeyManagementError(
                "AZURE_KEY_VAULT_URL and AZURE_KEY_NAME are required for the azure provider"
            )
        self._vault_url = vault_url
        self._key_name = key_name
        self._crypto = self._make_client()

    def _make_client(self):  # type: ignore[no-untyped-def]
        try:
            from azure.identity import DefaultAzureCredential  # type: ignore[import-not-found]
            from azure.keyvault.keys import KeyClient  # type: ignore[import-not-found]
            from azure.keyvault.keys.crypto import CryptographyClient  # type: ignore[import-not-found]
        except ImportError as exc:  # pragma: no cover - optional dep
            raise KeyManagementError(
                "azure-keyvault-keys and azure-identity are required for the azure provider"
            ) from exc
        cred = DefaultAzureCredential()
        key = KeyClient(vault_url=self._vault_url, credential=cred).get_key(self._key_name)
        return CryptographyClient(key, credential=cred)

    def current_key_id(self) -> str:
        return self._key_name

    def wrap(self, dek: bytes, aad: bytes | None = None) -> WrappedKey:
        from azure.keyvault.keys.crypto import KeyWrapAlgorithm  # type: ignore[import-not-found]

        result = self._crypto.wrap_key(KeyWrapAlgorithm.rsa_oaep_256, dek)
        return WrappedKey(
            provider=self.provider_name,
            master_key_id=self._key_name,
            algorithm=self._ALGORITHM,
            ciphertext=result.encrypted_key,
        )

    def unwrap(self, wrapped: WrappedKey, aad: bytes | None = None) -> bytes:
        from azure.keyvault.keys.crypto import KeyWrapAlgorithm  # type: ignore[import-not-found]

        result = self._crypto.unwrap_key(KeyWrapAlgorithm.rsa_oaep_256, wrapped.ciphertext)
        return result.key


class HashiCorpVaultProvider(MasterKeyProvider):
    """HashiCorp Vault Transit secrets engine-backed master key."""

    provider_name = "vault"
    _ALGORITHM = "VAULT_TRANSIT"

    def __init__(self, addr: str, token: str, transit_key: str) -> None:
        if not addr or not token:
            raise KeyManagementError(
                "VAULT_ADDR and VAULT_TOKEN are required for the vault provider"
            )
        self._transit_key = transit_key
        self._client = self._make_client(addr, token)

    def _make_client(self, addr: str, token: str):  # type: ignore[no-untyped-def]
        try:
            import hvac  # type: ignore[import-not-found]
        except ImportError as exc:  # pragma: no cover - optional dep
            raise KeyManagementError(
                "hvac is required for the HashiCorp Vault provider: pip install hvac"
            ) from exc
        client = hvac.Client(url=addr, token=token)
        if not client.is_authenticated():
            raise KeyManagementError("Vault authentication failed")
        return client

    def current_key_id(self) -> str:
        return self._transit_key

    def wrap(self, dek: bytes, aad: bytes | None = None) -> WrappedKey:
        import base64

        resp = self._client.secrets.transit.encrypt_data(
            name=self._transit_key,
            plaintext=base64.b64encode(dek).decode("ascii"),
        )
        ciphertext = resp["data"]["ciphertext"].encode("ascii")  # vault:v1:...
        return WrappedKey(
            provider=self.provider_name,
            master_key_id=self._transit_key,
            algorithm=self._ALGORITHM,
            ciphertext=ciphertext,
        )

    def unwrap(self, wrapped: WrappedKey, aad: bytes | None = None) -> bytes:
        import base64

        resp = self._client.secrets.transit.decrypt_data(
            name=self._transit_key,
            ciphertext=wrapped.ciphertext.decode("ascii"),
        )
        return base64.b64decode(resp["data"]["plaintext"])
