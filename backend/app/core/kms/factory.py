"""Master-key provider factory — selects the provider from settings."""

from __future__ import annotations

from functools import lru_cache

from app.core.config import KMSProvider, Settings, get_settings
from app.core.kms.base import MasterKeyProvider
from app.core.security.exceptions import KeyManagementError


def build_master_key_provider(settings: Settings | None = None) -> MasterKeyProvider:
    """Construct the configured :class:`MasterKeyProvider`."""
    s = settings or get_settings()

    if s.kms_provider is KMSProvider.local:
        from app.core.kms.local import LocalMasterKeyProvider

        return LocalMasterKeyProvider(
            current_key=s.master_key_bytes,
            previous_keys=s.previous_master_keys_bytes,
        )

    if s.kms_provider is KMSProvider.aws:
        from app.core.kms.cloud import AWSKMSProvider

        return AWSKMSProvider(key_id=s.aws_kms_key_id, region=s.aws_region)

    if s.kms_provider is KMSProvider.azure:
        from app.core.kms.cloud import AzureKeyVaultProvider

        return AzureKeyVaultProvider(
            vault_url=s.azure_key_vault_url, key_name=s.azure_key_name
        )

    if s.kms_provider is KMSProvider.vault:
        from app.core.kms.cloud import HashiCorpVaultProvider

        return HashiCorpVaultProvider(
            addr=s.vault_addr, token=s.vault_token, transit_key=s.vault_transit_key
        )

    raise KeyManagementError(f"Unknown KMS provider: {s.kms_provider}")  # pragma: no cover


@lru_cache
def get_master_key_provider() -> MasterKeyProvider:
    """Cached application-wide master-key provider."""
    return build_master_key_provider()
