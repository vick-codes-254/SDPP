"""Application configuration.

All secrets and security parameters are sourced from the environment (12-factor).
Nothing security-sensitive is ever hard-coded. Values are validated at startup so
the process fails fast on an insecure/misconfigured deployment.
"""

from __future__ import annotations

import base64
from enum import StrEnum
from functools import lru_cache
from typing import Annotated

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class AppEnv(StrEnum):
    development = "development"
    staging = "staging"
    production = "production"


class KMSProvider(StrEnum):
    local = "local"
    aws = "aws"
    azure = "azure"
    vault = "vault"


class Settings(BaseSettings):
    """Strongly-typed, validated application settings."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Application ─────────────────────────────────────────────
    app_name: str = "Secure Data Protection Platform"
    app_env: AppEnv = AppEnv.development
    debug: bool = False
    api_v1_prefix: str = "/api/v1"
    log_level: str = "INFO"

    # ── Server / CORS ───────────────────────────────────────────
    host: str = "0.0.0.0"  # noqa: S104 - bind handled by reverse proxy/container network
    port: int = 8000
    cors_origins: str = "http://localhost:5173"

    # ── Database ────────────────────────────────────────────────
    database_url: str = "postgresql+asyncpg://sdpp:sdpp_pw@localhost:5432/sdpp"
    database_url_sync: str = "postgresql+psycopg://sdpp:sdpp_pw@localhost:5432/sdpp"
    db_echo: bool = False

    # ── JWT ─────────────────────────────────────────────────────
    jwt_secret_key: str = Field(default="dev-insecure-change-me", min_length=8)
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 15
    refresh_token_expire_days: int = 7
    jwt_issuer: str = "sdpp"
    jwt_audience: str = "sdpp-clients"

    # ── KMS / Master Key ────────────────────────────────────────
    kms_provider: KMSProvider = KMSProvider.local
    master_key: str = ""  # base64 32 bytes (local provider)
    master_key_previous: str = ""  # comma-separated old keys for rotation
    aws_kms_key_id: str = ""
    aws_region: str = "us-east-1"
    azure_key_vault_url: str = ""
    azure_key_name: str = ""
    vault_addr: str = ""
    vault_token: str = ""
    vault_transit_key: str = "sdpp-master"

    # ── Argon2id password policy ────────────────────────────────
    argon2_time_cost: int = 3
    argon2_memory_cost_kib: int = 65536
    argon2_parallelism: int = 4
    argon2_hash_len: int = 32
    argon2_salt_len: int = 16
    password_min_length: int = 12
    password_history_size: int = 5
    password_max_age_days: int = 90
    max_failed_logins: int = 5
    account_lockout_minutes: int = 15

    # ── Startup bootstrap (optional initial admin) ──────────────
    bootstrap_admin_username: str = ""
    bootstrap_admin_email: str = ""
    bootstrap_admin_password: str = ""

    # ── File vault ──────────────────────────────────────────────
    vault_storage_path: str = "./var/vault"
    max_upload_size_mb: int = 2048
    key_rotation_days: int = 90
    integrity_algorithm: str = "sha256"

    # ── Security headers / TLS ──────────────────────────────────
    enable_hsts: bool = True
    hsts_max_age: int = 63072000
    enable_secure_cookies: bool = True

    # ───────────────────────── Validators ──────────────────────

    @field_validator("master_key")
    @classmethod
    def _validate_master_key(cls, v: str) -> str:
        if not v:
            return v
        try:
            raw = base64.b64decode(v, validate=True)
        except Exception as exc:  # noqa: BLE001
            raise ValueError("MASTER_KEY must be valid base64") from exc
        if len(raw) != 32:
            raise ValueError(
                f"MASTER_KEY must decode to 32 bytes (got {len(raw)}). "
                "Generate: python -c \"import os,base64;"
                "print(base64.b64encode(os.urandom(32)).decode())\""
            )
        return v

    @model_validator(mode="after")
    def _enforce_production_hardening(self) -> Settings:
        """Fail fast on insecure production configuration."""
        if self.app_env is AppEnv.production:
            problems: list[str] = []
            if self.debug:
                problems.append("DEBUG must be false in production")
            if self.jwt_secret_key in ("", "dev-insecure-change-me"):
                problems.append("JWT_SECRET_KEY must be set to a strong secret")
            if len(self.jwt_secret_key) < 32:
                problems.append("JWT_SECRET_KEY must be >= 32 chars in production")
            if self.kms_provider is KMSProvider.local and not self.master_key:
                problems.append("MASTER_KEY required for local KMS provider")
            if "*" in self.cors_origins:
                problems.append("Wildcard CORS origin is forbidden in production")
            if not self.enable_hsts:
                problems.append("HSTS must be enabled in production")
            if problems:
                raise ValueError(
                    "Insecure production configuration:\n  - " + "\n  - ".join(problems)
                )
        return self

    # ───────────────────────── Helpers ─────────────────────────

    @property
    def cors_origins_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def master_key_bytes(self) -> bytes:
        if not self.master_key:
            raise RuntimeError("MASTER_KEY is not configured for the local KMS provider")
        return base64.b64decode(self.master_key)

    @property
    def previous_master_keys_bytes(self) -> list[bytes]:
        return [
            base64.b64decode(k.strip())
            for k in self.master_key_previous.split(",")
            if k.strip()
        ]

    @property
    def is_production(self) -> bool:
        return self.app_env is AppEnv.production


@lru_cache
def get_settings() -> Settings:
    """Cached settings singleton (one parse per process)."""
    return Settings()


SettingsDep = Annotated[Settings, Field(default_factory=get_settings)]
