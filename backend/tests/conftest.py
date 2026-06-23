"""Shared pytest fixtures for SDPP.

Keeps the test environment hermetic: development settings, ephemeral master keys,
and low-cost password parameters so the suite is fast and deterministic.
"""

from __future__ import annotations

import os

import pytest

# Ensure tests never accidentally run under production hardening rules.
os.environ.setdefault("APP_ENV", "development")


@pytest.fixture
def master_key_bytes() -> bytes:
    """A fresh 256-bit master key for the local KMS provider."""
    return os.urandom(32)


@pytest.fixture
def local_provider(master_key_bytes: bytes):  # noqa: ANN201
    from app.core.kms.local import LocalMasterKeyProvider

    return LocalMasterKeyProvider(master_key_bytes)


@pytest.fixture
def envelope(local_provider):  # noqa: ANN001, ANN201
    from app.core.security.envelope import EnvelopeEncryptor

    return EnvelopeEncryptor(local_provider)


@pytest.fixture
def fast_password_manager():  # noqa: ANN201
    """Argon2id manager with low cost params for fast tests."""
    from app.core.security.passwords import PasswordManager

    return PasswordManager(time_cost=1, memory_cost=8192, parallelism=1)
