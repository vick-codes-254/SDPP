"""Async database & API client fixtures for integration tests (SQLite)."""

from __future__ import annotations

import base64
import os
from collections.abc import AsyncGenerator, AsyncIterator

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from app.core.security.crypto import generate_key
from app.core.security.field_encryption import FieldCipher, set_field_cipher
from app.models import Base
from tests.integration.api_helpers import ADMIN_PW


@pytest.fixture(scope="session", autouse=True)
def _install_field_cipher() -> None:
    """Process-wide field cipher so encrypted columns work in tests."""
    set_field_cipher(FieldCipher(generate_key()))


@pytest_asyncio.fixture
async def async_session() -> AsyncGenerator[AsyncSession, None]:
    engine = create_async_engine(
        "sqlite+aiosqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    maker = async_sessionmaker(engine, expire_on_commit=False)
    async with maker() as session:
        yield session

    await engine.dispose()


@pytest_asyncio.fixture
async def client(tmp_path, monkeypatch) -> AsyncIterator[AsyncClient]:
    """A fully-bootstrapped API client backed by an isolated in-memory database."""
    monkeypatch.setenv("APP_ENV", "development")
    monkeypatch.setenv("JWT_SECRET_KEY", "test-jwt-secret-key-32-bytes-minimum!!")
    monkeypatch.setenv("MASTER_KEY", base64.b64encode(os.urandom(32)).decode())
    monkeypatch.setenv("VAULT_STORAGE_PATH", str(tmp_path / "vault"))
    monkeypatch.setenv("ARGON2_TIME_COST", "1")
    monkeypatch.setenv("ARGON2_MEMORY_COST_KIB", "8192")
    monkeypatch.setenv("ARGON2_PARALLELISM", "1")
    monkeypatch.setenv("BOOTSTRAP_ADMIN_USERNAME", "admin")
    monkeypatch.setenv("BOOTSTRAP_ADMIN_EMAIL", "admin@example.com")
    monkeypatch.setenv("BOOTSTRAP_ADMIN_PASSWORD", ADMIN_PW)

    from app.core import config
    from app.core.kms import factory
    import app.core.security.passwords as pw_mod
    import app.core.security.tokens as tok_mod

    config.get_settings.cache_clear()
    factory.get_master_key_provider.cache_clear()
    tok_mod._default_manager = None
    pw_mod._default_manager = None

    from app.core.bootstrap import run_startup_bootstrap
    from app.core.config import get_settings
    from app.db.session import get_db
    from app.main import create_app

    engine = create_async_engine(
        "sqlite+aiosqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    maker = async_sessionmaker(engine, expire_on_commit=False)

    app = create_app()

    async def _get_db():  # noqa: ANN202
        async with maker() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    app.dependency_overrides[get_db] = _get_db

    async with maker() as session:
        await run_startup_bootstrap(session, get_settings())

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
    await engine.dispose()
