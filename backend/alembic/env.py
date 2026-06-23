"""Alembic migration environment.

Uses the *synchronous* database URL (psycopg) and pulls all settings from the
application config so no credentials live in alembic.ini. Imports the models
package so ``target_metadata`` reflects the full schema for autogenerate.
"""

from __future__ import annotations

from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

from app.core.config import get_settings

# Import models so their tables register on Base.metadata.
from app.models import Base  # noqa: F401  (side-effect import)

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Inject the runtime DB URL (sync driver) from settings.
config.set_main_option("sqlalchemy.url", get_settings().database_url_sync)

target_metadata = Base.metadata


def render_item(type_: str, obj: object, autogen_context: object) -> str | bool:
    """Render app-layer column types as their portable SQL impl in migrations.

    The transparent field-encryption ``TypeDecorator``s are an *application* layer
    concern; at the DDL level they are plain text columns. We also render the
    JSON/JSONB variant explicitly so the migration carries no unqualified names.
    """
    if type_ != "type":
        return False

    from sqlalchemy import JSON

    from app.core.security.field_encryption import (
        BlindIndex,
        EncryptedString,
        EncryptedText,
    )

    if isinstance(obj, EncryptedText):
        return "sa.Text()"
    if isinstance(obj, BlindIndex):
        return "sa.String(length=64)"
    if isinstance(obj, EncryptedString):
        return "sa.String()"
    if isinstance(obj, JSON):  # our JSONType variant (JSON base, JSONB on postgres)
        autogen_context.imports.add("from sqlalchemy.dialects import postgresql")  # type: ignore[attr-defined]
        return "sa.JSON().with_variant(postgresql.JSONB(), 'postgresql')"
    return False


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode (emit SQL without a DB connection)."""
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
        compare_type=True,
        compare_server_default=True,
        render_item=render_item,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations with a live DB connection."""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
            compare_server_default=True,
            render_item=render_item,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
