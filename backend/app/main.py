"""SDPP FastAPI application factory.

Wires configuration, structured logging, security middleware, CORS, exception
handlers, routers, and OpenAPI (bearer auth). On startup it runs the idempotent
bootstrap (field cipher, RBAC seed, optional admin).
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from collections.abc import AsyncIterator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import __version__
from app.api.errors import register_exception_handlers
from app.api.middleware import SecurityHeadersMiddleware
from app.api.routers import build_api_router, health
from app.core.bootstrap import run_startup_bootstrap
from app.core.config import Settings, get_settings
from app.core.logging import configure_logging, get_logger

logger = get_logger("app")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings: Settings = app.state.settings
    logger.info("startup", env=str(settings.app_env), version=__version__)
    try:
        from app.db.session import get_engine, get_sessionmaker

        # In non-production, self-provision any missing tables so the running app
        # always matches the ORM models. Production schema is owned by Alembic.
        if not settings.is_production:
            from app.models import Base

            async with get_engine().begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            logger.info("schema_synced", tables=len(Base.metadata.tables))

        async with get_sessionmaker()() as session:
            await run_startup_bootstrap(session, settings)
    except Exception as exc:  # noqa: BLE001 - never crash boot on a transient DB hiccup
        logger.error("startup_bootstrap_failed", error=str(exc))
    yield
    logger.info("shutdown")


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings.log_level, json_output=settings.is_production)

    app = FastAPI(
        title=settings.app_name,
        version=__version__,
        description=(
            "Secure Data Protection Platform — encryption, integrity verification, "
            "key management, tamper-evident auditing, and compliance reporting."
        ),
        docs_url=None if settings.is_production else "/docs",
        redoc_url=None if settings.is_production else "/redoc",
        openapi_url="/openapi.json" if not settings.is_production else None,
        lifespan=lifespan,
    )
    app.state.settings = settings

    # ── Middleware (order matters: outermost first) ─────────────
    app.add_middleware(SecurityHeadersMiddleware, settings=settings)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins_list,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type"],
        max_age=600,
    )

    register_exception_handlers(app)

    # ── Routers ─────────────────────────────────────────────────
    app.include_router(health.router)
    app.include_router(build_api_router(settings.api_v1_prefix))

    return app


app = create_app()
