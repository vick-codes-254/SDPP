"""API routers."""

from fastapi import APIRouter

from app.api.routers import audit, auth, compliance, dashboard, files, health, keys


def build_api_router(prefix: str) -> APIRouter:
    router = APIRouter(prefix=prefix)
    router.include_router(auth.router)
    router.include_router(files.router)
    router.include_router(keys.router)
    router.include_router(audit.router)
    router.include_router(dashboard.router)
    router.include_router(compliance.router)
    return router


__all__ = ["build_api_router", "health"]
