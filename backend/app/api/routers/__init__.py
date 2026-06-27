"""API routers."""

from fastapi import APIRouter

from app.api.routers import (
    access,
    admin,
    analytics,
    assets,
    audit,
    auth,
    billing,
    cameras,
    comms,
    compliance,
    cyber,
    dashboard,
    detections,
    discovery,
    emergency,
    evidence,
    files,
    guards,
    health,
    incidents,
    keys,
    notifications,
    organizations,
    sites,
    users,
    vehicles,
    visitors,
    vulns,
    workflows,
)


def build_api_router(prefix: str) -> APIRouter:
    router = APIRouter(prefix=prefix)
    # SDPP — Encryption & Security Layer
    router.include_router(auth.router)
    router.include_router(files.router)
    router.include_router(keys.router)
    router.include_router(audit.router)
    router.include_router(dashboard.router)
    router.include_router(compliance.router)
    # Unified Security Platform — tenancy & physical estate
    router.include_router(organizations.router)
    router.include_router(sites.router)
    # Physical security
    router.include_router(cameras.router)
    router.include_router(guards.router)
    router.include_router(visitors.router)
    router.include_router(access.router)
    router.include_router(vehicles.router)
    # AI detection & threat intelligence
    router.include_router(detections.router)
    # SecOps: alert delivery, emergency response, evidence
    router.include_router(notifications.router)
    router.include_router(emergency.router)
    router.include_router(evidence.router)
    # Cybersecurity monitoring & SOC
    router.include_router(cyber.router)
    # Analytics, communication, workflow automation
    router.include_router(analytics.router)
    router.include_router(comms.router)
    router.include_router(workflows.router)
    # SaaS: billing & system administration
    router.include_router(billing.router)
    router.include_router(admin.router)
    # Security Monitoring Platform modules
    router.include_router(assets.router)
    router.include_router(discovery.router)
    router.include_router(vulns.router)
    router.include_router(incidents.router)
    router.include_router(users.router)
    return router


__all__ = ["build_api_router", "health"]
