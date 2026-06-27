"""System administration endpoints: feature flags, settings, backups, integrations."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, status

from app.api.deps import get_admin_service, require_permission
from app.schemas.saas import (
    BackupCreate,
    BackupResponse,
    FlagResponse,
    FlagSet,
    IntegrationCreate,
    IntegrationResponse,
    IntegrationStatusReq,
    SettingResponse,
    SettingSet,
)
from app.services.admin_service import AdminService

router = APIRouter(prefix="/admin", tags=["system-administration"])

Dep = Annotated[AdminService, Depends(get_admin_service)]
Admin = Annotated[object, Depends(require_permission("system:admin"))]


# ── Feature flags ───────────────────────────────────────────────
@router.get("/feature-flags", response_model=list[FlagResponse])
async def list_flags(svc: Dep, _: Admin, organization_id: uuid.UUID | None = None) -> list[FlagResponse]:
    return [FlagResponse.model_validate(f) for f in await svc.list_flags(organization_id=organization_id)]


@router.post("/feature-flags", response_model=FlagResponse)
async def set_flag(body: FlagSet, svc: Dep, _: Admin) -> FlagResponse:
    flag = await svc.set_flag(
        key=body.key, enabled=body.enabled, organization_id=body.organization_id,
        description=body.description,
    )
    return FlagResponse.model_validate(flag)


# ── Settings ────────────────────────────────────────────────────
@router.get("/settings", response_model=list[SettingResponse])
async def list_settings(svc: Dep, _: Admin, organization_id: uuid.UUID | None = None) -> list[SettingResponse]:
    return [SettingResponse.model_validate(s) for s in await svc.list_settings(organization_id=organization_id)]


@router.post("/settings", response_model=SettingResponse)
async def set_setting(body: SettingSet, svc: Dep, _: Admin) -> SettingResponse:
    setting = await svc.set_setting(
        key=body.key, value=body.value, scope=body.scope, organization_id=body.organization_id,
    )
    return SettingResponse.model_validate(setting)


# ── Backups ─────────────────────────────────────────────────────
@router.get("/backups", response_model=list[BackupResponse])
async def list_backups(svc: Dep, _: Admin, organization_id: uuid.UUID | None = None) -> list[BackupResponse]:
    return [BackupResponse.model_validate(b) for b in await svc.list_backups(organization_id=organization_id)]


@router.post("/backups", response_model=BackupResponse, status_code=status.HTTP_201_CREATED)
async def create_backup(body: BackupCreate, svc: Dep, _: Admin) -> BackupResponse:
    rec = await svc.create_backup(organization_id=body.organization_id, note=body.note)
    return BackupResponse.model_validate(rec)


# ── Integrations ────────────────────────────────────────────────
@router.get("/integrations", response_model=list[IntegrationResponse])
async def list_integrations(organization_id: uuid.UUID, svc: Dep, _: Admin) -> list[IntegrationResponse]:
    return [IntegrationResponse.model_validate(i) for i in await svc.list_integrations(organization_id=organization_id)]


@router.post("/integrations", response_model=IntegrationResponse, status_code=status.HTTP_201_CREATED)
async def create_integration(body: IntegrationCreate, svc: Dep, _: Admin) -> IntegrationResponse:
    integ = await svc.create_integration(body.model_dump())
    return IntegrationResponse.model_validate(integ)


@router.post("/integrations/{integration_id}/status", response_model=IntegrationResponse)
async def set_integration_status(
    integration_id: uuid.UUID, body: IntegrationStatusReq, svc: Dep, _: Admin
) -> IntegrationResponse:
    integ = await svc.set_integration_status(integration_id, active=body.active)
    return IntegrationResponse.model_validate(integ)
