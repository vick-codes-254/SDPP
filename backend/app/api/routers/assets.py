"""Asset management endpoints."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query, status

from app.api.deps import get_asset_service, require_permission
from app.core.enums import AssetCriticality, AssetStatus, AssetType
from app.schemas.common import Message
from app.schemas.smp import AssetCreate, AssetResponse, AssetUpdate
from app.services.asset_service import AssetData, AssetService, SoftwareEntry

router = APIRouter(prefix="/assets", tags=["asset-management"])

AssetDep = Annotated[AssetService, Depends(get_asset_service)]


@router.get("", response_model=list[AssetResponse])
async def list_assets(
    assets: AssetDep,
    principal: Annotated[object, Depends(require_permission("asset:read"))],
    asset_type: AssetType | None = None,
    criticality: AssetCriticality | None = None,
    status_filter: Annotated[AssetStatus | None, Query(alias="status")] = None,
    search: str | None = None,
) -> list[AssetResponse]:
    rows = await assets.list(
        asset_type=asset_type, criticality=criticality, status=status_filter, search=search
    )
    return [AssetResponse.model_validate(a) for a in rows]


@router.post("", response_model=AssetResponse, status_code=status.HTTP_201_CREATED)
async def create_asset(
    body: AssetCreate,
    assets: AssetDep,
    principal: Annotated[object, Depends(require_permission("asset:manage"))],
) -> AssetResponse:
    data = AssetData(
        name=body.name, asset_type=body.asset_type, hostname=body.hostname,
        ip_address=body.ip_address, mac_address=body.mac_address,
        operating_system=body.operating_system, os_version=body.os_version,
        criticality=body.criticality, owner=body.owner, location=body.location,
        tags=body.tags, notes=body.notes,
        software=[SoftwareEntry(s.name, s.version, s.vendor) for s in body.software],
    )
    asset = await assets.create(data, actor_id=principal.user_id)  # type: ignore[attr-defined]
    return AssetResponse.model_validate(asset)


@router.get("/{asset_id}", response_model=AssetResponse)
async def get_asset(
    asset_id: uuid.UUID,
    assets: AssetDep,
    principal: Annotated[object, Depends(require_permission("asset:read"))],
) -> AssetResponse:
    return AssetResponse.model_validate(await assets.get_or_404(asset_id))


@router.patch("/{asset_id}", response_model=AssetResponse)
async def update_asset(
    asset_id: uuid.UUID,
    body: AssetUpdate,
    assets: AssetDep,
    principal: Annotated[object, Depends(require_permission("asset:manage"))],
) -> AssetResponse:
    asset = await assets.update(
        asset_id, body.model_dump(exclude_unset=True), actor_id=principal.user_id  # type: ignore[attr-defined]
    )
    return AssetResponse.model_validate(asset)


@router.delete("/{asset_id}", response_model=Message)
async def delete_asset(
    asset_id: uuid.UUID,
    assets: AssetDep,
    principal: Annotated[object, Depends(require_permission("asset:manage"))],
) -> Message:
    await assets.delete(asset_id, actor_id=principal.user_id)  # type: ignore[attr-defined]
    return Message(detail="Asset deleted")
