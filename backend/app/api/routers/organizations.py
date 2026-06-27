"""Organization management endpoints: organizations, branches, departments."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, status

from app.api.deps import get_org_service, require_permission
from app.schemas.common import Message
from app.schemas.tenancy import (
    BranchCreate,
    BranchResponse,
    DepartmentCreate,
    DepartmentResponse,
    OrganizationCreate,
    OrganizationResponse,
    OrganizationUpdate,
)
from app.services.org_service import OrgService

router = APIRouter(prefix="/organizations", tags=["organization-management"])

OrgDep = Annotated[OrgService, Depends(get_org_service)]


@router.get("", response_model=list[OrganizationResponse])
async def list_organizations(
    svc: OrgDep,
    _: Annotated[object, Depends(require_permission("org:read"))],
) -> list[OrganizationResponse]:
    return [OrganizationResponse.model_validate(o) for o in await svc.list_orgs()]


@router.post("", response_model=OrganizationResponse, status_code=status.HTTP_201_CREATED)
async def create_organization(
    body: OrganizationCreate,
    svc: OrgDep,
    principal: Annotated[object, Depends(require_permission("org:manage"))],
) -> OrganizationResponse:
    org = await svc.create_org(body.model_dump(), actor_id=principal.user_id)  # type: ignore[attr-defined]
    return OrganizationResponse.model_validate(org)


@router.get("/{org_id}", response_model=OrganizationResponse)
async def get_organization(
    org_id: uuid.UUID,
    svc: OrgDep,
    _: Annotated[object, Depends(require_permission("org:read"))],
) -> OrganizationResponse:
    return OrganizationResponse.model_validate(await svc.get_org_or_404(org_id))


@router.patch("/{org_id}", response_model=OrganizationResponse)
async def update_organization(
    org_id: uuid.UUID,
    body: OrganizationUpdate,
    svc: OrgDep,
    principal: Annotated[object, Depends(require_permission("org:manage"))],
) -> OrganizationResponse:
    org = await svc.update_org(org_id, body.model_dump(exclude_unset=True), actor_id=principal.user_id)  # type: ignore[attr-defined]
    return OrganizationResponse.model_validate(org)


@router.delete("/{org_id}", response_model=Message)
async def delete_organization(
    org_id: uuid.UUID,
    svc: OrgDep,
    principal: Annotated[object, Depends(require_permission("org:manage"))],
) -> Message:
    await svc.delete_org(org_id, actor_id=principal.user_id)  # type: ignore[attr-defined]
    return Message(detail="Organization deleted")


# ── Branches ────────────────────────────────────────────────────
@router.get("/{org_id}/branches", response_model=list[BranchResponse])
async def list_branches(
    org_id: uuid.UUID,
    svc: OrgDep,
    _: Annotated[object, Depends(require_permission("org:read"))],
) -> list[BranchResponse]:
    return [BranchResponse.model_validate(b) for b in await svc.list_branches(org_id)]


@router.post("/branches", response_model=BranchResponse, status_code=status.HTTP_201_CREATED)
async def create_branch(
    body: BranchCreate,
    svc: OrgDep,
    principal: Annotated[object, Depends(require_permission("org:manage"))],
) -> BranchResponse:
    branch = await svc.create_branch(body.model_dump(), actor_id=principal.user_id)  # type: ignore[attr-defined]
    return BranchResponse.model_validate(branch)


# ── Departments ─────────────────────────────────────────────────
@router.get("/{org_id}/departments", response_model=list[DepartmentResponse])
async def list_departments(
    org_id: uuid.UUID,
    svc: OrgDep,
    _: Annotated[object, Depends(require_permission("org:read"))],
) -> list[DepartmentResponse]:
    return [DepartmentResponse.model_validate(d) for d in await svc.list_departments(org_id)]


@router.post("/departments", response_model=DepartmentResponse, status_code=status.HTTP_201_CREATED)
async def create_department(
    body: DepartmentCreate,
    svc: OrgDep,
    principal: Annotated[object, Depends(require_permission("org:manage"))],
) -> DepartmentResponse:
    dept = await svc.create_department(body.model_dump(), actor_id=principal.user_id)  # type: ignore[attr-defined]
    return DepartmentResponse.model_validate(dept)
