"""Tenancy & physical-estate schemas: organizations, branches, departments,
sites, buildings, zones, checkpoints."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.core.enums import (
    CheckpointType,
    OrgStatus,
    SiteStatus,
    SiteType,
    SubscriptionPlan,
    ZoneType,
)


# ── Organizations ───────────────────────────────────────────────
class OrganizationCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    slug: str = Field(min_length=2, max_length=64, pattern=r"^[a-z0-9][a-z0-9-]*$")
    plan: SubscriptionPlan = SubscriptionPlan.trial
    contact_email: str | None = None
    contact_phone: str | None = None
    address: str | None = None
    country: str | None = None
    timezone: str = "UTC"


class OrganizationUpdate(BaseModel):
    name: str | None = None
    status: OrgStatus | None = None
    plan: SubscriptionPlan | None = None
    contact_email: str | None = None
    contact_phone: str | None = None
    address: str | None = None
    country: str | None = None
    timezone: str | None = None
    is_active: bool | None = None


class OrganizationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    name: str
    slug: str
    status: OrgStatus
    plan: SubscriptionPlan
    contact_email: str | None = None
    contact_phone: str | None = None
    country: str | None = None
    timezone: str
    is_active: bool
    created_at: datetime


# ── Branches & departments ──────────────────────────────────────
class BranchCreate(BaseModel):
    organization_id: uuid.UUID
    name: str = Field(min_length=1, max_length=255)
    code: str | None = None
    city: str | None = None
    country: str | None = None


class BranchResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    organization_id: uuid.UUID
    name: str
    code: str | None = None
    city: str | None = None
    country: str | None = None


class DepartmentCreate(BaseModel):
    organization_id: uuid.UUID
    name: str = Field(min_length=1, max_length=255)
    parent_id: uuid.UUID | None = None


class DepartmentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    organization_id: uuid.UUID
    name: str
    parent_id: uuid.UUID | None = None


# ── Sites ───────────────────────────────────────────────────────
class SiteCreate(BaseModel):
    organization_id: uuid.UUID
    name: str = Field(min_length=1, max_length=255)
    code: str | None = None
    site_type: SiteType = SiteType.office
    branch_id: uuid.UUID | None = None
    address: str | None = None
    city: str | None = None
    country: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    timezone: str = "UTC"


class SiteUpdate(BaseModel):
    name: str | None = None
    code: str | None = None
    site_type: SiteType | None = None
    status: SiteStatus | None = None
    address: str | None = None
    city: str | None = None
    country: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    timezone: str | None = None


class SiteResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    organization_id: uuid.UUID
    name: str
    code: str | None = None
    site_type: SiteType
    status: SiteStatus
    branch_id: uuid.UUID | None = None
    city: str | None = None
    country: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    timezone: str
    created_at: datetime


# ── Buildings ───────────────────────────────────────────────────
class BuildingCreate(BaseModel):
    site_id: uuid.UUID
    name: str = Field(min_length=1, max_length=255)
    floors: int = Field(default=1, ge=1, le=300)


class BuildingResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    site_id: uuid.UUID
    name: str
    floors: int


# ── Zones ───────────────────────────────────────────────────────
class ZoneCreate(BaseModel):
    organization_id: uuid.UUID
    site_id: uuid.UUID
    building_id: uuid.UUID | None = None
    name: str = Field(min_length=1, max_length=255)
    zone_type: ZoneType = ZoneType.general
    floor: int | None = None
    is_restricted: bool = False


class ZoneResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    organization_id: uuid.UUID
    site_id: uuid.UUID
    building_id: uuid.UUID | None = None
    name: str
    zone_type: ZoneType
    floor: int | None = None
    is_restricted: bool


# ── Checkpoints ─────────────────────────────────────────────────
class CheckpointCreate(BaseModel):
    organization_id: uuid.UUID
    site_id: uuid.UUID
    zone_id: uuid.UUID | None = None
    name: str = Field(min_length=1, max_length=255)
    checkpoint_type: CheckpointType = CheckpointType.qr
    code: str = Field(min_length=1, max_length=64)
    latitude: float | None = None
    longitude: float | None = None


class CheckpointResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    organization_id: uuid.UUID
    site_id: uuid.UUID
    zone_id: uuid.UUID | None = None
    name: str
    checkpoint_type: CheckpointType
    code: str
    latitude: float | None = None
    longitude: float | None = None
    is_active: bool
