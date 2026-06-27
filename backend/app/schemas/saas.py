"""SaaS schemas: billing, system administration, integrations."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.core.enums import (
    IntegrationKind,
    IntegrationStatus,
    InvoiceStatus,
    PaymentMethod,
    PaymentStatus,
    SettingScope,
    SubscriptionPlan,
    SubscriptionStatus,
)


# ── Subscriptions ───────────────────────────────────────────────
class SubscriptionUpsert(BaseModel):
    organization_id: uuid.UUID
    plan: SubscriptionPlan | None = None
    status: SubscriptionStatus | None = None
    seats: int | None = Field(default=None, ge=1)
    monthly_price: float | None = Field(default=None, ge=0)
    currency: str | None = None


class SubscriptionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    organization_id: uuid.UUID
    plan: SubscriptionPlan
    status: SubscriptionStatus
    seats: int
    monthly_price: float
    currency: str
    started_at: datetime | None = None
    current_period_end: datetime | None = None


# ── Invoices & payments ─────────────────────────────────────────
class InvoiceCreate(BaseModel):
    organization_id: uuid.UUID
    amount: float = Field(ge=0)
    currency: str = "USD"
    period_start: datetime | None = None
    period_end: datetime | None = None


class InvoiceResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    organization_id: uuid.UUID
    number: str
    status: InvoiceStatus
    amount: float
    currency: str
    issued_at: datetime | None = None
    paid_at: datetime | None = None
    created_at: datetime


class PayRequest(BaseModel):
    method: PaymentMethod = PaymentMethod.card
    reference: str | None = None


class PaymentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    organization_id: uuid.UUID
    invoice_id: uuid.UUID | None = None
    amount: float
    currency: str
    method: PaymentMethod
    status: PaymentStatus
    reference: str | None = None
    paid_at: datetime | None = None


# ── Feature flags & settings ────────────────────────────────────
class FlagSet(BaseModel):
    key: str = Field(min_length=1, max_length=64)
    enabled: bool
    organization_id: uuid.UUID | None = None
    description: str | None = None


class FlagResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    organization_id: uuid.UUID | None = None
    key: str
    enabled: bool
    description: str | None = None


class SettingSet(BaseModel):
    key: str = Field(min_length=1, max_length=64)
    value: dict
    scope: SettingScope = SettingScope.tenant
    organization_id: uuid.UUID | None = None


class SettingResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    organization_id: uuid.UUID | None = None
    scope: SettingScope
    key: str
    value: dict | None = None


# ── Backups ─────────────────────────────────────────────────────
class BackupCreate(BaseModel):
    organization_id: uuid.UUID | None = None
    note: str | None = None


class BackupResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    organization_id: uuid.UUID | None = None
    status: str
    location: str | None = None
    size_bytes: int | None = None
    note: str | None = None
    completed_at: datetime | None = None
    created_at: datetime


# ── Integrations ────────────────────────────────────────────────
class IntegrationCreate(BaseModel):
    organization_id: uuid.UUID
    name: str = Field(min_length=1, max_length=128)
    kind: IntegrationKind
    secret: str | None = None
    config: dict | None = None


class IntegrationStatusReq(BaseModel):
    active: bool


class IntegrationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    organization_id: uuid.UUID
    name: str
    kind: IntegrationKind
    status: IntegrationStatus
    config: dict | None = None
    last_sync_at: datetime | None = None
    created_at: datetime
