"""Billing & SaaS subscription endpoints."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, status

from app.api.deps import get_billing_service, require_permission
from app.schemas.saas import (
    InvoiceCreate,
    InvoiceResponse,
    PaymentResponse,
    PayRequest,
    SubscriptionResponse,
    SubscriptionUpsert,
)
from app.services.billing_service import BillingService

router = APIRouter(prefix="/billing", tags=["billing"])

Dep = Annotated[BillingService, Depends(get_billing_service)]


@router.get("/subscription", response_model=SubscriptionResponse | None)
async def get_subscription(
    organization_id: uuid.UUID,
    svc: Dep,
    _: Annotated[object, Depends(require_permission("billing:read"))],
) -> SubscriptionResponse | None:
    sub = await svc.get_subscription(organization_id)
    return SubscriptionResponse.model_validate(sub) if sub else None


@router.put("/subscription", response_model=SubscriptionResponse)
async def upsert_subscription(
    body: SubscriptionUpsert,
    svc: Dep,
    _: Annotated[object, Depends(require_permission("billing:manage"))],
) -> SubscriptionResponse:
    data = body.model_dump(exclude={"organization_id"}, exclude_none=True)
    sub = await svc.upsert_subscription(body.organization_id, data)
    return SubscriptionResponse.model_validate(sub)


@router.get("/invoices", response_model=list[InvoiceResponse])
async def list_invoices(
    organization_id: uuid.UUID,
    svc: Dep,
    _: Annotated[object, Depends(require_permission("billing:read"))],
) -> list[InvoiceResponse]:
    return [InvoiceResponse.model_validate(i) for i in await svc.list_invoices(organization_id)]


@router.post("/invoices", response_model=InvoiceResponse, status_code=status.HTTP_201_CREATED)
async def create_invoice(
    body: InvoiceCreate,
    svc: Dep,
    _: Annotated[object, Depends(require_permission("billing:manage"))],
) -> InvoiceResponse:
    data = body.model_dump(exclude={"organization_id"})
    inv = await svc.create_invoice(body.organization_id, data)
    return InvoiceResponse.model_validate(inv)


@router.post("/invoices/{invoice_id}/pay", response_model=PaymentResponse)
async def pay_invoice(
    invoice_id: uuid.UUID,
    body: PayRequest,
    svc: Dep,
    _: Annotated[object, Depends(require_permission("billing:manage"))],
) -> PaymentResponse:
    payment = await svc.pay_invoice(invoice_id, method=body.method, reference=body.reference)
    return PaymentResponse.model_validate(payment)


@router.get("/payments", response_model=list[PaymentResponse])
async def list_payments(
    organization_id: uuid.UUID,
    svc: Dep,
    _: Annotated[object, Depends(require_permission("billing:read"))],
) -> list[PaymentResponse]:
    return [PaymentResponse.model_validate(p) for p in await svc.list_payments(organization_id)]


@router.get("/usage", response_model=dict)
async def usage(
    organization_id: uuid.UUID,
    svc: Dep,
    _: Annotated[object, Depends(require_permission("billing:read"))],
) -> dict:
    return await svc.usage(organization_id)
