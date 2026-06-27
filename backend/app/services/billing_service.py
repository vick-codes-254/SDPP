"""SaaS billing: subscriptions, invoices, payments, usage vs plan quotas."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import (
    InvoiceStatus,
    PaymentStatus,
    SubscriptionPlan,
    SubscriptionStatus,
)
from app.models.billing import Invoice, Payment, Subscription
from app.models.camera import Camera
from app.models.site import Site
from app.models.user import User
from app.services.exceptions import NotFoundError

# Plan entitlements (None = unlimited).
PLAN_LIMITS: dict[SubscriptionPlan, dict[str, int | None]] = {
    SubscriptionPlan.trial: {"sites": 1, "cameras": 5, "users": 3},
    SubscriptionPlan.starter: {"sites": 3, "cameras": 25, "users": 10},
    SubscriptionPlan.professional: {"sites": 10, "cameras": 200, "users": 50},
    SubscriptionPlan.enterprise: {"sites": None, "cameras": None, "users": None},
}


def _now() -> datetime:
    return datetime.now(UTC)


class BillingService:
    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    async def get_subscription(self, organization_id: uuid.UUID) -> Subscription | None:
        return (await self.db.execute(
            select(Subscription).where(Subscription.organization_id == organization_id)
        )).scalar_one_or_none()

    async def upsert_subscription(self, organization_id: uuid.UUID, data: dict[str, Any]) -> Subscription:
        sub = await self.get_subscription(organization_id)
        if sub is None:
            sub = Subscription(id=uuid.uuid4(), organization_id=organization_id,
                               status=SubscriptionStatus.active, started_at=_now())
            self.db.add(sub)
        for k, v in data.items():
            if v is not None and hasattr(sub, k):
                setattr(sub, k, v)
        await self.db.flush()
        return sub

    async def list_invoices(self, organization_id: uuid.UUID) -> list[Invoice]:
        return list((await self.db.execute(
            select(Invoice).where(Invoice.organization_id == organization_id)
            .order_by(Invoice.created_at.desc())
        )).scalars().all())

    async def create_invoice(self, organization_id: uuid.UUID, data: dict[str, Any]) -> Invoice:
        count = int((await self.db.execute(
            select(func.count()).select_from(Invoice).where(Invoice.organization_id == organization_id)
        )).scalar_one())
        invoice = Invoice(
            id=uuid.uuid4(), organization_id=organization_id,
            number=f"INV-{count + 1:05d}", status=InvoiceStatus.sent, issued_at=_now(),
            **data,
        )
        self.db.add(invoice)
        await self.db.flush()
        return invoice

    async def pay_invoice(self, invoice_id: uuid.UUID, *, method, reference: str | None = None) -> Payment:
        invoice = (await self.db.execute(
            select(Invoice).where(Invoice.id == invoice_id)
        )).scalar_one_or_none()
        if invoice is None:
            raise NotFoundError("Invoice not found")
        now = _now()
        invoice.status = InvoiceStatus.paid
        invoice.paid_at = now
        payment = Payment(
            id=uuid.uuid4(), organization_id=invoice.organization_id, invoice_id=invoice.id,
            amount=invoice.amount, currency=invoice.currency, method=method,
            status=PaymentStatus.completed, reference=reference, paid_at=now,
        )
        self.db.add(payment)
        await self.db.flush()
        return payment

    async def list_payments(self, organization_id: uuid.UUID) -> list[Payment]:
        return list((await self.db.execute(
            select(Payment).where(Payment.organization_id == organization_id)
            .order_by(Payment.created_at.desc())
        )).scalars().all())

    async def usage(self, organization_id: uuid.UUID) -> dict:
        sub = await self.get_subscription(organization_id)
        plan = sub.plan if sub else SubscriptionPlan.trial
        limits = PLAN_LIMITS.get(plan, {})

        async def _count(model) -> int:
            return int((await self.db.execute(
                select(func.count()).select_from(model)
                .where(model.organization_id == organization_id)
            )).scalar_one())

        used = {
            "sites": await _count(Site),
            "cameras": await _count(Camera),
            "users": int((await self.db.execute(
                select(func.count()).select_from(User)
                .where(User.organization_id == organization_id)
            )).scalar_one()),
        }
        return {
            "plan": plan.value,
            "limits": {k: v for k, v in limits.items()},
            "used": used,
            "over_limit": {
                k: (limits.get(k) is not None and used[k] > limits[k]) for k in used
            },
        }
