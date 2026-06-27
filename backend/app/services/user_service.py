"""User management service — list users, assign roles, enable/disable accounts.

Account *creation* lives in AuthService.register; this service covers the
administrative lifecycle (role assignment, activation) that the User Management
module exposes. All changes are audited.
"""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import AuditEventType, AuditOutcome
from app.models.user import Role, User
from app.services.audit_service import AuditService
from app.services.exceptions import NotFoundError, ValidationError


class UserService:
    def __init__(self, db: AsyncSession, *, audit: AuditService | None = None) -> None:
        self.db = db
        self.audit = audit or AuditService(db)

    async def list_users(self, *, limit: int = 100) -> list[User]:
        return list(
            (
                await self.db.execute(select(User).order_by(User.created_at.desc()).limit(limit))
            ).scalars().all()
        )

    async def get_user(self, user_id: uuid.UUID) -> User:
        user = (
            await self.db.execute(select(User).where(User.id == user_id))
        ).scalar_one_or_none()
        if user is None:
            raise NotFoundError("User not found")
        return user

    async def set_roles(
        self, user_id: uuid.UUID, role_names: list[str], *, actor_id: uuid.UUID | None = None
    ) -> User:
        user = await self.get_user(user_id)
        roles = list(
            (await self.db.execute(select(Role).where(Role.name.in_(role_names)))).scalars().all()
        )
        found = {r.name for r in roles}
        missing = set(role_names) - found
        if missing:
            raise ValidationError(f"Unknown roles: {sorted(missing)}")
        user.roles = roles
        await self.audit.record(
            event_type=AuditEventType.role_change, outcome=AuditOutcome.success,
            actor_id=actor_id, resource_type="user", resource_id=str(user_id),
            action="set_roles", detail={"roles": sorted(found)},
        )
        await self.db.flush()
        return user

    async def set_active(
        self, user_id: uuid.UUID, active: bool, *, actor_id: uuid.UUID | None = None
    ) -> User:
        user = await self.get_user(user_id)
        user.is_active = active
        await self.audit.record(
            event_type=AuditEventType.config_change, outcome=AuditOutcome.success,
            actor_id=actor_id, resource_type="user", resource_id=str(user_id),
            action="activate" if active else "deactivate",
        )
        await self.db.flush()
        return user
