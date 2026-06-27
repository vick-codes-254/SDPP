"""Communication center service: announcements and chat rooms."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.comms import Announcement, ChatMessage


def _now() -> datetime:
    return datetime.now(UTC)


class CommsService:
    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    # ── Announcements ───────────────────────────────────────────
    async def list_announcements(self, *, organization_id: uuid.UUID | None = None,
                                 limit: int = 100) -> list[Announcement]:
        stmt = select(Announcement).order_by(Announcement.created_at.desc()).limit(limit)
        if organization_id is not None:
            stmt = stmt.where(Announcement.organization_id == organization_id)
        return list((await self.db.execute(stmt)).scalars().all())

    async def create_announcement(self, data: dict[str, Any]) -> Announcement:
        ann = Announcement(id=uuid.uuid4(), **data)
        self.db.add(ann)
        await self.db.flush()
        return ann

    # ── Chat rooms ──────────────────────────────────────────────
    async def list_messages(self, *, room: str, organization_id: uuid.UUID | None = None,
                            limit: int = 200) -> list[ChatMessage]:
        stmt = (
            select(ChatMessage).where(ChatMessage.room == room)
            .order_by(ChatMessage.created_at).limit(limit)
        )
        if organization_id is not None:
            stmt = stmt.where(ChatMessage.organization_id == organization_id)
        return list((await self.db.execute(stmt)).scalars().all())

    async def post_message(self, *, organization_id: uuid.UUID, room: str, body: str,
                           author_id: uuid.UUID | None = None,
                           author_label: str | None = None) -> ChatMessage:
        msg = ChatMessage(
            id=uuid.uuid4(), organization_id=organization_id, room=room, body=body,
            author_id=author_id, author_label=author_label, created_at=_now(),
        )
        self.db.add(msg)
        await self.db.flush()
        return msg
