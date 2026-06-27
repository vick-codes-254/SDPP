"""Communication center: announcements and chat messages.

Message/announcement bodies are free text and encrypted at rest. Chat is grouped
into rooms (e.g. "general" or "incident:<id>") for incident war-rooms.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Enum, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.enums import AnnouncementAudience
from app.core.security.field_encryption import EncryptedText
from app.db.base import Base, TenantMixin, TimestampMixin, UUIDPrimaryKeyMixin
from app.db.types import GUID


class Announcement(Base, UUIDPrimaryKeyMixin, TenantMixin, TimestampMixin):
    __tablename__ = "announcements"

    title: Mapped[str] = mapped_column(String(255), nullable=False)
    body: Mapped[str] = mapped_column(EncryptedText(context="comms.announcement"), nullable=False)
    audience: Mapped[AnnouncementAudience] = mapped_column(
        Enum(AnnouncementAudience, name="announcement_audience"),
        nullable=False, default=AnnouncementAudience.all,
    )
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        GUID, ForeignKey("users.id", ondelete="SET NULL")
    )


class ChatMessage(Base, UUIDPrimaryKeyMixin, TenantMixin):
    __tablename__ = "chat_messages"

    room: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    author_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID, ForeignKey("users.id", ondelete="SET NULL")
    )
    author_label: Mapped[str | None] = mapped_column(String(64))
    body: Mapped[str] = mapped_column(EncryptedText(context="comms.message"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
