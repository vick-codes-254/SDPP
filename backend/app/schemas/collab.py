"""Communication & workflow-automation schemas."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.core.enums import AnnouncementAudience, AutomationAction, AutomationTrigger


# ── Communication ───────────────────────────────────────────────
class AnnouncementCreate(BaseModel):
    organization_id: uuid.UUID
    title: str = Field(min_length=1, max_length=255)
    body: str = Field(min_length=1)
    audience: AnnouncementAudience = AnnouncementAudience.all


class AnnouncementResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    organization_id: uuid.UUID
    title: str
    body: str
    audience: AnnouncementAudience
    created_by: uuid.UUID | None = None
    created_at: datetime


class MessagePost(BaseModel):
    organization_id: uuid.UUID
    room: str = Field(min_length=1, max_length=128)
    body: str = Field(min_length=1)


class MessageResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    room: str
    author_id: uuid.UUID | None = None
    author_label: str | None = None
    body: str
    created_at: datetime


# ── Workflow automation ─────────────────────────────────────────
class RuleCreate(BaseModel):
    organization_id: uuid.UUID
    name: str = Field(min_length=1, max_length=255)
    trigger: AutomationTrigger
    condition: dict | None = None
    action: AutomationAction
    action_config: dict | None = None


class RuleUpdate(BaseModel):
    name: str | None = None
    condition: dict | None = None
    action: AutomationAction | None = None
    action_config: dict | None = None
    is_active: bool | None = None


class RuleResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    organization_id: uuid.UUID
    name: str
    trigger: AutomationTrigger
    condition: dict | None = None
    action: AutomationAction
    action_config: dict | None = None
    is_active: bool
    trigger_count: int
    last_triggered_at: datetime | None = None
    created_at: datetime


class EvaluateRequest(BaseModel):
    organization_id: uuid.UUID
    trigger: AutomationTrigger
    context: dict = {}


class EvaluateResult(BaseModel):
    executed: list[dict]
