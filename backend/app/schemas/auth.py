"""Authentication & user schemas."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class RegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")
    email: EmailStr
    password: str = Field(min_length=12, max_length=128)
    full_name: str | None = Field(default=None, max_length=255)
    phone: str | None = Field(default=None, max_length=32)


class LoginRequest(BaseModel):
    identifier: str = Field(description="Username or email")
    password: str


class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str = Field(min_length=12, max_length=128)


class RefreshRequest(BaseModel):
    refresh_token: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"  # noqa: S105 - scheme name


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    username: str
    # Plain str on output: the value was validated as EmailStr on input; output
    # serialization must never fail on legitimately-stored data.
    email: str
    full_name: str | None = None
    is_active: bool
    is_superuser: bool
    mfa_enabled: bool
    last_login_at: datetime | None = None
    created_at: datetime


class UserWithPermissions(UserResponse):
    permissions: list[str] = []
