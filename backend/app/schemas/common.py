"""Common/shared schemas."""

from __future__ import annotations

from pydantic import BaseModel, Field


class Message(BaseModel):
    detail: str


class ErrorResponse(BaseModel):
    error: str = Field(description="Machine-readable error code")
    detail: str = Field(description="Human-readable explanation")


class HealthResponse(BaseModel):
    status: str = "ok"
    version: str
    environment: str
