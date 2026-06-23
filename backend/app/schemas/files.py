"""File vault schemas."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict

from app.core.enums import FileCategory, FileStatus, IntegrityResult, IntegrityTarget


class FileResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    owner_id: uuid.UUID
    original_filename: str
    content_type: str
    size_bytes: int
    category: FileCategory
    status: FileStatus
    plaintext_sha256: str | None = None
    description: str | None = None
    created_at: datetime


class EncryptedFileInfo(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    algorithm: str
    chunk_size: int
    ciphertext_size: int
    ciphertext_sha256: str
    encryption_key_id: uuid.UUID


class UploadResponse(BaseModel):
    file: FileResponse
    encrypted: EncryptedFileInfo


class IntegrityCheckResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    file_id: uuid.UUID
    target: IntegrityTarget
    expected_sha256: str
    actual_sha256: str | None = None
    result: IntegrityResult
    created_at: datetime
