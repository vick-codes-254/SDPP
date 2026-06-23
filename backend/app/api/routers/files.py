"""Secure file vault endpoints."""

from __future__ import annotations

import tempfile
import uuid
from collections.abc import Iterator
from typing import Annotated

from fastapi import APIRouter, Depends, File, Form, Request, UploadFile, status
from fastapi.responses import StreamingResponse

from app.api.deps import client_ip, get_vault_service, require_permission
from app.core.enums import FileCategory
from app.schemas.common import Message
from app.schemas.files import FileResponse, IntegrityCheckResponse, UploadResponse
from app.services.vault_service import VaultService

router = APIRouter(prefix="/files", tags=["file-vault"])

VaultDep = Annotated[VaultService, Depends(get_vault_service)]
_DL_CHUNK = 1024 * 1024


@router.get("", response_model=list[FileResponse])
async def list_files(
    vault: VaultDep,
    principal: Annotated[object, Depends(require_permission("file:read"))],
) -> list[FileResponse]:
    files = await vault.list_files()
    return [
        FileResponse.model_validate(
            {**f.__dict__, "original_filename": f.original_filename, "description": f.description}
        )
        for f in files
    ]


@router.post("", response_model=UploadResponse, status_code=status.HTTP_201_CREATED)
async def upload_file(
    request: Request,
    vault: VaultDep,
    principal: Annotated[object, Depends(require_permission("file:upload"))],
    upload: Annotated[UploadFile, File(description="File to encrypt and store")],
    category: Annotated[FileCategory, Form()] = FileCategory.other,
    description: Annotated[str | None, Form()] = None,
) -> UploadResponse:
    result = await vault.upload(
        owner_id=principal.user_id,  # type: ignore[attr-defined]
        filename=upload.filename or "unnamed",
        content_type=upload.content_type or "application/octet-stream",
        category=category,
        source=upload.file,
        description=description,
        ip_address=client_ip(request),
    )
    return UploadResponse.model_validate(
        {
            "file": {**result.file.__dict__, "original_filename": result.file.original_filename,
                     "description": result.file.description},
            "encrypted": result.encrypted,
        }
    )


@router.get("/{file_id}/download")
async def download_file(
    file_id: uuid.UUID,
    request: Request,
    vault: VaultDep,
    principal: Annotated[object, Depends(require_permission("file:download"))],
) -> StreamingResponse:
    # Decrypt into a spooled buffer (spills to disk for large files), then stream.
    tmp = tempfile.SpooledTemporaryFile(max_size=16 * 1024 * 1024)
    file = await vault.download(
        file_id=file_id, dest=tmp,
        requester_id=principal.user_id,  # type: ignore[attr-defined]
        ip_address=client_ip(request),
    )
    tmp.seek(0)

    def iterfile() -> Iterator[bytes]:
        try:
            while chunk := tmp.read(_DL_CHUNK):
                yield chunk
        finally:
            tmp.close()

    return StreamingResponse(
        iterfile(),
        media_type=file.content_type,
        headers={"Content-Disposition": f'attachment; filename="{file.original_filename}"'},
    )


@router.post("/{file_id}/verify-integrity", response_model=IntegrityCheckResponse)
async def verify_integrity(
    file_id: uuid.UUID,
    vault: VaultDep,
    principal: Annotated[object, Depends(require_permission("integrity:verify"))],
) -> IntegrityCheckResponse:
    check = await vault.verify_integrity(file_id, requester_id=principal.user_id)  # type: ignore[attr-defined]
    return IntegrityCheckResponse.model_validate(check)


@router.delete("/{file_id}", response_model=Message)
async def delete_file(
    file_id: uuid.UUID,
    vault: VaultDep,
    principal: Annotated[object, Depends(require_permission("file:delete"))],
    secure: bool = False,
) -> Message:
    if secure:
        await vault.secure_delete(file_id, actor_id=principal.user_id)  # type: ignore[attr-defined]
        return Message(detail="File securely deleted (crypto-shredded)")
    await vault.soft_delete(file_id, actor_id=principal.user_id)  # type: ignore[attr-defined]
    return Message(detail="File deleted (restorable)")


@router.post("/{file_id}/restore", response_model=Message)
async def restore_file(
    file_id: uuid.UUID,
    vault: VaultDep,
    principal: Annotated[object, Depends(require_permission("file:restore"))],
) -> Message:
    await vault.restore(file_id, actor_id=principal.user_id)  # type: ignore[attr-defined]
    return Message(detail="File restored")
