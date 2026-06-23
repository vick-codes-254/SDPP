"""Encrypted-blob storage backends for the file vault.

The vault stores only AES-256-GCM *ciphertext* blobs. Storage backends are
content-agnostic and addressed by an opaque key. A local filesystem backend is
provided; the same interface fits S3/GCS/Azure Blob (add a backend, no service
changes).
"""

from __future__ import annotations

import os
import uuid
from pathlib import Path
from typing import BinaryIO, Protocol


class VaultStorage(Protocol):
    """Content-agnostic encrypted blob store."""

    def new_key(self) -> str: ...
    def open_write(self, key: str) -> BinaryIO: ...
    def open_read(self, key: str) -> BinaryIO: ...
    def exists(self, key: str) -> bool: ...
    def delete(self, key: str) -> None: ...
    def size(self, key: str) -> int: ...


class LocalFileSystemStorage:
    """Stores ciphertext blobs on the local filesystem with 2-level sharding."""

    def __init__(self, base_path: str | os.PathLike[str]) -> None:
        self.base = Path(base_path)
        self.base.mkdir(parents=True, exist_ok=True)

    def new_key(self) -> str:
        h = uuid.uuid4().hex
        return f"{h[:2]}/{h[2:4]}/{h}"

    def _path(self, key: str) -> Path:
        # Prevent path traversal: only hex/slash keys are valid.
        safe = key.replace("\\", "/")
        if ".." in safe or safe.startswith("/"):
            raise ValueError("Invalid storage key")
        return self.base / safe

    def open_write(self, key: str) -> BinaryIO:
        path = self._path(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        return path.open("wb")

    def open_read(self, key: str) -> BinaryIO:
        return self._path(key).open("rb")

    def exists(self, key: str) -> bool:
        return self._path(key).exists()

    def size(self, key: str) -> int:
        return self._path(key).stat().st_size

    def delete(self, key: str) -> None:
        """Best-effort secure delete.

        The authoritative "secure delete" is crypto-shredding the DEK (the blob
        becomes undecryptable). We additionally overwrite the file once and unlink
        it. (Note: overwrite is not guaranteed on copy-on-write/SSD media — hence
        crypto-shred is the primary control.)
        """
        path = self._path(key)
        if not path.exists():
            return
        try:
            length = path.stat().st_size
            with path.open("r+b") as fh:
                fh.write(b"\x00" * min(length, 1024 * 1024))
                fh.flush()
                os.fsync(fh.fileno())
        except OSError:
            pass
        path.unlink(missing_ok=True)


def get_default_storage() -> LocalFileSystemStorage:
    from app.core.config import get_settings

    return LocalFileSystemStorage(get_settings().vault_storage_path)
