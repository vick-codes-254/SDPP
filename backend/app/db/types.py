"""Dialect-adaptive column types.

Production runs on PostgreSQL (native ``UUID`` + ``JSONB`` for indexing); the test
suite runs on SQLite for speed and isolation. These helpers pick the optimal type
per dialect so the *same* models work in both places.
"""

from __future__ import annotations

from sqlalchemy import JSON, Uuid
from sqlalchemy.dialects.postgresql import JSONB

# Native UUID on PostgreSQL; CHAR(32) on SQLite. Returns python uuid.UUID either way.
GUID = Uuid

# JSONB (binary, indexable) on PostgreSQL; generic JSON elsewhere.
JSONType = JSON().with_variant(JSONB(), "postgresql")
