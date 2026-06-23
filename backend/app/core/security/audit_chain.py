"""Tamper-evident audit hash chain (pure, dependency-free).

Each audit entry's hash is computed over a canonical serialization of its fields
plus the previous entry's hash:

    entry_hash = SHA-256( canonical(fields) ‖ prev_hash )

This forms a hash chain: altering or removing any historical entry changes its
hash, which breaks every subsequent link — detectable by re-walking the chain.
The first entry chains off a fixed genesis hash.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

GENESIS_HASH = "0" * 64


def _canonical_timestamp(value: datetime | str) -> str:
    """Normalize a timestamp to a UTC ISO-8601 string.

    Critical for chain stability: timestamps are always written in UTC, but some
    databases (e.g. SQLite) return naive datetimes on read-back. Treating naive
    values as UTC guarantees the verifier recomputes the identical hash.
    """
    if isinstance(value, datetime):
        dt = value if value.tzinfo is not None else value.replace(tzinfo=UTC)
        return dt.astimezone(UTC).isoformat()
    return str(value)


def compute_entry_hash(
    *,
    event_type: str,
    outcome: str,
    actor_id: str | None,
    actor_label: str | None,
    resource_type: str | None,
    resource_id: str | None,
    action: str | None,
    ip_address: str | None,
    user_agent: str | None,
    detail: dict[str, Any] | None,
    created_at: datetime | str,
    prev_hash: str,
) -> str:
    """Compute the SHA-256 hash for an audit entry, chained off ``prev_hash``."""
    payload = {
        "event_type": str(event_type),
        "outcome": str(outcome),
        "actor_id": str(actor_id) if actor_id is not None else None,
        "actor_label": actor_label,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "action": action,
        "ip_address": ip_address,
        "user_agent": user_agent,
        "detail": detail,
        "created_at": _canonical_timestamp(created_at),
        "prev_hash": prev_hash,
    }
    canonical = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), default=str, ensure_ascii=False
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
