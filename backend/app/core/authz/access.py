"""Pure permission-evaluation helpers (no framework / ORM coupling)."""

from __future__ import annotations

from collections.abc import Iterable


def has_permission(granted: Iterable[str], required: str, *, is_superuser: bool = False) -> bool:
    """True if ``required`` is granted (superusers and ``system:admin`` pass all)."""
    if is_superuser:
        return True
    granted_set = set(granted)
    return "system:admin" in granted_set or required in granted_set


def has_any(granted: Iterable[str], required: Iterable[str], *, is_superuser: bool = False) -> bool:
    if is_superuser:
        return True
    granted_set = set(granted)
    return "system:admin" in granted_set or bool(granted_set & set(required))
