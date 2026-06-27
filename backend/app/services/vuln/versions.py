"""Lightweight version comparison for CVE range matching.

Parses the numeric release components of a version string and compares them
component-wise (zero-padded). Sufficient for matching software versions against
OSV-style affected ranges (``introduced <= v < fixed``). For exotic versioning,
a real scanner adapter (OSV/NVD) can be plugged in via ``VulnSource``.
"""

from __future__ import annotations

import re

_TOKEN = re.compile(r"\d+|[A-Za-z]+")


def _alpha_value(token: str) -> int:
    """Map a letter run to a comparable int (a=1..z=26, base-27) so 'f' < 'g'.

    Critical for software like OpenSSL whose releases use letter suffixes
    (1.0.1f < 1.0.1g). A bare version (1.0.1) sorts below its lettered
    successors because it simply has fewer components.
    """
    value = 0
    for ch in token.lower():
        value = value * 27 + (ord(ch) - ord("a") + 1)
    return value


def parse_version(version: str) -> tuple[int, ...]:
    """Return a comparable component tuple, e.g. '1.0.1f' -> (1, 0, 1, 6)."""
    parts = tuple(
        int(tok) if tok.isdigit() else _alpha_value(tok)
        for tok in _TOKEN.findall(version or "")
    )
    return parts or (0,)


def vcompare(a: str, b: str) -> int:
    """Return -1, 0, or 1 comparing version ``a`` to ``b``."""
    ta, tb = parse_version(a), parse_version(b)
    length = max(len(ta), len(tb))
    ta += (0,) * (length - len(ta))
    tb += (0,) * (length - len(tb))
    return (ta > tb) - (ta < tb)


def is_affected(
    version: str,
    *,
    introduced: str | None = None,
    fixed: str | None = None,
    last_affected: str | None = None,
) -> bool:
    """True if ``version`` falls within an affected range (OSV semantics)."""
    if not version:
        return False
    if introduced and vcompare(version, introduced) < 0:
        return False
    if fixed and vcompare(version, fixed) >= 0:
        return False
    if last_affected and vcompare(version, last_affected) > 0:
        return False
    return True
