"""Vulnerability matching: version comparison + a pluggable CVE knowledge base."""

from app.services.vuln.cve_db import BundledCveSource, CveMatch, VulnSource
from app.services.vuln.versions import is_affected, parse_version, vcompare

__all__ = [
    "BundledCveSource",
    "CveMatch",
    "VulnSource",
    "is_affected",
    "parse_version",
    "vcompare",
]
