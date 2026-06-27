"""Pluggable CVE knowledge base and matcher.

Ships a small, curated *seed* dataset of well-known CVEs for common software so
the scanner works out of the box. This is illustrative, **not** an authoritative
feed — a production deployment plugs in a live source (OSV.dev, NVD, OpenVAS,
Nessus) by implementing :class:`VulnSource`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from app.core.enums import VulnSeverity
from app.services.vuln.versions import is_affected


@dataclass(slots=True)
class CveMatch:
    cve_id: str
    product: str
    title: str
    description: str
    severity: VulnSeverity
    cvss_score: float
    affected_version: str
    fixed_version: str | None
    remediation: str
    references: list[str] = field(default_factory=list)


@runtime_checkable
class VulnSource(Protocol):
    """A source of CVE data. Implement this to plug in OSV/NVD/OpenVAS/Nessus."""

    def lookup(self, product: str, version: str) -> list[CveMatch]: ...


# ── Seed dataset (illustrative) ─────────────────────────────────
# Ranges use OSV semantics: affected if introduced <= v < fixed (or <= last_affected).
_CVE_RECORDS: list[dict[str, Any]] = [
    {
        "cve_id": "CVE-2014-0160", "product": "openssl", "title": "Heartbleed",
        "description": "TLS heartbeat read overrun leaks memory (private keys, secrets).",
        "severity": VulnSeverity.high, "cvss": 7.5,
        "affected": [{"introduced": "1.0.1", "fixed": "1.0.1g"}], "fixed": "1.0.1g",
        "remediation": "Upgrade OpenSSL to 1.0.1g+ and rotate keys/certs.",
        "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2014-0160"],
    },
    {
        "cve_id": "CVE-2022-3602", "product": "openssl", "title": "X.509 punycode buffer overflow",
        "description": "Stack buffer overflow in X.509 name constraint checking.",
        "severity": VulnSeverity.high, "cvss": 7.5,
        "affected": [{"introduced": "3.0.0", "fixed": "3.0.7"}], "fixed": "3.0.7",
        "remediation": "Upgrade OpenSSL to 3.0.7+.",
        "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2022-3602"],
    },
    {
        "cve_id": "CVE-2021-44228", "product": "log4j", "aliases": ["log4j-core", "apache-log4j"],
        "title": "Log4Shell", "description": "JNDI lookup enables unauthenticated RCE.",
        "severity": VulnSeverity.critical, "cvss": 10.0,
        "affected": [{"introduced": "2.0", "fixed": "2.15.0"}], "fixed": "2.17.1",
        "remediation": "Upgrade log4j-core to 2.17.1+; disable JNDI lookups.",
        "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
    },
    {
        "cve_id": "CVE-2021-23017", "product": "nginx",
        "title": "DNS resolver off-by-one", "description": "Off-by-one in the resolver may allow RCE.",
        "severity": VulnSeverity.high, "cvss": 7.7,
        "affected": [{"introduced": "0.6.18", "fixed": "1.21.0"}], "fixed": "1.21.0",
        "remediation": "Upgrade nginx to 1.21.0+.",
        "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2021-23017"],
    },
    {
        "cve_id": "CVE-2024-6387", "product": "openssh", "aliases": ["openssh-server"],
        "title": "regreSSHion", "description": "Signal-handler race enables unauthenticated RCE.",
        "severity": VulnSeverity.high, "cvss": 8.1,
        "affected": [{"introduced": "8.5", "fixed": "9.8"}], "fixed": "9.8",
        "remediation": "Upgrade OpenSSH to 9.8p1+.",
        "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2024-6387"],
    },
    {
        "cve_id": "CVE-2021-41773", "product": "apache", "aliases": ["httpd", "apache-httpd", "apache2"],
        "title": "Path traversal / RCE", "description": "Path traversal in Apache HTTP Server 2.4.49.",
        "severity": VulnSeverity.critical, "cvss": 9.8,
        "affected": [{"introduced": "2.4.49", "last_affected": "2.4.50"}], "fixed": "2.4.51",
        "remediation": "Upgrade Apache httpd to 2.4.51+.",
        "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2021-41773"],
    },
    {
        "cve_id": "CVE-2021-3156", "product": "sudo",
        "title": "Baron Samedit", "description": "Heap overflow enabling local privilege escalation.",
        "severity": VulnSeverity.high, "cvss": 7.8,
        "affected": [{"introduced": "1.8.2", "fixed": "1.9.5p2"}], "fixed": "1.9.5p2",
        "remediation": "Upgrade sudo to 1.9.5p2+.",
        "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2021-3156"],
    },
    {
        "cve_id": "CVE-2014-6271", "product": "bash",
        "title": "Shellshock", "description": "Crafted environment variables allow command execution.",
        "severity": VulnSeverity.critical, "cvss": 9.8,
        "affected": [{"introduced": "1.14", "fixed": "4.3.30"}], "fixed": "4.3.30",
        "remediation": "Patch bash to a Shellshock-fixed build.",
        "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2014-6271"],
    },
]


class BundledCveSource:
    """Matches software against the bundled seed dataset."""

    def __init__(self, records: list[dict[str, Any]] | None = None) -> None:
        self._records = records if records is not None else _CVE_RECORDS

    def lookup(self, product: str, version: str) -> list[CveMatch]:
        name = (product or "").strip().lower()
        if not name or not version:
            return []
        matches: list[CveMatch] = []
        for rec in self._records:
            names = {rec["product"], *rec.get("aliases", [])}
            if name not in names:
                continue
            for rng in rec["affected"]:
                if is_affected(version, **rng):
                    matches.append(
                        CveMatch(
                            cve_id=rec["cve_id"], product=rec["product"], title=rec["title"],
                            description=rec["description"], severity=rec["severity"],
                            cvss_score=rec["cvss"], affected_version=version,
                            fixed_version=rec.get("fixed"), remediation=rec["remediation"],
                            references=rec.get("refs", []),
                        )
                    )
                    break
        return matches
