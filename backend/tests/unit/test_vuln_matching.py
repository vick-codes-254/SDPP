"""Version comparison & CVE matching tests."""

from __future__ import annotations

import pytest

from app.core.enums import VulnSeverity
from app.services.vuln.cve_db import BundledCveSource
from app.services.vuln.versions import is_affected, parse_version, vcompare

pytestmark = pytest.mark.unit


class TestVersions:
    def test_parse(self) -> None:
        assert parse_version("1.18.0") == (1, 18, 0)
        assert parse_version("3.0.2") == (3, 0, 2)

    @pytest.mark.parametrize(
        ("a", "b", "expected"),
        [("1.0.0", "1.0.1", -1), ("2.4.51", "2.4.50", 1), ("3.0.2", "3.0.2", 0),
         ("1.18", "1.18.0", 0),
         ("1.0.1f", "1.0.1g", -1),  # OpenSSL letter releases order correctly
         ("1.0.1", "1.0.1a", -1)],
    )
    def test_compare(self, a: str, b: str, expected: int) -> None:
        assert vcompare(a, b) == expected

    def test_is_affected_range(self) -> None:
        assert is_affected("3.0.2", introduced="3.0.0", fixed="3.0.7")
        assert not is_affected("3.0.7", introduced="3.0.0", fixed="3.0.7")  # fixed is exclusive
        assert not is_affected("2.9.0", introduced="3.0.0", fixed="3.0.7")

    def test_last_affected(self) -> None:
        assert is_affected("2.4.50", introduced="2.4.49", last_affected="2.4.50")
        assert not is_affected("2.4.51", introduced="2.4.49", last_affected="2.4.50")


class TestCveSource:
    def test_openssl_heartbleed(self) -> None:
        matches = BundledCveSource().lookup("openssl", "1.0.1f")
        assert any(m.cve_id == "CVE-2014-0160" for m in matches)

    def test_log4shell_critical(self) -> None:
        matches = BundledCveSource().lookup("log4j", "2.14.1")
        assert matches and matches[0].severity is VulnSeverity.critical

    def test_alias_match(self) -> None:
        assert BundledCveSource().lookup("apache-httpd", "2.4.49")  # alias of "apache"

    def test_patched_version_not_matched(self) -> None:
        assert BundledCveSource().lookup("openssl", "3.0.7") == []
        assert BundledCveSource().lookup("nginx", "1.21.0") == []

    def test_unknown_product(self) -> None:
        assert BundledCveSource().lookup("my-custom-app", "1.0.0") == []
