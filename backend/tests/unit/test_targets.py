"""Scan target-expansion safety tests."""

from __future__ import annotations

import pytest

from app.services.scanning.targets import TargetExpansionError, expand_targets

pytestmark = pytest.mark.unit


def test_single_ip() -> None:
    assert expand_targets(["10.0.0.1"]) == ["10.0.0.1"]


def test_hostname_passthrough() -> None:
    assert expand_targets(["scanme.example.com"]) == ["scanme.example.com"]


def test_cidr_expansion() -> None:
    hosts = expand_targets(["192.168.1.0/30"])
    # /30 usable hosts = .1 and .2
    assert hosts == ["192.168.1.1", "192.168.1.2"]


def test_single_host_cidr_32() -> None:
    assert expand_targets(["10.0.0.5/32"]) == ["10.0.0.5"]


def test_dedup() -> None:
    assert expand_targets(["10.0.0.1", "10.0.0.1"]) == ["10.0.0.1"]


def test_host_cap_enforced() -> None:
    # /16 = 65k hosts -> must be rejected by the cap (no giant sweeps)
    with pytest.raises(TargetExpansionError):
        expand_targets(["10.0.0.0/16"], max_hosts=1024)


def test_empty_rejected() -> None:
    with pytest.raises(TargetExpansionError):
        expand_targets([])


def test_invalid_cidr_rejected() -> None:
    with pytest.raises(TargetExpansionError):
        expand_targets(["10.0.0.0/99"])
