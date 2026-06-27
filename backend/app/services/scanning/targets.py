"""Safe expansion of user-supplied scan targets.

Accepts individual IPs, hostnames, and CIDR ranges, but enforces a hard cap on
the total number of expanded hosts so a careless ``/8`` can't trigger a massive
sweep. This cap is the primary guard-rail behind the "no unsolicited sweeps" rule.
"""

from __future__ import annotations

import ipaddress

MAX_HOSTS = 1024


class TargetExpansionError(ValueError):
    """Raised when targets are invalid or exceed the host cap."""


def _is_probably_hostname(value: str) -> bool:
    # Not an IP/CIDR; treat as a DNS name (resolved by the scanner at runtime).
    try:
        ipaddress.ip_address(value)
        return False
    except ValueError:
        return "/" not in value


def expand_targets(targets: list[str], *, max_hosts: int = MAX_HOSTS) -> list[str]:
    """Expand targets into a de-duplicated host list, capped at ``max_hosts``."""
    if not targets:
        raise TargetExpansionError("No targets provided")

    hosts: list[str] = []
    seen: set[str] = set()

    def _add(value: str) -> None:
        if value not in seen:
            seen.add(value)
            hosts.append(value)
        if len(hosts) > max_hosts:
            raise TargetExpansionError(
                f"Target set expands to more than {max_hosts} hosts; narrow the scope"
            )

    for raw in targets:
        target = raw.strip()
        if not target:
            continue
        if "/" in target:
            try:
                net = ipaddress.ip_network(target, strict=False)
            except ValueError as exc:
                raise TargetExpansionError(f"Invalid CIDR '{target}': {exc}") from exc
            # Reject oversized ranges WITHOUT materializing them (avoids a
            # 16M-host /8 from blowing up memory before the cap check).
            if net.num_addresses > max_hosts + 2:
                raise TargetExpansionError(
                    f"CIDR '{target}' has ~{net.num_addresses} addresses (cap {max_hosts}); "
                    "narrow the scope"
                )
            members = list(net.hosts()) or [net.network_address]
            for ip in members:
                _add(str(ip))
        elif _is_probably_hostname(target) or _valid_ip(target):
            _add(target)
        else:
            raise TargetExpansionError(f"Invalid target '{target}'")

    if not hosts:
        raise TargetExpansionError("No valid targets after expansion")
    return hosts


def _valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False
