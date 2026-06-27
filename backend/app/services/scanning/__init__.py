"""Network scanning: safe target expansion and a pluggable port-scanner.

Safety model (per project constraint): scans only run against targets a user
EXPLICITLY supplies, expansion is hard-capped, and the scanner performs only
non-intrusive TCP-connect probes — no payloads, no exploitation, no unsolicited
sweeps. Real scanners (nmap/masscan) can be wired in via the ``PortScanner``
protocol without touching the service layer.
"""

from app.services.scanning.targets import TargetExpansionError, expand_targets
from app.services.scanning.tcp_scanner import (
    DEFAULT_PORTS,
    AsyncTcpScanner,
    HostResult,
    PortScanner,
)

__all__ = [
    "expand_targets",
    "TargetExpansionError",
    "AsyncTcpScanner",
    "HostResult",
    "PortScanner",
    "DEFAULT_PORTS",
]
