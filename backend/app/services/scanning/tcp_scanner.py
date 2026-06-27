"""Non-intrusive async TCP-connect port scanner.

For each (host, port) it attempts a TCP handshake with a timeout; a successful
connect means the port is open. It is immediately closed — **no data is ever
sent**, so this is a benign connectivity probe, not an exploit or banner-grab.
Concurrency is bounded; reverse DNS is best-effort.
"""

from __future__ import annotations

import asyncio
import socket
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

# A compact set of commonly-exposed service ports (scanned when none specified).
DEFAULT_PORTS: list[int] = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
    993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200,
]


@dataclass(slots=True)
class HostResult:
    ip: str
    hostname: str | None = None
    open_ports: list[int] = field(default_factory=list)
    latency_ms: float | None = None

    @property
    def is_alive(self) -> bool:
        return bool(self.open_ports)


@runtime_checkable
class PortScanner(Protocol):
    """Pluggable scanner interface (swap in nmap/masscan adapters here)."""

    async def scan(self, hosts: list[str], ports: list[int]) -> list[HostResult]: ...


class AsyncTcpScanner:
    def __init__(self, *, timeout: float = 1.0, concurrency: int = 200) -> None:
        self.timeout = timeout
        self._sem = asyncio.Semaphore(concurrency)

    async def _probe(self, host: str, port: int) -> bool:
        async with self._sem:
            try:
                fut = asyncio.open_connection(host, port)
                reader, writer = await asyncio.wait_for(fut, timeout=self.timeout)
            except (OSError, asyncio.TimeoutError):
                return False
            else:
                writer.close()
                try:
                    await writer.wait_closed()
                except OSError:
                    pass
                return True

    async def _reverse_dns(self, host: str) -> str | None:
        loop = asyncio.get_running_loop()
        try:
            name, _, _ = await loop.run_in_executor(None, socket.gethostbyaddr, host)
            return name
        except (OSError, socket.herror):
            return None

    async def _scan_host(self, host: str, ports: list[int]) -> HostResult:
        loop = asyncio.get_running_loop()
        start = loop.time()
        checks = await asyncio.gather(*(self._probe(host, p) for p in ports))
        elapsed_ms = (loop.time() - start) * 1000
        open_ports = [p for p, is_open in zip(ports, checks, strict=True) if is_open]
        hostname = await self._reverse_dns(host) if open_ports else None
        return HostResult(
            ip=host, hostname=hostname, open_ports=open_ports,
            latency_ms=round(elapsed_ms, 2) if open_ports else None,
        )

    async def scan(self, hosts: list[str], ports: list[int]) -> list[HostResult]:
        ports = ports or DEFAULT_PORTS
        return await asyncio.gather(*(self._scan_host(h, ports) for h in hosts))
