"""Structured, security-aware application logging.

Uses ``structlog`` to emit JSON logs suitable for SIEM ingestion. A redaction
processor strips known-sensitive keys so secrets, tokens, and plaintext never
leak into logs (a common cause of "sensitive data exposure").

Note: this is *operational* logging. The tamper-evident **audit trail** (who did
what, when) is a separate, database-backed, hash-chained facility implemented in
the audit service — see ``app/services/audit``.
"""

from __future__ import annotations

import logging
import sys
from typing import Any

import structlog

# Keys whose values must never be written to logs.
_REDACT_KEYS = frozenset(
    {
        "password",
        "passwd",
        "secret",
        "token",
        "access_token",
        "refresh_token",
        "authorization",
        "jwt_secret_key",
        "master_key",
        "dek",
        "private_key",
        "api_key",
        "set-cookie",
        "cookie",
    }
)
_REDACTED = "***REDACTED***"


def _redact(_: Any, __: str, event_dict: dict[str, Any]) -> dict[str, Any]:
    for key in list(event_dict):
        if key.lower() in _REDACT_KEYS:
            event_dict[key] = _REDACTED
    return event_dict


def configure_logging(level: str = "INFO", *, json_output: bool = True) -> None:
    """Configure structlog + stdlib logging once at startup."""
    logging.basicConfig(format="%(message)s", stream=sys.stdout, level=level.upper())

    processors: list[Any] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        _redact,
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]
    processors.append(
        structlog.processors.JSONRenderer()
        if json_output
        else structlog.dev.ConsoleRenderer()
    )

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(
            logging.getLevelName(level.upper())
        ),
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    return structlog.get_logger(name)
