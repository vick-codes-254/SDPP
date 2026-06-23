"""Centralized exception handling.

Maps internal exceptions to safe HTTP responses that never leak sensitive
details (no stack traces, no key material, no oracle on decryption failures).
"""

from __future__ import annotations

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse

from app.core.logging import get_logger
from app.core.security.exceptions import (
    DecryptionError,
    IntegrityError,
    KeyManagementError,
    PasswordPolicyError,
    SecurityError,
    TokenError,
)
from app.services.exceptions import (
    AccountInactiveError,
    AccountLockedError,
    AuthenticationError,
    ConflictError,
    IntegrityViolationError,
    NotFoundError,
    PermissionDeniedError,
    ServiceError,
    ValidationError,
)

logger = get_logger("api.errors")

# (exception, http status, error code, safe client message-or-None[use str(exc)])
_MAP: list[tuple[type[Exception], int, str, str | None]] = [
    (AuthenticationError, status.HTTP_401_UNAUTHORIZED, "authentication_failed", "Invalid credentials"),
    (TokenError, status.HTTP_401_UNAUTHORIZED, "invalid_token", "Invalid or expired token"),
    (AccountLockedError, status.HTTP_423_LOCKED, "account_locked", "Account is temporarily locked"),
    (AccountInactiveError, status.HTTP_403_FORBIDDEN, "account_inactive", "Account is disabled"),
    (PermissionDeniedError, status.HTTP_403_FORBIDDEN, "permission_denied", None),
    (NotFoundError, status.HTTP_404_NOT_FOUND, "not_found", None),
    (ConflictError, status.HTTP_409_CONFLICT, "conflict", None),
    (IntegrityViolationError, status.HTTP_409_CONFLICT, "integrity_violation", None),
    (IntegrityError, status.HTTP_409_CONFLICT, "integrity_violation", "Integrity check failed"),
    (PasswordPolicyError, 422, "password_policy", None),
    (ValidationError, 422, "validation_error", None),
    (DecryptionError, 422, "decryption_failed", "Decryption failed"),
    (KeyManagementError, status.HTTP_400_BAD_REQUEST, "key_management_error", None),
]


def _make_handler(http_status: int, code: str, message: str | None):  # noqa: ANN202
    async def handler(request: Request, exc: Exception) -> JSONResponse:
        detail = message if message is not None else str(exc)
        if http_status >= 500:
            logger.error("request_error", code=code, path=str(request.url.path))
        return JSONResponse(status_code=http_status, content={"error": code, "detail": detail})

    return handler


async def _security_fallback(request: Request, exc: Exception) -> JSONResponse:
    # Any unmapped SecurityError -> 400 without leaking internals.
    logger.warning("unmapped_security_error", type=type(exc).__name__)
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={"error": "security_error", "detail": "Request could not be processed"},
    )


async def _service_fallback(request: Request, exc: Exception) -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={"error": "service_error", "detail": str(exc)},
    )


def register_exception_handlers(app: FastAPI) -> None:
    for exc_type, http_status, code, message in _MAP:
        app.add_exception_handler(exc_type, _make_handler(http_status, code, message))
    # Base-class fallbacks (checked after specific handlers).
    app.add_exception_handler(SecurityError, _security_fallback)
    app.add_exception_handler(ServiceError, _service_fallback)
