"""Service-layer exceptions, mapped to HTTP responses at the API boundary."""

from __future__ import annotations


class ServiceError(Exception):
    """Base class for service-layer errors."""


class AuthenticationError(ServiceError):
    """Invalid credentials (intentionally generic to avoid user enumeration)."""


class AccountLockedError(ServiceError):
    """Account is temporarily locked due to repeated failed logins."""


class AccountInactiveError(ServiceError):
    """Account is disabled."""


class PermissionDeniedError(ServiceError):
    """Authenticated principal lacks the required permission."""


class NotFoundError(ServiceError):
    """Requested resource does not exist (or is not visible to the caller)."""


class ConflictError(ServiceError):
    """Resource conflict (e.g. duplicate username/email)."""


class IntegrityViolationError(ServiceError):
    """A stored object failed integrity verification (possible tampering)."""


class ValidationError(ServiceError):
    """Input failed a business rule (distinct from schema validation)."""
