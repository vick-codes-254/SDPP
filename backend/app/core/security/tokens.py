"""JWT issuance & verification for stateless authentication.

Two token types are issued:

* **access**  — short-lived (minutes), sent on every API request.
* **refresh** — longer-lived (days), single-use, rotated on each use and
  revocable via its ``jti`` (tracked server-side in the ``refresh_tokens`` table).

Every token carries ``iss``/``aud``/``iat``/``nbf``/``exp``/``jti``/``type``
claims, all of which are validated on decode. A clock can be injected for
deterministic testing.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any

import jwt

from app.core.security.exceptions import TokenError


class TokenType(StrEnum):
    access = "access"  # noqa: S105 - claim value, not a secret
    refresh = "refresh"  # noqa: S105


@dataclass(frozen=True, slots=True)
class DecodedToken:
    subject: str
    token_type: TokenType
    jti: str
    issued_at: datetime
    expires_at: datetime
    claims: dict[str, Any]


@dataclass(slots=True)
class TokenManager:
    secret_key: str
    algorithm: str = "HS256"
    issuer: str = "sdpp"
    audience: str = "sdpp-clients"
    access_ttl: timedelta = timedelta(minutes=15)
    refresh_ttl: timedelta = timedelta(days=7)
    _now: Callable[[], datetime] = datetime.now  # injectable clock

    def _utcnow(self) -> datetime:
        now = self._now(UTC) if self._now is datetime.now else self._now()
        return now if now.tzinfo else now.replace(tzinfo=UTC)

    # ── Issuance ────────────────────────────────────────────────
    def _create(
        self,
        subject: str,
        token_type: TokenType,
        ttl: timedelta,
        extra_claims: dict[str, Any] | None = None,
        jti: str | None = None,
    ) -> tuple[str, str]:
        now = self._utcnow()
        token_id = jti or uuid.uuid4().hex
        payload: dict[str, Any] = {
            "sub": subject,
            "type": token_type.value,
            "jti": token_id,
            "iat": int(now.timestamp()),
            "nbf": int(now.timestamp()),
            "exp": int((now + ttl).timestamp()),
            "iss": self.issuer,
            "aud": self.audience,
        }
        if extra_claims:
            # reserved claims cannot be overridden by callers
            reserved = set(payload)
            payload.update({k: v for k, v in extra_claims.items() if k not in reserved})
        token = jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
        return token, token_id

    def create_access_token(
        self, subject: str, extra_claims: dict[str, Any] | None = None
    ) -> str:
        token, _ = self._create(subject, TokenType.access, self.access_ttl, extra_claims)
        return token

    def create_refresh_token(
        self, subject: str, jti: str | None = None
    ) -> tuple[str, str]:
        """Return ``(token, jti)`` so the caller can persist the jti for rotation."""
        return self._create(subject, TokenType.refresh, self.refresh_ttl, jti=jti)

    # ── Verification ────────────────────────────────────────────
    def decode(self, token: str, expected_type: TokenType | None = None) -> DecodedToken:
        try:
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algorithm],
                issuer=self.issuer,
                audience=self.audience,
                options={"require": ["exp", "iat", "nbf", "sub", "jti", "iss", "aud"]},
            )
        except jwt.ExpiredSignatureError as exc:
            raise TokenError("Token has expired") from exc
        except jwt.InvalidTokenError as exc:
            raise TokenError(f"Invalid token: {exc}") from exc

        token_type = TokenType(payload.get("type", ""))
        if expected_type is not None and token_type != expected_type:
            raise TokenError(
                f"Expected {expected_type.value} token, got {token_type.value}"
            )

        return DecodedToken(
            subject=payload["sub"],
            token_type=token_type,
            jti=payload["jti"],
            issued_at=datetime.fromtimestamp(payload["iat"], UTC),
            expires_at=datetime.fromtimestamp(payload["exp"], UTC),
            claims=payload,
        )


_default_manager: TokenManager | None = None


def get_token_manager() -> TokenManager:
    """Application-wide token manager built from settings (cached)."""
    global _default_manager
    if _default_manager is None:
        from app.core.config import get_settings

        s = get_settings()
        _default_manager = TokenManager(
            secret_key=s.jwt_secret_key,
            algorithm=s.jwt_algorithm,
            issuer=s.jwt_issuer,
            audience=s.jwt_audience,
            access_ttl=timedelta(minutes=s.access_token_expire_minutes),
            refresh_ttl=timedelta(days=s.refresh_token_expire_days),
        )
    return _default_manager
