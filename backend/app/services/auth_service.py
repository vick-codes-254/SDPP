"""Authentication & account-security service.

Responsibilities:
* user registration with password-strength enforcement and role assignment,
* login with constant-time password verification, brute-force lockout, and audit,
* JWT access + refresh issuance, refresh rotation, and revocation,
* password change with history (no-reuse) and expiration tracking.

All security-relevant outcomes are written to the tamper-evident audit log.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
from app.core.security.passwords import PasswordManager, get_password_manager
from app.core.security.tokens import TokenManager, TokenType, get_token_manager
from app.models.enums import AuditEventType, AuditOutcome
from app.models.user import PasswordHistory, RefreshToken, Role, User
from app.services.audit_service import AuditService
from app.services.exceptions import (
    AccountInactiveError,
    AccountLockedError,
    AuthenticationError,
    ConflictError,
    ValidationError,
)


def _as_utc(value: datetime) -> datetime:
    """Normalize a (possibly naive) datetime to aware UTC.

    PostgreSQL returns timezone-aware datetimes; SQLite returns naive. All values
    are stored in UTC, so naive values are interpreted as UTC.
    """
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def user_permissions(user: User) -> set[str]:
    """Effective permission codes for a user (union over assigned roles)."""
    perms: set[str] = set()
    for role in user.roles:
        perms.update(p.code for p in role.permissions)
    return perms


@dataclass(frozen=True, slots=True)
class TokenPair:
    access_token: str
    refresh_token: str
    token_type: str = "bearer"  # noqa: S105 - OAuth2 scheme name, not a secret


class AuthService:
    def __init__(
        self,
        db: AsyncSession,
        *,
        audit: AuditService | None = None,
        passwords: PasswordManager | None = None,
        tokens: TokenManager | None = None,
        settings: Settings | None = None,
    ) -> None:
        self.db = db
        self.settings = settings or get_settings()
        self.audit = audit or AuditService(db)
        self.passwords = passwords or get_password_manager()
        self.tokens = tokens or get_token_manager()

    # ── Lookups ─────────────────────────────────────────────────
    async def _by_username(self, username: str) -> User | None:
        res = await self.db.execute(select(User).where(User.username == username))
        return res.scalar_one_or_none()

    async def _by_email(self, email: str) -> User | None:
        # BlindIndex transparently HMACs the supplied plaintext for comparison.
        res = await self.db.execute(select(User).where(User.email_bidx == email))
        return res.scalar_one_or_none()

    async def get_user(self, user_id: uuid.UUID) -> User | None:
        res = await self.db.execute(select(User).where(User.id == user_id))
        return res.scalar_one_or_none()

    # ── Registration ────────────────────────────────────────────
    async def register(
        self,
        *,
        username: str,
        email: str,
        password: str,
        full_name: str | None = None,
        phone: str | None = None,
        role_names: list[str] | None = None,
        is_superuser: bool = False,
        actor_id: uuid.UUID | None = None,
        ip_address: str | None = None,
    ) -> User:
        self.passwords.validate_strength(password)  # raises PasswordPolicyError

        if await self._by_username(username):
            raise ConflictError("Username already exists")
        if await self._by_email(email):
            raise ConflictError("Email already registered")

        now = datetime.now(UTC)
        user = User(
            id=uuid.uuid4(),
            username=username,
            email=email,
            email_bidx=email,  # BlindIndex column hashes on write
            full_name=full_name,
            phone=phone,
            hashed_password=self.passwords.hash(password),
            is_active=True,
            is_superuser=is_superuser,
            password_changed_at=now,
        )
        roles: list[Role] = []
        if role_names:
            roles = list(
                (await self.db.execute(select(Role).where(Role.name.in_(role_names))))
                .scalars()
                .all()
            )
        # Always assign (even empty) so the collection is "loaded" and accessing
        # user.roles later never triggers an async lazy-load in a sync context.
        user.roles = roles

        self.db.add(user)
        await self.db.flush()
        self.db.add(
            PasswordHistory(
                id=uuid.uuid4(), user_id=user.id,
                hashed_password=user.hashed_password, created_at=now,
            )
        )
        await self.audit.record(
            event_type=AuditEventType.role_change,
            outcome=AuditOutcome.success,
            actor_id=actor_id or user.id,
            actor_label=username,
            resource_type="user",
            resource_id=str(user.id),
            action="register",
            ip_address=ip_address,
            detail={"roles": role_names or []},
        )
        await self.db.flush()
        return user

    # ── Authentication ──────────────────────────────────────────
    async def authenticate(
        self,
        *,
        identifier: str,
        password: str,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> User:
        """Verify credentials. Generic failures avoid user enumeration."""
        user = await self._by_username(identifier) or await self._by_email(identifier)

        # Always run a hash verification to keep timing uniform for unknown users.
        if user is None:
            self.passwords.dummy_verify(password)
            await self._audit_login(None, identifier, AuditOutcome.failure, ip_address, user_agent, "unknown_user")
            await self.db.commit()  # persist the failed-login audit despite the raise
            raise AuthenticationError("Invalid credentials")

        now = datetime.now(UTC)
        if user.locked_until and _as_utc(user.locked_until) > now:
            await self._audit_login(user, user.username, AuditOutcome.denied, ip_address, user_agent, "locked")
            await self.db.commit()
            raise AccountLockedError("Account is temporarily locked")

        if not self.passwords.verify(user.hashed_password, password):
            await self._register_failure(user, ip_address, user_agent)
            raise AuthenticationError("Invalid credentials")

        if not user.is_active:
            await self._audit_login(user, user.username, AuditOutcome.denied, ip_address, user_agent, "inactive")
            raise AccountInactiveError("Account is disabled")

        # Success: transparent rehash if params strengthened; reset lockout state.
        if self.passwords.needs_rehash(user.hashed_password):
            user.hashed_password = self.passwords.hash(password)
        user.failed_login_count = 0
        user.locked_until = None
        user.last_login_at = now
        await self._audit_login(user, user.username, AuditOutcome.success, ip_address, user_agent, "ok")
        await self.db.flush()
        return user

    async def _register_failure(
        self, user: User, ip_address: str | None, user_agent: str | None
    ) -> None:
        user.failed_login_count += 1
        reason = "bad_password"
        if user.failed_login_count >= self.settings.max_failed_logins:
            user.locked_until = datetime.now(UTC) + timedelta(
                minutes=self.settings.account_lockout_minutes
            )
            reason = "locked_now"
        await self._audit_login(user, user.username, AuditOutcome.failure, ip_address, user_agent, reason)
        # Commit so the lockout counter + audit survive the request rollback.
        await self.db.commit()

    async def _audit_login(
        self, user: User | None, label: str, outcome: AuditOutcome,
        ip: str | None, ua: str | None, reason: str,
    ) -> None:
        await self.audit.record(
            event_type=(
                AuditEventType.login if outcome is AuditOutcome.success
                else AuditEventType.login_failed
            ),
            outcome=outcome,
            actor_id=user.id if user else None,
            actor_label=label,
            resource_type="auth",
            action="login",
            ip_address=ip,
            user_agent=ua,
            detail={"reason": reason},
        )

    # ── Token issuance / rotation ───────────────────────────────
    def is_password_expired(self, user: User) -> bool:
        if not user.password_changed_at:
            return False
        max_age = timedelta(days=self.settings.password_max_age_days)
        return datetime.now(UTC) - _as_utc(user.password_changed_at) > max_age

    async def issue_tokens(
        self, user: User, *, ip_address: str | None = None, user_agent: str | None = None
    ) -> TokenPair:
        access = self.tokens.create_access_token(
            str(user.id),
            {"username": user.username, "perms": sorted(user_permissions(user)),
             "su": user.is_superuser},
        )
        refresh, jti = self.tokens.create_refresh_token(str(user.id))
        self.db.add(
            RefreshToken(
                id=uuid.uuid4(), user_id=user.id, jti=jti,
                expires_at=datetime.now(UTC) + self.tokens.refresh_ttl,
                user_agent=user_agent, ip_address=ip_address,
                created_at=datetime.now(UTC),
            )
        )
        await self.db.flush()
        return TokenPair(access_token=access, refresh_token=refresh)

    async def login(
        self, *, identifier: str, password: str,
        ip_address: str | None = None, user_agent: str | None = None,
    ) -> tuple[User, TokenPair]:
        user = await self.authenticate(
            identifier=identifier, password=password,
            ip_address=ip_address, user_agent=user_agent,
        )
        tokens = await self.issue_tokens(user, ip_address=ip_address, user_agent=user_agent)
        return user, tokens

    async def refresh(
        self, refresh_token: str, *, ip_address: str | None = None, user_agent: str | None = None
    ) -> TokenPair:
        decoded = self.tokens.decode(refresh_token, TokenType.refresh)  # raises TokenError
        res = await self.db.execute(
            select(RefreshToken).where(RefreshToken.jti == decoded.jti)
        )
        record = res.scalar_one_or_none()
        if record is None or not record.is_active:
            raise AuthenticationError("Refresh token is invalid or revoked")

        user = await self.get_user(uuid.UUID(decoded.subject))
        if user is None or not user.is_active:
            raise AuthenticationError("User not found or inactive")

        # Rotate: revoke the presented token, issue a fresh pair.
        record.revoked_at = datetime.now(UTC)
        new_pair = await self.issue_tokens(user, ip_address=ip_address, user_agent=user_agent)
        # link rotation (best-effort: newest token is the last added)
        await self.db.flush()
        return new_pair

    async def revoke_refresh(self, jti: str) -> None:
        res = await self.db.execute(select(RefreshToken).where(RefreshToken.jti == jti))
        record = res.scalar_one_or_none()
        if record and record.is_active:
            record.revoked_at = datetime.now(UTC)
            await self.db.flush()

    async def logout(self, refresh_token: str, *, actor_id: uuid.UUID | None = None) -> None:
        try:
            decoded = self.tokens.decode(refresh_token, TokenType.refresh)
        except Exception:  # noqa: BLE001 - logout is idempotent/best-effort
            return
        await self.revoke_refresh(decoded.jti)
        await self.audit.record(
            event_type=AuditEventType.logout, outcome=AuditOutcome.success,
            actor_id=actor_id, resource_type="auth", action="logout",
        )

    # ── Password change ─────────────────────────────────────────
    async def change_password(
        self, user: User, *, old_password: str, new_password: str,
        ip_address: str | None = None,
    ) -> None:
        if not self.passwords.verify(user.hashed_password, old_password):
            await self.audit.record(
                event_type=AuditEventType.password_change, outcome=AuditOutcome.failure,
                actor_id=user.id, actor_label=user.username, action="change_password",
                ip_address=ip_address, detail={"reason": "wrong_current_password"},
            )
            await self.db.commit()  # persist the failed attempt audit
            raise AuthenticationError("Current password is incorrect")

        self.passwords.validate_strength(new_password)

        history = (
            await self.db.execute(
                select(PasswordHistory)
                .where(PasswordHistory.user_id == user.id)
                .order_by(PasswordHistory.created_at.desc())
                .limit(self.passwords.policy.history_size)
            )
        ).scalars().all()
        if self.passwords.is_reused(new_password, [h.hashed_password for h in history]):
            raise ValidationError(
                f"Password was used recently; choose one not among your last "
                f"{self.passwords.policy.history_size} passwords"
            )

        now = datetime.now(UTC)
        user.hashed_password = self.passwords.hash(new_password)
        user.password_changed_at = now
        self.db.add(
            PasswordHistory(
                id=uuid.uuid4(), user_id=user.id,
                hashed_password=user.hashed_password, created_at=now,
            )
        )
        # Revoke all active refresh tokens on password change.
        active = (
            await self.db.execute(
                select(RefreshToken).where(
                    RefreshToken.user_id == user.id, RefreshToken.revoked_at.is_(None)
                )
            )
        ).scalars().all()
        for token in active:
            token.revoked_at = now

        await self.audit.record(
            event_type=AuditEventType.password_change, outcome=AuditOutcome.success,
            actor_id=user.id, actor_label=user.username, action="change_password",
            ip_address=ip_address,
        )
        await self.db.flush()
