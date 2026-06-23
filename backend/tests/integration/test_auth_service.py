"""Authentication service integration tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.security.passwords import PasswordManager, PasswordPolicy
from app.core.security.tokens import TokenManager, TokenType
from app.services.auth_service import AuthService, user_permissions
from app.services.exceptions import (
    AccountLockedError,
    AuthenticationError,
    ConflictError,
    ValidationError,
)

pytestmark = pytest.mark.integration

PASSWORD = "Str0ng-P@ssw0rd!"
NEW_PASSWORD = "An0ther-Str0ng-P@ss!"
SECRET = "unit-test-secret-key-32-bytes-minimum!!"


@pytest_asyncio.fixture
def auth(async_session: AsyncSession) -> AuthService:
    pm = PasswordManager(
        time_cost=1, memory_cost=8192, parallelism=1,
        policy=PasswordPolicy(min_length=12, history_size=3),
    )
    tm = TokenManager(secret_key=SECRET)
    settings = Settings(max_failed_logins=3, account_lockout_minutes=15, password_history_size=3)
    return AuthService(async_session, passwords=pm, tokens=tm, settings=settings)


async def _register(auth: AuthService, username: str = "alice") -> object:
    return await auth.register(
        username=username, email=f"{username}@example.com", password=PASSWORD,
        full_name="Alice Analyst",
    )


class TestRegistration:
    async def test_register_and_login(self, auth: AuthService) -> None:
        user = await _register(auth)
        assert user.email == "alice@example.com"  # decrypted via ORM
        logged_in, tokens = await auth.login(identifier="alice", password=PASSWORD)
        assert logged_in.id == user.id
        assert tokens.access_token and tokens.refresh_token

    async def test_login_by_email(self, auth: AuthService) -> None:
        await _register(auth)
        user, _ = await auth.login(identifier="alice@example.com", password=PASSWORD)
        assert user.username == "alice"

    async def test_duplicate_username_rejected(self, auth: AuthService) -> None:
        await _register(auth)
        with pytest.raises(ConflictError):
            await auth.register(username="alice", email="other@example.com", password=PASSWORD)

    async def test_duplicate_email_rejected(self, auth: AuthService) -> None:
        await _register(auth)
        with pytest.raises(ConflictError):
            await auth.register(username="bob", email="alice@example.com", password=PASSWORD)

    async def test_weak_password_rejected(self, auth: AuthService) -> None:
        from app.core.security.exceptions import PasswordPolicyError

        with pytest.raises(PasswordPolicyError):
            await auth.register(username="weak", email="weak@example.com", password="short")


class TestAuthentication:
    async def test_wrong_password_fails(self, auth: AuthService) -> None:
        await _register(auth)
        with pytest.raises(AuthenticationError):
            await auth.authenticate(identifier="alice", password="wrong-password")

    async def test_unknown_user_fails_generically(self, auth: AuthService) -> None:
        with pytest.raises(AuthenticationError):
            await auth.authenticate(identifier="ghost", password="whatever-123")

    async def test_lockout_after_threshold(self, auth: AuthService) -> None:
        await _register(auth)
        for _ in range(3):  # max_failed_logins = 3
            with pytest.raises(AuthenticationError):
                await auth.authenticate(identifier="alice", password="bad")
        # Now locked, even with the CORRECT password.
        with pytest.raises(AccountLockedError):
            await auth.authenticate(identifier="alice", password=PASSWORD)


class TestTokens:
    async def test_access_token_carries_permissions(self, auth: AuthService) -> None:
        user = await _register(auth)
        _, tokens = await auth.login(identifier="alice", password=PASSWORD)
        decoded = auth.tokens.decode(tokens.access_token, TokenType.access)
        assert decoded.subject == str(user.id)
        assert "perms" in decoded.claims

    async def test_refresh_rotation_revokes_old(self, auth: AuthService) -> None:
        await _register(auth)
        _, tokens = await auth.login(identifier="alice", password=PASSWORD)
        new_pair = await auth.refresh(tokens.refresh_token)
        assert new_pair.refresh_token != tokens.refresh_token
        # Old refresh token is now revoked.
        with pytest.raises(AuthenticationError):
            await auth.refresh(tokens.refresh_token)

    async def test_logout_revokes_refresh(self, auth: AuthService) -> None:
        user = await _register(auth)
        _, tokens = await auth.login(identifier="alice", password=PASSWORD)
        await auth.logout(tokens.refresh_token, actor_id=user.id)
        with pytest.raises(AuthenticationError):
            await auth.refresh(tokens.refresh_token)


class TestPasswordChange:
    async def test_change_password_success(self, auth: AuthService) -> None:
        user = await _register(auth)
        await auth.change_password(user, old_password=PASSWORD, new_password=NEW_PASSWORD)
        # Old password no longer works; new one does.
        with pytest.raises(AuthenticationError):
            await auth.authenticate(identifier="alice", password=PASSWORD)
        ok = await auth.authenticate(identifier="alice", password=NEW_PASSWORD)
        assert ok.id == user.id

    async def test_wrong_current_password_rejected(self, auth: AuthService) -> None:
        user = await _register(auth)
        with pytest.raises(AuthenticationError):
            await auth.change_password(user, old_password="nope-123456", new_password=NEW_PASSWORD)

    async def test_password_reuse_rejected(self, auth: AuthService) -> None:
        user = await _register(auth)
        with pytest.raises(ValidationError):
            # Reusing the current password must be blocked by history.
            await auth.change_password(user, old_password=PASSWORD, new_password=PASSWORD)


class TestPasswordExpiry:
    async def test_not_expired_when_recent(self, auth: AuthService) -> None:
        user = await _register(auth)
        assert not auth.is_password_expired(user)

    async def test_expired_when_old(self, auth: AuthService) -> None:
        user = await _register(auth)
        user.password_changed_at = datetime.now(UTC) - timedelta(days=200)
        assert auth.is_password_expired(user)


class TestPermissions:
    async def test_user_with_no_roles_has_no_perms(self, auth: AuthService) -> None:
        user = await _register(auth)
        assert user_permissions(user) == set()
