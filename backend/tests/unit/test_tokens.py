"""JWT issuance & verification tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import jwt
import pytest

from app.core.security.exceptions import TokenError
from app.core.security.tokens import TokenManager, TokenType

pytestmark = pytest.mark.unit

SECRET = "test-secret-key-at-least-32-bytes-long!!"


@pytest.fixture
def tm() -> TokenManager:
    return TokenManager(secret_key=SECRET, issuer="sdpp", audience="sdpp-clients")


class TestAccessTokens:
    def test_round_trip(self, tm: TokenManager) -> None:
        token = tm.create_access_token("user-123", {"role": "analyst"})
        decoded = tm.decode(token, TokenType.access)
        assert decoded.subject == "user-123"
        assert decoded.token_type is TokenType.access
        assert decoded.claims["role"] == "analyst"

    def test_has_jti(self, tm: TokenManager) -> None:
        decoded = tm.decode(tm.create_access_token("u"))
        assert decoded.jti

    def test_reserved_claims_not_overridable(self, tm: TokenManager) -> None:
        token = tm.create_access_token("u", {"sub": "attacker", "type": "refresh"})
        decoded = tm.decode(token)
        assert decoded.subject == "u"
        assert decoded.token_type is TokenType.access


class TestRefreshTokens:
    def test_round_trip_and_jti_returned(self, tm: TokenManager) -> None:
        token, jti = tm.create_refresh_token("user-1")
        decoded = tm.decode(token, TokenType.refresh)
        assert decoded.jti == jti
        assert decoded.token_type is TokenType.refresh

    def test_type_enforced(self, tm: TokenManager) -> None:
        access = tm.create_access_token("u")
        with pytest.raises(TokenError):
            tm.decode(access, TokenType.refresh)


class TestSecurity:
    def test_tampered_signature_rejected(self, tm: TokenManager) -> None:
        token = tm.create_access_token("u")
        tampered = token[:-3] + ("aaa" if not token.endswith("aaa") else "bbb")
        with pytest.raises(TokenError):
            tm.decode(tampered)

    def test_wrong_secret_rejected(self, tm: TokenManager) -> None:
        token = tm.create_access_token("u")
        other = TokenManager(secret_key="a-completely-different-secret-key-here!!")
        with pytest.raises(TokenError):
            other.decode(token)

    def test_wrong_issuer_rejected(self) -> None:
        issuer_a = TokenManager(secret_key=SECRET, issuer="evil", audience="sdpp-clients")
        verifier = TokenManager(secret_key=SECRET, issuer="sdpp", audience="sdpp-clients")
        with pytest.raises(TokenError):
            verifier.decode(issuer_a.create_access_token("u"))

    def test_wrong_audience_rejected(self) -> None:
        issuer = TokenManager(secret_key=SECRET, issuer="sdpp", audience="other-app")
        verifier = TokenManager(secret_key=SECRET, issuer="sdpp", audience="sdpp-clients")
        with pytest.raises(TokenError):
            verifier.decode(issuer.create_access_token("u"))

    def test_expired_token_rejected(self) -> None:
        past = datetime(2020, 1, 1, tzinfo=UTC)
        tm = TokenManager(
            secret_key=SECRET, access_ttl=timedelta(minutes=1), _now=lambda: past
        )
        token = tm.create_access_token("u")
        # verify with a normal clock -> expired
        verifier = TokenManager(secret_key=SECRET)
        with pytest.raises(TokenError):
            verifier.decode(token)

    def test_alg_none_attack_rejected(self, tm: TokenManager) -> None:
        # Forge an unsigned token with alg=none; must be rejected.
        forged = jwt.encode(
            {"sub": "attacker", "type": "access"}, key="", algorithm="none"
        )
        with pytest.raises(TokenError):
            tm.decode(forged)
