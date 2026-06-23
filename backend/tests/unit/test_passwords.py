"""Argon2id password hashing & policy tests."""

from __future__ import annotations

import pytest

from app.core.security.exceptions import PasswordPolicyError
from app.core.security.passwords import PasswordManager, PasswordPolicy

pytestmark = pytest.mark.unit


@pytest.fixture
def pm() -> PasswordManager:
    # Low cost params for fast tests; production uses settings-driven values.
    return PasswordManager(time_cost=1, memory_cost=8192, parallelism=1)


class TestHashing:
    def test_hash_and_verify(self, pm: PasswordManager) -> None:
        h = pm.hash("Str0ng-P@ssw0rd!")
        assert pm.verify(h, "Str0ng-P@ssw0rd!")

    def test_wrong_password_fails(self, pm: PasswordManager) -> None:
        h = pm.hash("Str0ng-P@ssw0rd!")
        assert not pm.verify(h, "wrong-password")

    def test_is_argon2id(self, pm: PasswordManager) -> None:
        # PHC string identifies the variant
        assert pm.hash("Str0ng-P@ssw0rd!").startswith("$argon2id$")

    def test_salt_is_random(self, pm: PasswordManager) -> None:
        a = pm.hash("Str0ng-P@ssw0rd!")
        b = pm.hash("Str0ng-P@ssw0rd!")
        assert a != b  # unique salt per hash

    def test_verify_invalid_hash_returns_false(self, pm: PasswordManager) -> None:
        assert not pm.verify("not-a-valid-hash", "whatever")

    def test_needs_rehash_on_stronger_params(self, pm: PasswordManager) -> None:
        weak = PasswordManager(time_cost=1, memory_cost=8192, parallelism=1)
        strong = PasswordManager(time_cost=4, memory_cost=65536, parallelism=2)
        h = weak.hash("Str0ng-P@ssw0rd!")
        assert strong.needs_rehash(h)


class TestStrengthPolicy:
    def test_strong_password_passes(self, pm: PasswordManager) -> None:
        assert pm.validate_strength("Str0ng-P@ssw0rd!") == []

    @pytest.mark.parametrize(
        "weak",
        ["short", "alllowercase1!", "ALLUPPERCASE1!", "NoDigits!!", "NoSymbols123"],
    )
    def test_weak_passwords_fail(self, pm: PasswordManager, weak: str) -> None:
        assert pm.validate_strength(weak, raise_on_fail=False) != []

    def test_common_password_rejected(self, pm: PasswordManager) -> None:
        issues = pm.validate_strength("password", raise_on_fail=False)
        assert any("common" in i for i in issues)

    def test_sequential_rejected(self, pm: PasswordManager) -> None:
        issues = pm.validate_strength("abcd-ABCD-1234!", raise_on_fail=False)
        assert any("sequential" in i or "repeated" in i for i in issues)

    def test_raises_on_fail(self, pm: PasswordManager) -> None:
        with pytest.raises(PasswordPolicyError):
            pm.validate_strength("weak")

    def test_min_length_configurable(self) -> None:
        pm = PasswordManager(
            time_cost=1, memory_cost=8192, parallelism=1,
            policy=PasswordPolicy(min_length=20),
        )
        assert any("20" in i for i in pm.validate_strength("Str0ng-P@ss!", raise_on_fail=False))


class TestHistory:
    def test_reuse_detected(self, pm: PasswordManager) -> None:
        old = [pm.hash("OldP@ssw0rd-1!"), pm.hash("OldP@ssw0rd-2!")]
        assert pm.is_reused("OldP@ssw0rd-1!", old)

    def test_new_password_not_reused(self, pm: PasswordManager) -> None:
        old = [pm.hash("OldP@ssw0rd-1!")]
        assert not pm.is_reused("BrandN3w-P@ss!", old)
