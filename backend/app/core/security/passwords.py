"""Password hashing (Argon2id) and password policy enforcement.

Argon2id is the OWASP-recommended password hashing algorithm (memory-hard,
resistant to GPU/ASIC cracking and side-channel attacks). We use the reference
``argon2-cffi`` implementation directly for precise control over cost parameters.

Responsibilities:
* hash / verify passwords (with transparent rehashing when params strengthen),
* enforce password strength policy,
* detect password reuse against a hash history,
* expose helpers for password-expiration checks (timestamps live in the model).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerifyMismatchError

from app.core.security.exceptions import PasswordPolicyError

# A small embedded denylist of catastrophically common passwords. In production
# this is augmented by a service-layer check against the full "Have I Been Pwned"
# k-anonymity range API or a bundled rockyou-derived bloom filter.
_COMMON_PASSWORDS = frozenset(
    {
        "password",
        "password1",
        "passw0rd",
        "123456",
        "12345678",
        "123456789",
        "qwerty",
        "qwertyuiop",
        "abc123",
        "letmein",
        "welcome",
        "admin",
        "administrator",
        "iloveyou",
        "monkey",
        "dragon",
        "sunshine",
        "princess",
        "changeme",
        "secret",
    }
)

_RE_LOWER = re.compile(r"[a-z]")
_RE_UPPER = re.compile(r"[A-Z]")
_RE_DIGIT = re.compile(r"[0-9]")
_RE_SYMBOL = re.compile(r"[^A-Za-z0-9]")


@dataclass(frozen=True, slots=True)
class PasswordPolicy:
    """Configurable password policy."""

    min_length: int = 12
    max_length: int = 128
    require_lower: bool = True
    require_upper: bool = True
    require_digit: bool = True
    require_symbol: bool = True
    history_size: int = 5
    max_age_days: int = 90


@dataclass(slots=True)
class PasswordManager:
    """Argon2id password hasher + policy enforcer.

    Instantiate directly with explicit parameters in tests; the application uses
    :func:`get_password_manager`, which builds one from :class:`Settings`.
    """

    time_cost: int = 3
    memory_cost: int = 65536  # KiB
    parallelism: int = 4
    hash_len: int = 32
    salt_len: int = 16
    policy: PasswordPolicy = field(default_factory=PasswordPolicy)
    _hasher: PasswordHasher = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._hasher = PasswordHasher(
            time_cost=self.time_cost,
            memory_cost=self.memory_cost,
            parallelism=self.parallelism,
            hash_len=self.hash_len,
            salt_len=self.salt_len,
            type=Type.ID,  # Argon2id
        )

    # ── Hashing / verification ──────────────────────────────────
    def hash(self, password: str) -> str:
        """Hash a password with a per-hash random salt. Returns PHC-format string."""
        return self._hasher.hash(password)

    def verify(self, hashed: str, password: str) -> bool:
        """Constant-time verify. Returns ``False`` instead of raising on mismatch."""
        try:
            return self._hasher.verify(hashed, password)
        except (VerifyMismatchError, InvalidHashError):
            return False

    def needs_rehash(self, hashed: str) -> bool:
        """True if the hash was produced with weaker params than current policy."""
        try:
            return self._hasher.check_needs_rehash(hashed)
        except InvalidHashError:
            return True

    # ── Policy enforcement ──────────────────────────────────────
    def validate_strength(self, password: str, *, raise_on_fail: bool = True) -> list[str]:
        """Return a list of policy violations (empty == valid).

        With ``raise_on_fail`` (default), raises :class:`PasswordPolicyError`
        listing all violations.
        """
        p = self.policy
        issues: list[str] = []

        if len(password) < p.min_length:
            issues.append(f"must be at least {p.min_length} characters")
        if len(password) > p.max_length:
            issues.append(f"must be at most {p.max_length} characters")
        if p.require_lower and not _RE_LOWER.search(password):
            issues.append("must contain a lowercase letter")
        if p.require_upper and not _RE_UPPER.search(password):
            issues.append("must contain an uppercase letter")
        if p.require_digit and not _RE_DIGIT.search(password):
            issues.append("must contain a digit")
        if p.require_symbol and not _RE_SYMBOL.search(password):
            issues.append("must contain a symbol")
        if password.lower() in _COMMON_PASSWORDS:
            issues.append("is among the most common passwords and is not allowed")
        if _is_trivial_sequence(password):
            issues.append("must not be a simple repeated or sequential pattern")

        if issues and raise_on_fail:
            raise PasswordPolicyError("Password policy violation: " + "; ".join(issues))
        return issues

    def is_reused(self, password: str, history_hashes: list[str]) -> bool:
        """True if ``password`` matches any hash in the recent history."""
        return any(self.verify(h, password) for h in history_hashes[: self.policy.history_size])


def _is_trivial_sequence(password: str) -> bool:
    """Detect all-same characters or short ascending/descending runs."""
    if len(set(password)) == 1:
        return True
    lowered = password.lower()
    sequences = ("abcdefghijklmnopqrstuvwxyz", "0123456789", "qwertyuiop")
    for seq in sequences:
        for i in range(len(seq) - 3):
            window = seq[i : i + 4]
            if window in lowered or window[::-1] in lowered:
                return True
    return False


_default_manager: PasswordManager | None = None


def get_password_manager() -> PasswordManager:
    """Application-wide password manager built from settings (cached)."""
    global _default_manager
    if _default_manager is None:
        from app.core.config import get_settings

        s = get_settings()
        _default_manager = PasswordManager(
            time_cost=s.argon2_time_cost,
            memory_cost=s.argon2_memory_cost_kib,
            parallelism=s.argon2_parallelism,
            hash_len=s.argon2_hash_len,
            salt_len=s.argon2_salt_len,
            policy=PasswordPolicy(
                min_length=s.password_min_length,
                history_size=s.password_history_size,
                max_age_days=s.password_max_age_days,
            ),
        )
    return _default_manager
