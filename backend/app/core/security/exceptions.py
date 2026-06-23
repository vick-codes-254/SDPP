"""Typed security exception hierarchy.

These are deliberately distinct from generic application errors so that the API
layer can map them to safe, non-leaking HTTP responses and so the audit layer
can record security-relevant failures (tamper detection, wrong key, etc.).
"""

from __future__ import annotations


class SecurityError(Exception):
    """Base class for all security-relevant failures."""


class EncryptionError(SecurityError):
    """Raised when encryption fails (e.g. invalid key length)."""


class DecryptionError(SecurityError):
    """Raised when authenticated decryption fails.

    A failure here means either the key is wrong OR the ciphertext/AAD has been
    tampered with (GCM authentication tag mismatch). The two cases are
    intentionally indistinguishable to the caller to avoid oracle attacks.
    """


class IntegrityError(SecurityError):
    """Raised when a stored file's hash does not match its recorded hash."""


class KeyManagementError(SecurityError):
    """Raised for KMS / key-lifecycle failures (rotation, revocation, missing key)."""


class TokenError(SecurityError):
    """Raised when a JWT is invalid, expired, or fails signature/claim checks."""


class PasswordPolicyError(SecurityError):
    """Raised when a password fails strength/history/expiration policy."""
