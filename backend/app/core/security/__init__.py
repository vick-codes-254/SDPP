"""Cryptographic & security primitives.

This package contains the *low-level, dependency-free* security building blocks
of SDPP. Modules here MUST NOT import application config or the database — they
are pure, deterministically testable primitives:

  - crypto      : AES-256-GCM authenticated encryption (one-shot + streaming)
  - hashing     : SHA-256 integrity hashing & HMAC
  - passwords   : Argon2id password hashing & policy
  - tokens      : JWT issuance / verification
  - envelope    : envelope encryption (DEK wrapped by KMS master key)
  - field_encryption : transparent SQLAlchemy column encryption
  - exceptions  : typed security error hierarchy
"""
