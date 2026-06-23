"""Shared domain enumerations (dependency-free).

These live in ``app.core`` so any layer — core, models, schemas, services — can use
them without importing the ORM. ``app.models.enums`` re-exports them for ergonomic
``from app.models.enums import ...`` access in model definitions.
"""

from __future__ import annotations

from enum import StrEnum


class FileCategory(StrEnum):
    video = "video"
    audio = "audio"
    image = "image"
    document = "document"
    pdf = "pdf"
    json = "json"
    csv = "csv"
    backup = "backup"
    log = "log"
    evidence = "evidence"
    archive = "archive"
    other = "other"


class FileStatus(StrEnum):
    uploaded = "uploaded"        # received, not yet encrypted
    encrypted = "encrypted"      # ciphertext written to vault
    available = "available"      # encrypted + integrity recorded, ready
    quarantined = "quarantined"  # integrity failure / suspected tamper
    deleted = "deleted"          # crypto-shredded (key destroyed)


class KeyType(StrEnum):
    data = "data"          # per-file Data Encryption Key (DEK)
    field = "field"        # database field encryption key
    master_ref = "master"  # reference to a KMS master key (KEK)


class KeyStatus(StrEnum):
    active = "active"
    rotated = "rotated"
    revoked = "revoked"
    expired = "expired"
    compromised = "compromised"
    destroyed = "destroyed"  # crypto-shredded


class RotationType(StrEnum):
    dek_rotation = "dek_rotation"
    master_key_rotation = "master_key_rotation"
    field_key_rotation = "field_key_rotation"


class AuditEventType(StrEnum):
    login = "login"
    logout = "logout"
    login_failed = "login_failed"
    upload = "upload"
    download = "download"
    encrypt = "encrypt"
    decrypt = "decrypt"
    decrypt_failed = "decrypt_failed"
    delete = "delete"
    restore = "restore"
    integrity_check = "integrity_check"
    integrity_violation = "integrity_violation"
    key_generated = "key_generated"
    key_rotation = "key_rotation"
    key_revoked = "key_revoked"
    failed_access = "failed_access"
    access_denied = "access_denied"
    password_change = "password_change"
    role_change = "role_change"
    report_generated = "report_generated"
    config_change = "config_change"


class AuditOutcome(StrEnum):
    success = "success"
    failure = "failure"
    denied = "denied"


class IntegrityTarget(StrEnum):
    plaintext = "plaintext"    # hash of original content
    ciphertext = "ciphertext"  # hash of stored encrypted blob (at-rest tamper)


class IntegrityResult(StrEnum):
    passed = "passed"
    failed = "failed"
    error = "error"


class AlertType(StrEnum):
    integrity_violation = "integrity_violation"
    failed_decryption = "failed_decryption"
    brute_force = "brute_force"
    unauthorized_access = "unauthorized_access"
    key_compromise = "key_compromise"
    tamper_detected = "tamper_detected"
    anomaly = "anomaly"
    policy_violation = "policy_violation"


class AlertSeverity(StrEnum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class AlertStatus(StrEnum):
    open = "open"
    acknowledged = "acknowledged"
    resolved = "resolved"
    false_positive = "false_positive"


class ComplianceFramework(StrEnum):
    owasp_asvs = "owasp_asvs"
    nist_csf = "nist_csf"
    nist_crypto = "nist_crypto"
    iso_27001 = "iso_27001"


class ReportStatus(StrEnum):
    draft = "draft"
    final = "final"
