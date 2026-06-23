"""Machine-readable compliance control catalog.

Each :class:`Control` maps a framework requirement to a concrete, *evaluable*
check key. The Compliance Service runs the check against the live configuration
and produces a pass/fail result + evidence, then aggregates a score per framework.

Check keys (evaluated in app/services/compliance/evaluator.py):
  aes_256_gcm, unique_dek_per_object, envelope_encryption, sha256_integrity,
  argon2id_passwords, password_policy, tls_1_3, security_headers, secure_cookies,
  rbac_enabled, least_privilege, jwt_rotation, audit_immutable, audit_chain,
  log_redaction, kms_provider, key_rotation, no_hardcoded_secrets,
  prod_hardening, input_validation, dependency_audit, account_lockout.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.core.enums import ComplianceFramework as FW


@dataclass(frozen=True, slots=True)
class Control:
    id: str
    framework: FW
    title: str
    description: str
    check: str
    severity: str = "medium"  # informational | low | medium | high | critical


CONTROLS: tuple[Control, ...] = (
    # ─────────────────── OWASP ASVS v4 ───────────────────
    Control("ASVS-2.4.1", FW.owasp_asvs, "Password hashing",
            "Passwords stored with an approved, memory-hard algorithm (Argon2id).",
            "argon2id_passwords", "high"),
    Control("ASVS-2.1.1", FW.owasp_asvs, "Password policy",
            "Enforce minimum length, complexity, history and expiration.",
            "password_policy", "medium"),
    Control("ASVS-2.2.1", FW.owasp_asvs, "Anti-automation / lockout",
            "Throttle and lock accounts after repeated failed logins.",
            "account_lockout", "medium"),
    Control("ASVS-3.5.3", FW.owasp_asvs, "Token management",
            "Stateless tokens validated for signature, issuer, audience, expiry; refresh rotation.",
            "jwt_rotation", "high"),
    Control("ASVS-4.1.1", FW.owasp_asvs, "Access control enforced server-side",
            "RBAC enforced on the trusted server layer, deny by default.",
            "rbac_enabled", "high"),
    Control("ASVS-4.1.3", FW.owasp_asvs, "Least privilege",
            "Roles grant only the permissions required.",
            "least_privilege", "medium"),
    Control("ASVS-6.2.1", FW.owasp_asvs, "Approved cryptography",
            "Use approved AEAD (AES-256-GCM) for confidentiality + integrity.",
            "aes_256_gcm", "high"),
    Control("ASVS-6.2.3", FW.owasp_asvs, "Unique keys / nonces",
            "Unique DEK per object and unique nonces per encryption.",
            "unique_dek_per_object", "high"),
    Control("ASVS-6.4.1", FW.owasp_asvs, "Key management",
            "Keys protected by a KMS; no plaintext keys at rest.",
            "envelope_encryption", "high"),
    Control("ASVS-9.1.1", FW.owasp_asvs, "TLS for all traffic",
            "All communication uses TLS 1.2+ (SDPP requires 1.3).",
            "tls_1_3", "high"),
    Control("ASVS-14.4.1", FW.owasp_asvs, "Security headers",
            "Send HSTS, CSP, X-Content-Type-Options, etc.",
            "security_headers", "medium"),
    Control("ASVS-7.1.1", FW.owasp_asvs, "No secrets in logs",
            "Sensitive data is redacted from logs.",
            "log_redaction", "medium"),
    Control("ASVS-5.1.1", FW.owasp_asvs, "Input validation",
            "All input validated/typed at the boundary (Pydantic).",
            "input_validation", "medium"),

    # ─────────────────── NIST CSF 2.0 ───────────────────
    Control("CSF-PR.AC-01", FW.nist_csf, "Identities & credentials",
            "Manage identities, strong authentication and RBAC.",
            "rbac_enabled", "high"),
    Control("CSF-PR.AC-04", FW.nist_csf, "Access permissions (least privilege)",
            "Least privilege and separation of duties.",
            "least_privilege", "medium"),
    Control("CSF-PR.DS-01", FW.nist_csf, "Data-at-rest protection",
            "Encrypt sensitive data and files at rest.",
            "envelope_encryption", "high"),
    Control("CSF-PR.DS-02", FW.nist_csf, "Data-in-transit protection",
            "Encrypt data in transit (TLS 1.3).",
            "tls_1_3", "high"),
    Control("CSF-PR.DS-06", FW.nist_csf, "Integrity checking",
            "Use integrity verification to detect tampering.",
            "sha256_integrity", "high"),
    Control("CSF-DE.CM-01", FW.nist_csf, "Continuous monitoring",
            "Monitor for security events and anomalies.",
            "audit_chain", "medium"),
    Control("CSF-PR.PS-04", FW.nist_csf, "Log integrity",
            "Generate and protect tamper-evident logs.",
            "audit_immutable", "high"),
    Control("CSF-PR.DS-08", FW.nist_csf, "Key management",
            "Cryptographic keys managed throughout lifecycle.",
            "key_rotation", "medium"),

    # ─────────────── NIST Cryptography standards ───────────────
    Control("NIST-SP800-38D", FW.nist_crypto, "AES-GCM (AEAD)",
            "AES-GCM used per SP 800-38D with unique nonces.",
            "aes_256_gcm", "high"),
    Control("NIST-SP800-57", FW.nist_crypto, "Key management lifecycle",
            "Key generation, rotation, revocation per SP 800-57.",
            "key_rotation", "high"),
    Control("NIST-SP800-63B", FW.nist_crypto, "Memory-hard password hashing",
            "Argon2id / approved password storage per SP 800-63B.",
            "argon2id_passwords", "high"),
    Control("NIST-SP800-131A", FW.nist_crypto, "Approved key lengths",
            "256-bit symmetric keys, SHA-256 (≥112-bit security).",
            "unique_dek_per_object", "high"),
    Control("NIST-FIPS180-4", FW.nist_crypto, "Secure hashing",
            "SHA-256 per FIPS 180-4 for integrity.",
            "sha256_integrity", "medium"),

    # ─────────────────── ISO/IEC 27001:2022 (Annex A) ───────────────────
    Control("ISO-A.5.15", FW.iso_27001, "Access control",
            "Establish access control based on business and security requirements.",
            "rbac_enabled", "high"),
    Control("ISO-A.8.24", FW.iso_27001, "Use of cryptography",
            "Policy on cryptography implemented (AES-256-GCM, KMS).",
            "aes_256_gcm", "high"),
    Control("ISO-A.8.5", FW.iso_27001, "Secure authentication",
            "Secure authentication technologies and procedures.",
            "jwt_rotation", "high"),
    Control("ISO-A.5.17", FW.iso_27001, "Authentication information",
            "Protect secrets; strong password storage & policy.",
            "argon2id_passwords", "high"),
    Control("ISO-A.8.15", FW.iso_27001, "Logging",
            "Produce, protect and review event logs.",
            "audit_immutable", "high"),
    Control("ISO-A.8.16", FW.iso_27001, "Monitoring activities",
            "Monitor networks/systems for anomalous behaviour.",
            "audit_chain", "medium"),
    Control("ISO-A.8.12", FW.iso_27001, "Data leakage prevention",
            "Protect against disclosure of sensitive data (encryption at rest).",
            "envelope_encryption", "high"),
    Control("ISO-A.8.10", FW.iso_27001, "Information deletion",
            "Securely delete data when no longer required (crypto-shred).",
            "key_rotation", "medium"),
    Control("ISO-A.8.28", FW.iso_27001, "Secure coding",
            "Input validation and secure development practices.",
            "input_validation", "medium"),
    Control("ISO-A.8.9", FW.iso_27001, "Configuration management",
            "Secure, validated configuration; no hardcoded secrets.",
            "no_hardcoded_secrets", "high"),
)


def controls_for_framework(framework: FW) -> tuple[Control, ...]:
    return tuple(c for c in CONTROLS if c.framework is framework)
