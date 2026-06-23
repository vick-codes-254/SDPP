"""Compliance control catalog tests."""

from __future__ import annotations

import pytest

from app.core.compliance.controls import CONTROLS, controls_for_framework
from app.models.enums import ComplianceFramework

pytestmark = pytest.mark.unit


def test_control_ids_unique() -> None:
    ids = [c.id for c in CONTROLS]
    assert len(ids) == len(set(ids))


def test_every_framework_has_controls() -> None:
    for fw in ComplianceFramework:
        assert controls_for_framework(fw), f"no controls for {fw}"


def test_controls_reference_valid_severity() -> None:
    valid = {"informational", "low", "medium", "high", "critical"}
    assert all(c.severity in valid for c in CONTROLS)


def test_check_keys_are_known() -> None:
    # Keep the catalog's check keys in sync with the evaluator's registry.
    known = {
        "aes_256_gcm", "unique_dek_per_object", "envelope_encryption",
        "sha256_integrity", "argon2id_passwords", "password_policy", "tls_1_3",
        "security_headers", "secure_cookies", "rbac_enabled", "least_privilege",
        "jwt_rotation", "audit_immutable", "audit_chain", "log_redaction",
        "kms_provider", "key_rotation", "no_hardcoded_secrets", "prod_hardening",
        "input_validation", "dependency_audit", "account_lockout",
    }
    used = {c.check for c in CONTROLS}
    assert used <= known, f"unknown check keys: {used - known}"
