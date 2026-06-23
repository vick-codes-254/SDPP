"""RBAC permission catalog & role definition tests."""

from __future__ import annotations

import pytest

from app.core.authz.permissions import (
    DEFAULT_ROLES,
    PERMISSION_CODES,
    PERMISSIONS,
    validate_role_definitions,
)

pytestmark = pytest.mark.unit


def test_permission_codes_unique() -> None:
    codes = [p.code for p in PERMISSIONS]
    assert len(codes) == len(set(codes))


def test_role_definitions_reference_known_permissions() -> None:
    validate_role_definitions()  # raises if any role references an unknown code


def test_super_admin_has_all_permissions() -> None:
    super_admin = next(r for r in DEFAULT_ROLES if r.name == "super_admin")
    assert super_admin.permissions == PERMISSION_CODES


def test_least_privilege_viewer() -> None:
    viewer = next(r for r in DEFAULT_ROLES if r.name == "viewer")
    assert viewer.permissions == {"dashboard:read", "file:read"}
    # viewer must NOT be able to decrypt/delete/manage
    assert "file:download" not in viewer.permissions
    assert "key:rotate" not in viewer.permissions
    assert "user:manage" not in viewer.permissions


def test_auditor_is_read_only() -> None:
    auditor = next(r for r in DEFAULT_ROLES if r.name == "auditor")
    write_like = {"file:upload", "file:delete", "key:rotate", "user:manage", "alert:acknowledge"}
    assert auditor.permissions.isdisjoint(write_like)


def test_role_names_unique() -> None:
    names = [r.name for r in DEFAULT_ROLES]
    assert len(names) == len(set(names))
