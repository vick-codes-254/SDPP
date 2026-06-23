"""Permission catalog and default role definitions (RBAC).

Permissions are fine-grained ``resource:action`` codes. Roles are named bundles of
permissions. The seed migration/bootstrap inserts these into the ``permissions``,
``roles``, and ``role_permissions`` tables; the authorization dependency checks a
user's effective permission set (union over their roles) on each request.

Principle of least privilege: every role grants only what it needs.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class Permission:
    code: str
    resource: str
    action: str
    description: str


def _p(resource: str, action: str, description: str) -> Permission:
    return Permission(f"{resource}:{action}", resource, action, description)


# ── Permission catalog ──────────────────────────────────────────
PERMISSIONS: tuple[Permission, ...] = (
    # Files / vault
    _p("file", "upload", "Upload and encrypt files into the vault"),
    _p("file", "download", "Download and decrypt files from the vault"),
    _p("file", "read", "View file metadata"),
    _p("file", "delete", "Securely delete (crypto-shred) files"),
    _p("file", "restore", "Restore previously deleted files"),
    _p("integrity", "verify", "Run integrity verification on files"),
    # Key management
    _p("key", "read", "View key metadata and status"),
    _p("key", "rotate", "Rotate data/master encryption keys"),
    _p("key", "revoke", "Revoke or destroy encryption keys"),
    # Audit & monitoring
    _p("audit", "read", "Read the immutable audit trail"),
    _p("audit", "verify", "Verify audit-log chain integrity"),
    _p("alert", "read", "View security alerts"),
    _p("alert", "acknowledge", "Acknowledge / resolve security alerts"),
    _p("dashboard", "read", "View the security monitoring dashboard"),
    # Compliance & reporting
    _p("report", "read", "View compliance reports"),
    _p("report", "generate", "Generate compliance reports"),
    # Identity & administration
    _p("user", "read", "View users"),
    _p("user", "manage", "Create / update / disable users"),
    _p("role", "manage", "Manage roles and permission assignments"),
    _p("system", "admin", "Full system administration"),
)

PERMISSION_CODES: frozenset[str] = frozenset(p.code for p in PERMISSIONS)


@dataclass(frozen=True, slots=True)
class RoleDefinition:
    name: str
    description: str
    permissions: frozenset[str] = field(default_factory=frozenset)
    is_system: bool = True


_ALL = PERMISSION_CODES


# ── Default roles ───────────────────────────────────────────────
DEFAULT_ROLES: tuple[RoleDefinition, ...] = (
    RoleDefinition(
        name="super_admin",
        description="Unrestricted administrator (break-glass).",
        permissions=_ALL,
    ),
    RoleDefinition(
        name="security_officer",
        description="Manages keys, monitors alerts, runs compliance.",
        permissions=frozenset(
            {
                "key:read", "key:rotate", "key:revoke",
                "audit:read", "audit:verify",
                "alert:read", "alert:acknowledge",
                "dashboard:read",
                "report:read", "report:generate",
                "integrity:verify",
                "file:read",
                "user:read",
            }
        ),
    ),
    RoleDefinition(
        name="analyst",
        description="Day-to-day evidence/file handling.",
        permissions=frozenset(
            {
                "file:upload", "file:download", "file:read",
                "integrity:verify",
                "dashboard:read",
                "alert:read",
            }
        ),
    ),
    RoleDefinition(
        name="auditor",
        description="Read-only oversight of audit trail and compliance.",
        permissions=frozenset(
            {
                "audit:read", "audit:verify",
                "report:read",
                "alert:read",
                "dashboard:read",
                "file:read",
            }
        ),
    ),
    RoleDefinition(
        name="viewer",
        description="Minimal read-only dashboard access.",
        permissions=frozenset({"dashboard:read", "file:read"}),
    ),
)


def validate_role_definitions() -> None:
    """Ensure every role only references codes that exist in the catalog."""
    for role in DEFAULT_ROLES:
        unknown = role.permissions - PERMISSION_CODES
        if unknown:
            raise ValueError(f"Role '{role.name}' references unknown permissions: {unknown}")
