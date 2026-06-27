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
    # ── Security Monitoring Platform ────────────────────────────
    _p("asset", "read", "View asset inventory"),
    _p("asset", "manage", "Create / update / delete assets"),
    _p("discovery", "read", "View network discovery scans"),
    _p("discovery", "run", "Run network discovery scans"),
    _p("vuln", "read", "View vulnerability findings"),
    _p("vuln", "scan", "Run vulnerability scans"),
    _p("vuln", "manage", "Triage / update vulnerability findings"),
    _p("incident", "read", "View incidents"),
    _p("incident", "manage", "Create / triage / resolve incidents"),
    _p("alert", "manage", "Manage alert rules"),
    # ── Unified Security Platform — tenancy & estate ─────────────
    _p("org", "read", "View organizations, branches, departments"),
    _p("org", "manage", "Create / update / delete organizations & structure"),
    _p("site", "read", "View sites, buildings, zones, checkpoints"),
    _p("site", "manage", "Create / update / delete sites, zones, checkpoints"),
    # ── Physical security ────────────────────────────────────────
    _p("camera", "read", "View cameras and live monitoring"),
    _p("camera", "manage", "Register / configure / control cameras"),
    _p("guard", "read", "View guards and patrols"),
    _p("guard", "manage", "Manage guards, shifts, and patrols"),
    _p("visitor", "read", "View visitors and contractors"),
    _p("visitor", "manage", "Register / approve / check in-out visitors & contractors"),
    _p("access", "read", "View access points and access events"),
    _p("access", "manage", "Manage access points and log access decisions"),
    _p("vehicle", "read", "View vehicles and ANPR events"),
    _p("vehicle", "manage", "Manage vehicles, watchlists, and record ANPR"),
    # ── AI detection & threat intelligence ──────────────────────
    _p("detection", "read", "View AI detections"),
    _p("detection", "manage", "Ingest and triage AI detections"),
    _p("threat", "read", "View the threat intelligence center"),
    _p("threat", "manage", "Triage, correlate, and escalate threats"),
    # ── SecOps: notifications, emergency, evidence ──────────────
    _p("notify", "read", "View notification channels and delivery history"),
    _p("notify", "manage", "Configure channels/templates and send notifications"),
    _p("emergency", "read", "View emergency events and contacts"),
    _p("emergency", "respond", "Trigger / acknowledge / resolve emergencies"),
    _p("evidence", "read", "View evidence and chain of custody"),
    _p("evidence", "manage", "Register evidence and log custody actions"),
    # ── Cybersecurity monitoring & SOC ──────────────────────────
    _p("cyber", "read", "View cyber events, login attempts, devices, SOC queue"),
    _p("cyber", "manage", "Ingest auth events and triage cyber events"),
    # ── Analytics, communication, workflow ──────────────────────
    _p("analytics", "read", "View analytics, KPIs, maps, and reports"),
    _p("comms", "read", "Read announcements and chat rooms"),
    _p("comms", "manage", "Publish announcements"),
    _p("workflow", "read", "View automation rules"),
    _p("workflow", "manage", "Create / edit / run automation rules"),
    # ── SaaS: billing ───────────────────────────────────────────
    _p("billing", "read", "View subscription, invoices, payments, usage"),
    _p("billing", "manage", "Manage subscription, issue invoices, record payments"),
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
        description="Manages keys, monitors alerts, runs scans and compliance.",
        permissions=frozenset(
            {
                "key:read", "key:rotate", "key:revoke",
                "audit:read", "audit:verify",
                "alert:read", "alert:acknowledge", "alert:manage",
                "dashboard:read",
                "report:read", "report:generate",
                "integrity:verify",
                "file:read",
                "user:read",
                "asset:read", "asset:manage",
                "discovery:read", "discovery:run",
                "vuln:read", "vuln:scan", "vuln:manage",
                "incident:read", "incident:manage",
                "org:read", "site:read", "site:manage",
                "camera:read", "camera:manage",
                "guard:read", "guard:manage",
                "visitor:read", "visitor:manage",
                "access:read", "access:manage",
                "vehicle:read", "vehicle:manage",
                "detection:read", "detection:manage",
                "threat:read", "threat:manage",
                "notify:read", "notify:manage",
                "emergency:read", "emergency:respond",
                "evidence:read", "evidence:manage",
                "cyber:read", "cyber:manage",
                "analytics:read",
                "comms:read", "comms:manage",
                "workflow:read", "workflow:manage",
                "billing:read",
            }
        ),
    ),
    RoleDefinition(
        name="analyst",
        description="Day-to-day evidence handling, triage, and investigation.",
        permissions=frozenset(
            {
                "file:upload", "file:download", "file:read",
                "integrity:verify",
                "dashboard:read",
                "alert:read",
                "asset:read",
                "discovery:read",
                "vuln:read",
                "incident:read", "incident:manage",
                "site:read",
                "camera:read",
                "guard:read",
                "visitor:read", "visitor:manage",
                "access:read",
                "vehicle:read",
                "detection:read", "detection:manage",
                "threat:read", "threat:manage",
                "emergency:read", "emergency:respond",
                "evidence:read", "evidence:manage",
                "cyber:read", "cyber:manage",
                "analytics:read",
                "comms:read", "comms:manage",
                "workflow:read",
            }
        ),
    ),
    RoleDefinition(
        name="auditor",
        description="Read-only oversight of audit trail, posture, and compliance.",
        permissions=frozenset(
            {
                "audit:read", "audit:verify",
                "report:read",
                "alert:read",
                "dashboard:read",
                "file:read",
                "asset:read",
                "vuln:read",
                "incident:read",
                "org:read", "site:read",
                "camera:read", "guard:read", "visitor:read",
                "access:read", "vehicle:read",
                "detection:read", "threat:read",
                "notify:read", "emergency:read", "evidence:read",
                "cyber:read",
                "analytics:read", "comms:read",
            }
        ),
    ),
    RoleDefinition(
        name="viewer",
        description="Minimal read-only dashboard access.",
        permissions=frozenset({"dashboard:read", "file:read", "asset:read"}),
    ),
)


def validate_role_definitions() -> None:
    """Ensure every role only references codes that exist in the catalog."""
    for role in DEFAULT_ROLES:
        unknown = role.permissions - PERMISSION_CODES
        if unknown:
            raise ValueError(f"Role '{role.name}' references unknown permissions: {unknown}")
