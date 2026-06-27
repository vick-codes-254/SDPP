"""ORM models.

Importing this package registers every model on ``Base.metadata`` so Alembic's
autogenerate and ``create_all`` see the full schema.
"""

from app.db.base import Base
from app.models.access import AccessEvent, AccessPoint
from app.models.alert import AlertRule
from app.models.alert_delivery import (
    AlertTemplate,
    Notification,
    NotificationChannelConfig,
)
from app.models.asset import Asset, AssetSoftware
from app.models.audit import AuditLog, SecurityAlert
from app.models.automation import AutomationRule
from app.models.billing import Invoice, Payment, Subscription
from app.models.camera import Camera
from app.models.comms import Announcement, ChatMessage
from app.models.compliance import ComplianceReport
from app.models.cyber import CyberEvent, Device, LoginAttempt
from app.models.detection import Detection, Threat
from app.models.emergency import EmergencyContact, EmergencyEvent
from app.models.evidence import CustodyEntry, Evidence
from app.models.file import EncryptedFile, File, IntegrityCheck
from app.models.guard import Guard, Patrol, PatrolScan
from app.models.incident import Incident, IncidentNote
from app.models.key import EncryptionKey, KeyRotation
from app.models.organization import Branch, Department, Organization
from app.models.scan import DiscoveredHost, DiscoveryScan
from app.models.site import Building, Checkpoint, Site, Zone
from app.models.sysadmin import BackupRecord, FeatureFlag, Integration, Setting
from app.models.vehicle import Vehicle, VehicleEvent
from app.models.visitor import Contractor, Visitor
from app.models.vuln import Finding, VulnScan
from app.models.user import (
    Permission,
    Role,
    User,
    PasswordHistory,
    RefreshToken,
    role_permissions,
    user_roles,
)

__all__ = [
    "Base",
    "User",
    "Role",
    "Permission",
    "PasswordHistory",
    "RefreshToken",
    "role_permissions",
    "user_roles",
    "File",
    "EncryptedFile",
    "IntegrityCheck",
    "EncryptionKey",
    "KeyRotation",
    "AuditLog",
    "SecurityAlert",
    "ComplianceReport",
    "Asset",
    "AssetSoftware",
    "DiscoveryScan",
    "DiscoveredHost",
    "VulnScan",
    "Finding",
    "AlertRule",
    "Incident",
    "IncidentNote",
    "Organization",
    "Branch",
    "Department",
    "Site",
    "Building",
    "Zone",
    "Checkpoint",
    "Camera",
    "Guard",
    "Patrol",
    "PatrolScan",
    "Visitor",
    "Contractor",
    "AccessPoint",
    "AccessEvent",
    "Vehicle",
    "VehicleEvent",
    "Detection",
    "Threat",
    "NotificationChannelConfig",
    "AlertTemplate",
    "Notification",
    "EmergencyEvent",
    "EmergencyContact",
    "Evidence",
    "CustodyEntry",
    "LoginAttempt",
    "Device",
    "CyberEvent",
    "Announcement",
    "ChatMessage",
    "AutomationRule",
    "Subscription",
    "Invoice",
    "Payment",
    "FeatureFlag",
    "Setting",
    "BackupRecord",
    "Integration",
]
