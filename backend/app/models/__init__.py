"""ORM models.

Importing this package registers every model on ``Base.metadata`` so Alembic's
autogenerate and ``create_all`` see the full schema.
"""

from app.db.base import Base
from app.models.audit import AuditLog, SecurityAlert
from app.models.compliance import ComplianceReport
from app.models.file import EncryptedFile, File, IntegrityCheck
from app.models.key import EncryptionKey, KeyRotation
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
]
