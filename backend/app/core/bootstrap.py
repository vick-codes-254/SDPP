"""Idempotent startup bootstrap: field cipher, RBAC seed, initial admin."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.authz.permissions import DEFAULT_ROLES, PERMISSIONS
from app.core.config import Settings
from app.core.logging import get_logger
from app.core.security.field_encryption import is_field_cipher_set
from app.models.user import Permission, Role, User
from app.services.auth_service import AuthService
from app.services.key_service import KeyService

logger = get_logger("bootstrap")


async def bootstrap_field_cipher(db: AsyncSession) -> None:
    if is_field_cipher_set():
        return
    await KeyService(db).bootstrap_field_cipher()
    logger.info("field_cipher_initialized")


async def seed_rbac(db: AsyncSession) -> None:
    """Upsert the permission catalog and default roles (idempotent)."""
    existing_perms = {
        p.code: p for p in (await db.execute(select(Permission))).scalars().all()
    }
    for perm in PERMISSIONS:
        if perm.code not in existing_perms:
            row = Permission(
                code=perm.code, resource=perm.resource,
                action=perm.action, description=perm.description,
            )
            db.add(row)
            existing_perms[perm.code] = row
    await db.flush()

    existing_roles = {
        r.name: r for r in (await db.execute(select(Role))).scalars().all()
    }
    for role_def in DEFAULT_ROLES:
        role = existing_roles.get(role_def.name)
        if role is None:
            role = Role(name=role_def.name, description=role_def.description,
                        is_system=role_def.is_system)
            db.add(role)
        role.permissions = [existing_perms[c] for c in role_def.permissions if c in existing_perms]
    await db.flush()
    logger.info("rbac_seeded", permissions=len(PERMISSIONS), roles=len(DEFAULT_ROLES))


async def seed_admin(db: AsyncSession, settings: Settings) -> None:
    """Create the initial super_admin from env, if configured and absent."""
    if not (
        settings.bootstrap_admin_username
        and settings.bootstrap_admin_email
        and settings.bootstrap_admin_password
    ):
        return
    existing = (
        await db.execute(
            select(User).where(User.username == settings.bootstrap_admin_username)
        )
    ).scalar_one_or_none()
    if existing is not None:
        return
    auth = AuthService(db, settings=settings)
    await auth.register(
        username=settings.bootstrap_admin_username,
        email=settings.bootstrap_admin_email,
        password=settings.bootstrap_admin_password,
        full_name="Bootstrap Administrator",
        role_names=["super_admin"],
        is_superuser=True,
    )
    logger.info("admin_seeded", username=settings.bootstrap_admin_username)


async def seed_alert_rules(db: AsyncSession) -> None:
    from app.services.alert_engine import AlertEngine

    created = await AlertEngine(db).seed_default_rules()
    if created:
        logger.info("alert_rules_seeded", count=created)


async def seed_demo_org(db: AsyncSession) -> None:
    """Create a default tenant and attach the bootstrap admin to it (idempotent)."""
    from app.models.organization import Organization
    from app.models.site import Site

    org = (
        await db.execute(select(Organization).where(Organization.slug == "demo"))
    ).scalar_one_or_none()
    if org is None:
        from app.core.enums import OrgStatus, SubscriptionPlan

        org = Organization(
            name="Demo Security Co.",
            slug="demo",
            status=OrgStatus.active,
            plan=SubscriptionPlan.enterprise,
            country="KE",
            timezone="Africa/Nairobi",
        )
        db.add(org)
        await db.flush()
        db.add(
            Site(
                organization_id=org.id,
                name="HQ Campus",
                code="HQ",
                city="Nairobi",
                country="KE",
                timezone="Africa/Nairobi",
            )
        )
        logger.info("demo_org_seeded", org_id=str(org.id))

    # Attach any org-less users (e.g. the bootstrap admin) to the demo tenant.
    orphan_admins = (
        await db.execute(select(User).where(User.organization_id.is_(None)))
    ).scalars().all()
    for user in orphan_admins:
        user.organization_id = org.id


async def run_startup_bootstrap(db: AsyncSession, settings: Settings) -> None:
    await bootstrap_field_cipher(db)
    await seed_rbac(db)
    await seed_admin(db, settings)
    await seed_alert_rules(db)
    await seed_demo_org(db)
    await db.commit()
