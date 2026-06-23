"""Seed one demo user per role so the RBAC model can be explored in the UI.

Run from the backend directory (uses the same .env / database as the server):
    .venv/Scripts/python.exe scripts/seed_demo_users.py
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine  # noqa: E402

from app.core.config import get_settings  # noqa: E402
from app.services.auth_service import AuthService  # noqa: E402
from app.services.exceptions import ConflictError  # noqa: E402
from app.services.key_service import KeyService  # noqa: E402

DEMO_PASSWORD = "Demo-Sdpp-P@ss1!"
DEMO_USERS = [
    ("officer", "officer@sdpp.io", "security_officer"),
    ("analyst", "analyst@sdpp.io", "analyst"),
    ("auditor", "auditor@sdpp.io", "auditor"),
    ("viewer", "viewer@sdpp.io", "viewer"),
]


async def main() -> None:
    settings = get_settings()
    engine = create_async_engine(settings.database_url, connect_args={"timeout": 30})
    maker = async_sessionmaker(engine, expire_on_commit=False)

    async with maker() as session:
        # Load the existing field-encryption key so emails encrypt consistently.
        await KeyService(session).bootstrap_field_cipher()
        auth = AuthService(session, settings=settings)
        for username, email, role in DEMO_USERS:
            try:
                await auth.register(
                    username=username, email=email, password=DEMO_PASSWORD,
                    full_name=f"Demo {role}", role_names=[role],
                )
                print(f"  created {username:10s} -> role {role}")
            except ConflictError:
                print(f"  exists  {username:10s} (skipped)")
        await session.commit()

    await engine.dispose()
    print(f"\nAll demo users share password: {DEMO_PASSWORD}")


if __name__ == "__main__":
    asyncio.run(main())
