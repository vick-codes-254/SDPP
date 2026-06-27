"""Asset inventory service.

CRUD + search over assets, software-inventory management, and an upsert path used
by Network Discovery to register/refresh discovered hosts. All mutations are
written to the tamper-evident audit log.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import (
    AssetCriticality,
    AssetStatus,
    AssetType,
    AuditEventType,
    AuditOutcome,
    DiscoverySource,
)
from app.core.security.field_encryption import get_field_cipher
from app.models.asset import Asset, AssetSoftware
from app.services.audit_service import AuditService
from app.services.exceptions import NotFoundError


@dataclass(slots=True)
class SoftwareEntry:
    name: str
    version: str | None = None
    vendor: str | None = None


@dataclass(slots=True)
class AssetData:
    name: str
    asset_type: AssetType = AssetType.host
    hostname: str | None = None
    ip_address: str | None = None
    mac_address: str | None = None
    operating_system: str | None = None
    os_version: str | None = None
    criticality: AssetCriticality = AssetCriticality.medium
    owner: str | None = None
    location: str | None = None
    tags: list[str] = field(default_factory=list)
    notes: str | None = None
    software: list[SoftwareEntry] = field(default_factory=list)


class AssetService:
    def __init__(self, db: AsyncSession, *, audit: AuditService | None = None) -> None:
        self.db = db
        self.audit = audit or AuditService(db)

    @staticmethod
    def _ip_index(ip: str | None) -> str | None:
        return get_field_cipher().blind_index(ip) if ip else None

    # ── Reads ───────────────────────────────────────────────────
    async def get(self, asset_id: uuid.UUID) -> Asset | None:
        return (
            await self.db.execute(select(Asset).where(Asset.id == asset_id))
        ).scalar_one_or_none()

    async def get_or_404(self, asset_id: uuid.UUID) -> Asset:
        asset = await self.get(asset_id)
        if asset is None:
            raise NotFoundError("Asset not found")
        return asset

    async def find_by_ip(self, ip: str) -> Asset | None:
        idx = self._ip_index(ip)
        if idx is None:
            return None
        return (
            await self.db.execute(select(Asset).where(Asset.ip_bidx == idx))
        ).scalar_one_or_none()

    async def list(
        self,
        *,
        asset_type: AssetType | None = None,
        criticality: AssetCriticality | None = None,
        status: AssetStatus | None = None,
        search: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Asset]:
        stmt = select(Asset).order_by(Asset.created_at.desc())
        if asset_type is not None:
            stmt = stmt.where(Asset.asset_type == asset_type)
        if criticality is not None:
            stmt = stmt.where(Asset.criticality == criticality)
        if status is not None:
            stmt = stmt.where(Asset.status == status)
        if search:
            stmt = stmt.where(Asset.name.ilike(f"%{search}%"))
        stmt = stmt.limit(limit).offset(offset)
        return list((await self.db.execute(stmt)).scalars().all())

    # ── Writes ──────────────────────────────────────────────────
    async def create(self, data: AssetData, *, actor_id: uuid.UUID | None = None) -> Asset:
        asset = Asset(
            id=uuid.uuid4(),
            name=data.name,
            asset_type=data.asset_type,
            hostname=data.hostname,
            ip_address=data.ip_address,
            ip_bidx=self._ip_index(data.ip_address),
            mac_address=data.mac_address,
            operating_system=data.operating_system,
            os_version=data.os_version,
            criticality=data.criticality,
            owner=data.owner,
            location=data.location,
            tags=data.tags or [],
            notes=data.notes,
            discovered_by=DiscoverySource.manual,
            software=[
                AssetSoftware(id=uuid.uuid4(), name=s.name, version=s.version, vendor=s.vendor)
                for s in data.software
            ],
        )
        self.db.add(asset)
        await self.db.flush()
        await self.audit.record(
            event_type=AuditEventType.asset_created, outcome=AuditOutcome.success,
            actor_id=actor_id, resource_type="asset", resource_id=str(asset.id),
            action="create", detail={"name": data.name, "type": str(data.asset_type)},
        )
        return asset

    async def update(
        self, asset_id: uuid.UUID, changes: dict[str, Any], *, actor_id: uuid.UUID | None = None
    ) -> Asset:
        asset = await self.get_or_404(asset_id)
        for key, value in changes.items():
            if value is None or not hasattr(asset, key):
                continue
            setattr(asset, key, value)
            if key == "ip_address":
                asset.ip_bidx = self._ip_index(value)
        await self.db.flush()
        await self.audit.record(
            event_type=AuditEventType.asset_updated, outcome=AuditOutcome.success,
            actor_id=actor_id, resource_type="asset", resource_id=str(asset.id),
            action="update", detail={"fields": sorted(changes.keys())},
        )
        return asset

    async def set_software(
        self, asset_id: uuid.UUID, software: list[SoftwareEntry]
    ) -> Asset:
        asset = await self.get_or_404(asset_id)
        asset.software = [
            AssetSoftware(id=uuid.uuid4(), name=s.name, version=s.version, vendor=s.vendor)
            for s in software
        ]
        await self.db.flush()
        return asset

    async def delete(self, asset_id: uuid.UUID, *, actor_id: uuid.UUID | None = None) -> None:
        asset = await self.get_or_404(asset_id)
        await self.db.delete(asset)
        await self.audit.record(
            event_type=AuditEventType.asset_deleted, outcome=AuditOutcome.success,
            actor_id=actor_id, resource_type="asset", resource_id=str(asset_id), action="delete",
        )
        await self.db.flush()

    async def upsert_from_discovery(
        self,
        *,
        ip_address: str,
        hostname: str | None = None,
        open_ports: list[int] | None = None,
        asset_type: AssetType = AssetType.host,
    ) -> tuple[Asset, bool]:
        """Create or refresh an asset found by Network Discovery.

        Returns ``(asset, created)``. Matching is by IP blind index.
        """
        existing = await self.find_by_ip(ip_address)
        now = datetime.now(UTC)
        if existing is not None:
            existing.last_seen_at = now
            if hostname and not existing.hostname:
                existing.hostname = hostname
            if open_ports is not None:
                tags = set(existing.tags or [])
                tags.update(f"port:{p}" for p in open_ports)
                existing.tags = sorted(tags)
            await self.db.flush()
            return existing, False

        asset = Asset(
            id=uuid.uuid4(),
            name=hostname or ip_address,
            asset_type=asset_type,
            hostname=hostname,
            ip_address=ip_address,
            ip_bidx=self._ip_index(ip_address),
            discovered_by=DiscoverySource.network_discovery,
            last_seen_at=now,
            tags=sorted(f"port:{p}" for p in (open_ports or [])),
        )
        self.db.add(asset)
        await self.db.flush()
        await self.audit.record(
            event_type=AuditEventType.asset_created, outcome=AuditOutcome.success,
            resource_type="asset", resource_id=str(asset.id), action="discovered",
            detail={"ip": "<redacted>", "source": "network_discovery"},
        )
        return asset, True
