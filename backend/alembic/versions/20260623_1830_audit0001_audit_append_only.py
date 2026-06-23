"""audit_logs append-only hardening (PostgreSQL trigger)

Enforces the tamper-evident audit trail at the database layer: any UPDATE or
DELETE against ``audit_logs`` raises an exception, so even a compromised
application role (or operator) cannot silently rewrite history. Combined with the
in-row SHA-256 hash chain, this gives defense-in-depth immutability.

No-op on SQLite (tests use the ORM/create_all path), active on PostgreSQL.

Revision ID: audit0001
Revises: f0adfc356446
Create Date: 2026-06-23 18:30:00.000000+00:00
"""
from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "audit0001"
down_revision: str | None = "f0adfc356446"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


_UPGRADE_PG = """
CREATE OR REPLACE FUNCTION sdpp_audit_logs_immutable() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit_logs is append-only; % is not permitted', TG_OP
        USING ERRCODE = 'check_violation';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS audit_logs_no_mutation ON audit_logs;
CREATE TRIGGER audit_logs_no_mutation
    BEFORE UPDATE OR DELETE ON audit_logs
    FOR EACH ROW EXECUTE FUNCTION sdpp_audit_logs_immutable();
"""

_DOWNGRADE_PG = """
DROP TRIGGER IF EXISTS audit_logs_no_mutation ON audit_logs;
DROP FUNCTION IF EXISTS sdpp_audit_logs_immutable();
"""


def upgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute(_UPGRADE_PG)


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute(_DOWNGRADE_PG)
