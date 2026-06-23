"""Database schema & encrypted-column integration tests (SQLite).

Validates that:
* the full schema builds (relationships, FKs, types resolve on a real engine),
* sensitive columns are AES-256-GCM encrypted **at rest**,
* blind-index lookup finds rows without decryption,
* UUID/JSON adaptive types round-trip,
* the envelope (File ↔ EncryptedFile ↔ EncryptionKey) wires together.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import StaticPool, create_engine, select, text
from sqlalchemy.orm import Session

from app.core.security.crypto import generate_key
from app.core.security.field_encryption import FieldCipher, set_field_cipher
from app.models import (
    AuditLog,
    Base,
    EncryptedFile,
    EncryptionKey,
    File,
    User,
)
from app.models.enums import AuditEventType, AuditOutcome, FileCategory, FileStatus

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module", autouse=True)
def _field_cipher() -> None:
    # Deterministic field key for the test session.
    set_field_cipher(FieldCipher(generate_key()))


@pytest.fixture
def session() -> Session:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    with Session(engine) as s:
        yield s
    Base.metadata.drop_all(engine)


def _make_user(**over: object) -> User:
    data = {
        "username": "alice",
        "email": "Alice@Example.com",
        "email_bidx": "Alice@Example.com",  # transparently HMAC'd by BlindIndex type
        "full_name": "Alice Analyst",
        "hashed_password": "$argon2id$dummy",
    }
    data.update(over)
    return User(**data)


class TestEncryptedColumns:
    def test_email_is_ciphertext_at_rest(self, session: Session) -> None:
        session.add(_make_user())
        session.commit()

        # Raw bytes in the DB must NOT contain the plaintext.
        raw = session.execute(text("SELECT email FROM users")).scalar_one()
        assert "Alice@Example.com" not in raw
        assert raw  # base64 ciphertext present

        # ORM transparently decrypts.
        user = session.execute(select(User)).scalar_one()
        assert user.email == "Alice@Example.com"
        assert user.full_name == "Alice Analyst"

    def test_blind_index_lookup(self, session: Session) -> None:
        session.add(_make_user())
        session.commit()

        # Find by email via blind index (case-insensitive normalization).
        found = session.execute(
            select(User).where(User.email_bidx == "alice@example.com")
        ).scalar_one()
        assert found.username == "alice"

    def test_blind_index_is_not_plaintext(self, session: Session) -> None:
        session.add(_make_user())
        session.commit()
        bidx = session.execute(text("SELECT email_bidx FROM users")).scalar_one()
        assert "alice" not in bidx.lower()
        assert len(bidx) == 64  # sha256 hex


class TestAdaptiveTypes:
    def test_uuid_roundtrip(self, session: Session) -> None:
        user = _make_user()
        session.add(user)
        session.commit()
        fetched = session.execute(select(User)).scalar_one()
        assert isinstance(fetched.id, uuid.UUID)


class TestEnvelopeWiring:
    def test_file_encrypted_key_relationship(self, session: Session) -> None:
        user = _make_user()
        session.add(user)
        session.flush()

        key = EncryptionKey(
            wrapped_key='{"provider":"local","master_key_id":"abc","algorithm":"AES-256-GCM","ciphertext":"AA=="}',
            provider="local",
            master_key_id="abc",
        )
        session.add(key)
        session.flush()

        f = File(
            owner_id=user.id,
            original_filename="evidence.mp4",
            content_type="video/mp4",
            size_bytes=1024,
            category=FileCategory.evidence,
            status=FileStatus.available,
            plaintext_sha256="a" * 64,
        )
        session.add(f)
        session.flush()

        enc = EncryptedFile(
            file_id=f.id,
            storage_key="vault/obj/123",
            chunk_size=1048576,
            ciphertext_size=2048,
            encryption_key_id=key.id,
            ciphertext_sha256="b" * 64,
        )
        session.add(enc)
        session.commit()

        fetched = session.execute(select(File)).scalar_one()
        assert fetched.original_filename == "evidence.mp4"  # decrypted
        assert fetched.encrypted is not None
        assert fetched.encrypted.encryption_key.master_key_id == "abc"

        # Filename ciphertext at rest.
        raw = session.execute(text("SELECT original_filename FROM files")).scalar_one()
        assert "evidence" not in raw


class TestAuditLog:
    def test_insert_with_autoincrement_seq(self, session: Session) -> None:
        entry = AuditLog(
            id=uuid.uuid4(),
            event_type=AuditEventType.login,
            outcome=AuditOutcome.success,
            actor_label="alice",
            prev_hash="0" * 64,
            entry_hash="f" * 64,
        )
        session.add(entry)
        session.commit()
        fetched = session.execute(select(AuditLog)).scalar_one()
        assert fetched.seq >= 1
        assert fetched.event_type is AuditEventType.login
