# SDPP Architecture

## 1. System context

```mermaid
flowchart TB
    subgraph Client
        UI[React + TS + Tailwind + Shadcn SPA]
    end
    subgraph Edge
        NGINX[Nginx — TLS 1.3, HSTS, CSP, rate limit]
    end
    subgraph App
        API[FastAPI app]
        subgraph Services
            AUTH[Auth/AuthZ]
            VAULT[File Vault]
            KMS[Key Mgmt]
            INTEG[Integrity]
            AUDIT[Audit]
            MON[Monitoring]
            COMP[Compliance]
        end
    end
    subgraph Data
        PG[(PostgreSQL — encrypted fields)]
        BLOB[(Encrypted blob storage)]
        HSM[(KMS / HSM master key)]
    end

    UI -->|HTTPS| NGINX -->|reverse proxy| API
    API --> AUTH & VAULT & KMS & INTEG & AUDIT & MON & COMP
    AUTH --> PG
    VAULT --> PG & BLOB
    KMS --> PG & HSM
    AUDIT --> PG
```

## 2. Layered design (clean architecture)

```
core/        pure primitives & policy — NO db/web imports
  ├─ security/   crypto, hashing, passwords, tokens, envelope, field_encryption, audit_chain
  ├─ kms/        master-key provider abstraction (local / aws / azure / vault)
  ├─ authz/      permission catalog + access checks
  ├─ compliance/ control catalog + evaluator
  ├─ config.py   validated settings (fail-fast)
  └─ bootstrap.py startup seeding

db/          declarative base, adaptive types, async session
models/      ORM (depends on core, db)
schemas/     Pydantic API contract
services/    business logic (depends on models, core)  ← transactions, audit
api/         HTTP layer: deps, middleware, errors, routers  ← maps to/from services
main.py      app factory + lifespan
```

**Dependency rule:** `api → services → models → db/core`. Core never imports
upward. This is what let the crypto core be tested in total isolation (100 tests
with zero database).

## 3. Encryption data flow (upload)

```mermaid
sequenceDiagram
    participant C as Client
    participant A as API
    participant V as VaultService
    participant K as KMS
    participant S as Blob store
    participant D as DB

    C->>A: POST /files (multipart, Bearer JWT)
    A->>V: upload(owner, stream)
    V->>K: generate_data_key()  (DEK + wrapped DEK)
    V->>V: AES-256-GCM stream-encrypt (AAD = file id)
    V->>S: write ciphertext blob
    V->>D: store wrapped DEK, metadata, SHA-256(plaintext+ciphertext)
    V->>D: audit(upload) — hash-chained
    A-->>C: 201 {file, encrypted}
```

## 4. Decryption data flow (download)

```mermaid
sequenceDiagram
    participant C as Client
    participant V as VaultService
    participant S as Blob store
    participant K as KMS

    C->>V: GET /files/{id}/download
    V->>S: read ciphertext
    V->>V: verify SHA-256(ciphertext) == recorded  ❗ before decrypt
    alt mismatch
        V->>V: quarantine + critical alert + audit
        V-->>C: 409 integrity_violation
    else ok
        V->>K: unwrap DEK
        V->>V: AES-256-GCM stream-decrypt (AAD = file id)
        V-->>C: 200 stream
    end
```

## 5. Entity-Relationship Diagram

```mermaid
erDiagram
    users ||--o{ user_roles : has
    roles ||--o{ user_roles : grants
    roles ||--o{ role_permissions : has
    permissions ||--o{ role_permissions : in
    users ||--o{ password_history : keeps
    users ||--o{ refresh_tokens : owns
    users ||--o{ files : owns
    files ||--|| encrypted_files : has
    files ||--o{ integrity_checks : verified_by
    encryption_keys ||--o{ encrypted_files : protects
    encryption_keys ||--o{ key_rotations : rotated_by
    users ||--o{ audit_logs : acts
    files ||--o{ security_alerts : triggers
    users ||--o{ compliance_reports : generates

    users {
        uuid id PK
        string username UK
        string email "AES-256-GCM"
        string email_bidx UK "blind index"
        string hashed_password "Argon2id"
        bool is_superuser
        int failed_login_count
        datetime locked_until
    }
    files {
        uuid id PK
        uuid owner_id FK
        string original_filename "encrypted"
        enum category
        enum status
        string plaintext_sha256
    }
    encrypted_files {
        uuid id PK
        uuid file_id FK,UK
        string storage_key
        uuid encryption_key_id FK
        string ciphertext_sha256
    }
    encryption_keys {
        uuid id PK
        enum key_type
        text wrapped_key "DEK wrapped by KEK"
        string master_key_id
        enum status
    }
    audit_logs {
        bigint seq PK
        uuid id UK
        enum event_type
        string prev_hash
        string entry_hash "hash chain"
    }
```

## 6. Request lifecycle

1. **Nginx** terminates TLS 1.3, applies HSTS/CSP/security headers + rate limits.
2. **CORS + SecurityHeaders middleware** in FastAPI (defense in depth).
3. **Dependency injection**: `get_db` → request-scoped async session; bearer →
   `Principal` (decoded JWT with embedded permissions); `require_permission`.
4. **Router** validates the Pydantic request, calls a **service**.
5. **Service** performs crypto/KMS/db work and writes a **hash-chained audit** entry.
6. `get_db` commits on success / rolls back on error (security-state failure paths
   commit explicitly so lockout counters + failed-login audits persist).
7. **Exception handlers** map errors to safe responses (no leakage, no oracles).

## 7. Technology choices

| Layer | Choice | Why |
|-------|--------|-----|
| API | FastAPI + Pydantic v2 | async, typed, OpenAPI, boundary validation |
| ORM | SQLAlchemy 2.0 async | typed models, dialect-adaptive types |
| DB | PostgreSQL | JSONB, native UUID, triggers (audit immutability) |
| Crypto | `cryptography` (AES-GCM), `argon2-cffi` | vetted, AES-NI, memory-hard |
| Tokens | PyJWT | standard JWT with strict claim validation |
| Edge | Nginx | TLS 1.3 termination, headers, rate limiting |
| Tests | pytest + hypothesis + Locust | unit/property/integration/security/load |
