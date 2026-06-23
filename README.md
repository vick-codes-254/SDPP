# 🔐 SDPP — Secure Data Protection Platform

> Enterprise-grade platform for protecting sensitive data, files, and digital
> evidence through authenticated encryption, envelope key management, integrity
> verification, immutable auditing, and compliance reporting.

[![Security](https://img.shields.io/badge/crypto-AES--256--GCM-blue)]()
[![Passwords](https://img.shields.io/badge/passwords-Argon2id-blue)]()
[![Transport](https://img.shields.io/badge/TLS-1.3-green)]()
[![Tests](https://img.shields.io/badge/tests-pytest%20%2B%20hypothesis-orange)]()

SDPP is **not a CRUD app**. It is a security product whose primary job is to keep
data confidential, tamper-evident, and auditable — at rest, in transit, and in use.

---

## ✨ Capabilities

| # | Capability | How |
|---|------------|-----|
| 1 | Encrypt data at rest | AES-256-GCM + envelope encryption (unique DEK per file) |
| 2 | Protect data in transit | TLS 1.3, HSTS, secure cookies, strict CSP |
| 3 | Encrypt uploaded files | Streaming chunked AEAD (bounded memory, multi-GB capable) |
| 4 | Verify file integrity | SHA-256 fingerprint, checked before every access |
| 5 | Manage encryption keys | KMS abstraction (local / AWS KMS / Azure KV / Vault), rotation, revocation |
| 6 | Maintain audit trails | Append-only, hash-chained, tamper-evident audit log |
| 7 | Detect tampering | GCM auth tags + SHA-256 + truncation/reorder protection |
| 8 | Enterprise controls | RBAC, password policy, account lockout, MFA-ready |
| 9 | Compliance reports | OWASP ASVS, NIST CSF, NIST crypto, ISO 27001 mapping |
| 10 | Security testing | Unit, integration, security, crypto, performance, load, pentest |

---

## 🏗️ Architecture (high level)

```
            ┌──────────────────────────────────────────────────────┐
   Browser  │  React + TypeScript + Tailwind + Shadcn (Dashboard)  │
   (TLS 1.3)└───────────────────────────┬──────────────────────────┘
                                         │ HTTPS
                          ┌──────────────▼──────────────┐
                          │   Nginx  (TLS 1.3, HSTS,     │
                          │   CSP, security headers)     │
                          └──────────────┬──────────────┘
                                         │ reverse proxy
                          ┌──────────────▼──────────────┐
                          │      FastAPI application      │
                          │  ┌────────────────────────┐  │
                          │  │ AuthN / AuthZ (JWT+RBAC)│  │
                          │  ├────────────────────────┤  │
                          │  │ Encryption / Decryption │  │
                          │  │ Integrity / Vault       │  │
                          │  │ Key Management (KMS)     │  │
                          │  │ Audit / Monitoring       │  │
                          │  │ Reporting / Compliance   │  │
                          │  └────────────────────────┘  │
                          └───┬───────────────┬──────────┘
                              │               │
                  ┌───────────▼───┐   ┌───────▼────────┐   ┌──────────────┐
                  │  PostgreSQL    │   │ Encrypted file │   │   KMS / HSM  │
                  │ (encrypted     │   │ vault (blobs)  │   │ master key   │
                  │  fields + meta)│   │                │   │ (KEK)        │
                  └────────────────┘   └────────────────┘   └──────────────┘
```

Full diagrams, threat model, and data-flow live in [`docs/`](docs/).

---

## 📂 Repository layout

```
SDPP/
├── backend/                # FastAPI application
│   ├── app/
│   │   ├── core/
│   │   │   ├── config.py            # validated, fail-fast settings
│   │   │   ├── security/            # crypto primitives (pure, tested)
│   │   │   │   ├── crypto.py        # AES-256-GCM (one-shot + streaming)
│   │   │   │   ├── hashing.py       # SHA-256 integrity, HMAC
│   │   │   │   ├── passwords.py     # Argon2id + password policy
│   │   │   │   ├── tokens.py        # JWT issue/verify
│   │   │   │   ├── envelope.py      # envelope encryption workflow
│   │   │   │   └── field_encryption.py  # transparent DB column crypto
│   │   │   └── kms/                 # master-key provider abstraction
│   │   ├── models/         # SQLAlchemy ORM
│   │   ├── schemas/        # Pydantic request/response
│   │   ├── services/       # business logic (encryption, vault, audit, …)
│   │   ├── api/            # REST routers + dependencies
│   │   └── main.py         # ASGI app factory
│   ├── tests/             # unit / integration / security / crypto / perf
│   ├── alembic/           # database migrations
│   └── requirements*.txt
├── frontend/               # React + TS + Tailwind + Shadcn
├── nginx/                  # TLS 1.3 / security-header config
├── docker/                 # Dockerfiles
├── docs/                   # architecture, threat model, compliance, checklists
├── .github/workflows/      # CI/CD (lint, SAST, tests, dep-audit)
└── docker-compose.yml
```

---

## 🚀 Quickstart (development)

```bash
# 1. Backend dependencies
cd backend
python -m venv .venv && .venv/Scripts/activate     # (Windows)  or  source .venv/bin/activate
pip install -r requirements-dev.txt

# 2. Configuration (NEVER commit the real .env)
cp .env.example .env
python -c "import os,base64;print('MASTER_KEY=',base64.b64encode(os.urandom(32)).decode())"
python -c "import os,base64;print('JWT_SECRET_KEY=',base64.b64encode(os.urandom(48)).decode())"
#   ...paste those into .env

# 3. Run the test suite
pytest -m crypto            # cryptographic correctness
pytest                      # everything, with coverage

# 4. Run the API
uvicorn app.main:app --reload
```

Or the full stack with one command:

```bash
docker compose up --build      # api + postgres + nginx (TLS) + frontend
```

---

## 🔑 Core security design

* **Envelope encryption** — every file/field gets a unique 256-bit Data
  Encryption Key (DEK). The DEK is wrapped by a Master Key held in a KMS/HSM and
  is *never* stored in plaintext. A DB breach alone exposes nothing.
* **Streaming AEAD** — large files are encrypted chunk-by-chunk with a
  Tink-style `prefix‖counter‖last-flag` nonce construction, giving bounded
  memory plus protection against truncation and chunk reordering.
* **Integrity everywhere** — SHA-256 on upload, re-verified before every access;
  mismatch ⇒ block + alert + audit.
* **Argon2id** for passwords; **TLS 1.3** for transport; **JWT** for stateless
  auth with rotation + revocation.
* **No hardcoded secrets** — everything via environment/KMS; production config is
  validated at startup and refuses to boot if insecure.

See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) and
[`docs/SECURITY.md`](docs/SECURITY.md).

---

## 📚 Documentation

| Doc | Contents |
|-----|----------|
| [ARCHITECTURE](docs/ARCHITECTURE.md) | System & layer diagrams, ERD, data flows, request lifecycle |
| [SECURITY](docs/SECURITY.md) | Cryptographic design & rationale |
| [THREAT_MODEL](docs/THREAT_MODEL.md) | STRIDE analysis, OWASP Top 10 coverage, residual risks |
| [RISK_ASSESSMENT](docs/RISK_ASSESSMENT.md) | Scored risk register & treatment |
| [COMPLIANCE](docs/COMPLIANCE.md) | OWASP ASVS / NIST / ISO 27001 control mapping |
| [PENTEST](docs/PENTEST.md) | OWASP Top 10 test procedures & remediation |
| [DEPLOYMENT](docs/DEPLOYMENT.md) | Deployment guide (Docker / bare-metal / ops) |
| [PRODUCTION_READINESS](docs/PRODUCTION_READINESS.md) | Go-live security checklist |

API reference is auto-generated (OpenAPI) at `/docs` and `/redoc` (non-production).

---

## 📜 License

Proprietary — © SDPP. All rights reserved.
