# SDPP Integration Guide

How to plug SDPP into a larger enterprise security system. Audience: the
engineers/architects who own the bigger platform. For the plain-English version
see [`../OVERVIEW.md`](../OVERVIEW.md); for the security design see
[`SECURITY.md`](SECURITY.md) and [`ARCHITECTURE.md`](ARCHITECTURE.md).

---

## 1. Integration model

SDPP is **not** a whole security suite — it is a focused **data-protection
microservice**. The larger system delegates three jobs to it:

1. **Protect** — encrypt files/fields and store them safely.
2. **Prove** — verify integrity and keep a tamper-evident audit trail.
3. **Report** — stream security events to the SOC and produce compliance reports.

Other systems **consume SDPP through its REST API**; SDPP **connects outward** to
the organization's identity, key, storage, and monitoring infrastructure.

```
        ┌──────────────────── Larger security system ────────────────────┐
        │                                                                  │
 [Identity Provider]   [Apps: case mgmt,        [SIEM / SOC]              │
  Okta / Azure AD /     investigation] ──call──► SDPP API                 │
  Active Directory          │                          ▲ audit + alerts   │
        │ SSO (OIDC/SAML)   ▼                          │                  │
        ▼     ╔═══════════ SDPP data-protection service ═══════╪════════╗ │
              ║  API gateway / WAF → SDPP → encrypt·vault·audit │        ║ │
              ╚═════════╤═══════════════╤══════════════╤════════╪════════╝ │
                        ▼               ▼              ▼        ▼          │
                  [KMS / HSM]    [Object storage]  [PostgreSQL] [Grafana] │
                  (master key)    (S3 / Azure)                            │
        └──────────────────────────────────────────────────────────────────┘
```

---

## 2. The integration points ("wires")

### 2.1 Inbound — other systems call the SDPP API  ✅ ready
This is the primary integration. SDPP exposes a versioned REST API under
`/api/v1` with an OpenAPI spec at `/openapi.json` (Swagger UI at `/docs` in
non-production). Other services generate a client from the spec and call it.

Key endpoints for integrators:
| Purpose | Endpoint |
|---------|----------|
| Authenticate | `POST /api/v1/auth/login` → access + refresh tokens |
| Store + encrypt a file | `POST /api/v1/files` (multipart) |
| List files | `GET /api/v1/files` |
| Retrieve + decrypt | `GET /api/v1/files/{id}/download` |
| Verify integrity | `POST /api/v1/files/{id}/verify-integrity` |
| Securely delete | `DELETE /api/v1/files/{id}?secure=true` |
| Read audit trail | `GET /api/v1/audit-logs` |
| Dashboard metrics | `GET /api/v1/security-dashboard` |
| Compliance report | `POST /api/v1/compliance/reports` |

Every protected call carries `Authorization: Bearer <access_token>` and is
gated by RBAC permissions (see [`SECURITY.md`](SECURITY.md)).
Implementation: [`backend/app/api/`](../backend/app/api/).

### 2.2 Identity — Single Sign-On (SSO)  🟡 adapter needed
Today SDPP authenticates locally (username/password → JWT). To join an
enterprise IdP (Okta / Azure AD / Active Directory / Keycloak):

- **Option A (recommended): accept the IdP's OIDC tokens.** Add an OIDC verifier
  that validates the IdP's JWT (issuer, audience, signature via JWKS) and maps
  IdP groups/claims → SDPP roles.
- **Option B: OIDC Authorization-Code login** where SDPP redirects to the IdP.

Where to implement: token handling is isolated in
[`backend/app/core/security/tokens.py`](../backend/app/core/security/tokens.py)
and the request principal is built in
[`backend/app/api/deps.py`](../backend/app/api/deps.py) (`get_current_principal`).
Add an alternate verifier there; the rest of the app already consumes a
`Principal` with permissions, so nothing downstream changes. Map IdP groups to
the existing roles in [`backend/app/core/authz/permissions.py`](../backend/app/core/authz/permissions.py).

### 2.3 Key management — KMS / HSM  ✅ config only
The master key (KEK) is already abstracted behind a provider interface, so you
switch to the org's key service with **configuration, not code**:

```env
KMS_PROVIDER=aws        # or: azure | vault | local(dev only)
AWS_KMS_KEY_ID=arn:aws:kms:...
# or AZURE_KEY_VAULT_URL / AZURE_KEY_NAME
# or VAULT_ADDR / VAULT_TOKEN / VAULT_TRANSIT_KEY
```
Interface: [`backend/app/core/kms/`](../backend/app/core/kms/) (`MasterKeyProvider`,
with `aws` / `azure` / `vault` implementations in `cloud.py`). The optional SDK
(`boto3` / `azure-keyvault-keys` / `hvac`) is installed per provider.

### 2.4 SOC / SIEM — log & alert forwarding  🟢 mostly ready
- **Audit logs & operational logs** are emitted as **structured JSON to stdout**
  with secret redaction ([`backend/app/core/logging.py`](../backend/app/core/logging.py)).
  In containers this is the standard collection path — point your log shipper
  (Fluent Bit / Filebeat / the cloud agent) at stdout to land them in Splunk /
  Elastic / Sentinel / QRadar.
- **The immutable audit trail** also lives in the `audit_logs` table and is
  queryable via `GET /api/v1/audit-logs` (pull model) for SIEMs that prefer it.
- **Security alerts** (integrity violations, brute force, etc.) are persisted and
  surfaced via `GET /api/v1/alerts`. To push them in real time to a SOAR /
  PagerDuty / Slack / webhook, add a notifier in the monitoring service
  ([`backend/app/services/monitoring_service.py`](../backend/app/services/monitoring_service.py)) —
  a small, self-contained adapter.

### 2.5 Storage backend — object storage  🟢 small adapter
Encrypted blobs go through a pluggable interface so you can target enterprise
object storage instead of local disk:

- Interface: `VaultStorage` in
  [`backend/app/services/storage.py`](../backend/app/services/storage.py)
  (methods: `new_key`, `open_write`, `open_read`, `exists`, `delete`, `size`).
- A `LocalFileSystemStorage` ships today; add an `S3Storage` / `AzureBlobStorage`
  implementing the same protocol and wire it in `get_default_storage()`.
  Nothing else in the vault changes.

### 2.6 Database — managed PostgreSQL  ✅ config only
Point at the managed cluster; migrations run automatically on container start.
```env
DATABASE_URL=postgresql+asyncpg://USER:PASS@HOST:5432/sdpp
DATABASE_URL_SYNC=postgresql+psycopg://USER:PASS@HOST:5432/sdpp
```
Grant the app role `INSERT, SELECT` only on `audit_logs` (the migration also
installs a trigger blocking UPDATE/DELETE). See [`DEPLOYMENT.md`](DEPLOYMENT.md).

### 2.7 Observability — metrics  🟡 endpoint to add
`prometheus-client` is bundled. Expose a `/metrics` endpoint (a small add in
[`backend/app/main.py`](../backend/app/main.py)) and scrape it into the org's
Prometheus/Grafana to chart encryption health, alert counts, and request rates.

### 2.8 Network / edge  ✅ ready
SDPP is stateless behind a reverse proxy. Place it behind the org's **API
gateway / WAF**; terminate TLS at the gateway or the bundled Nginx config
([`nginx/`](../nginx/)). It reads `X-Forwarded-For` for client IPs. Ship the
Docker image into the org's Kubernetes/orchestration and CI/CD.

---

## 3. Readiness matrix

| Integration | Effort | Status |
|-------------|--------|--------|
| Consume the REST API | Generate client from OpenAPI | ✅ Ready |
| KMS / HSM master key | Set env vars | ✅ Config only |
| Managed PostgreSQL | Set env vars | ✅ Config only |
| Behind gateway / WAF / K8s | Deploy the container | ✅ Ready |
| SIEM log ingestion | Point log shipper at stdout | 🟢 Mostly ready |
| Real-time alert push (SOAR) | Add a notifier | 🟢 Small adapter |
| Object storage (S3/Azure) | Implement `VaultStorage` | 🟢 Small adapter |
| SSO (OIDC/SAML) | Add an OIDC verifier in `deps.py` | 🟡 Adapter |
| `/metrics` for Prometheus | Add endpoint | 🟡 Small add |

---

## 4. Service-to-service authentication (machine clients)

Other *systems* (not humans) calling SDPP should use a **dedicated service
account** with a least-privilege role (e.g. only `file:upload` + `file:download`).

- **Now:** create a service-account user and have the calling system log in for a
  short-lived access token, refreshing as needed.
- **Recommended for production:** add an **OAuth2 client-credentials** grant (or
  let the API gateway mint/verify tokens) so no password is stored by callers.
  This slots into the same auth extension point as SSO (§2.2).

---

## 5. Worked example — another service stores and retrieves a file

```bash
BASE=https://sdpp.internal/api/v1

# 1) Service account obtains a token
TOKEN=$(curl -s -X POST $BASE/auth/login \
  -H "Content-Type: application/json" \
  -d '{"identifier":"svc-casemgmt","password":"<from-secret-store>"}' \
  | jq -r .access_token)

# 2) Store + encrypt a piece of evidence
FILE_ID=$(curl -s -X POST $BASE/files \
  -H "Authorization: Bearer $TOKEN" \
  -F "upload=@evidence.mp4" -F "category=evidence" \
  | jq -r .file.id)

# 3) Later: integrity-check, then retrieve + decrypt
curl -s -X POST $BASE/files/$FILE_ID/verify-integrity -H "Authorization: Bearer $TOKEN"
curl -s $BASE/files/$FILE_ID/download -H "Authorization: Bearer $TOKEN" -o evidence.mp4
```
The caller never sees a key or ciphertext — it deals only in plaintext + a file
id. SDPP handles encryption, the key envelope, integrity, and audit.

---

## 6. Where to implement each adapter (file map)

| Adapter | File to extend |
|---------|----------------|
| SSO / OIDC verification | `backend/app/api/deps.py`, `backend/app/core/security/tokens.py` |
| Group → role mapping | `backend/app/core/authz/permissions.py` |
| S3 / Azure storage | `backend/app/services/storage.py` |
| Alert push (SOAR/webhook) | `backend/app/services/monitoring_service.py` |
| `/metrics` endpoint | `backend/app/main.py` |
| New KMS provider | `backend/app/core/kms/cloud.py` + `factory.py` |

The codebase is layered (`api → services → models → core`) specifically so each
of these is a contained change with no ripple effects.

---

## 7. Go-live integration checklist

- [ ] SDPP deployed behind the API gateway / WAF; TLS via org certificate.
- [ ] `KMS_PROVIDER` set to a real HSM/cloud KMS; master key access via least-priv IAM.
- [ ] Managed PostgreSQL connected; `audit_logs` grants restricted; backups + PITR on.
- [ ] Object-storage backend configured (S3/Azure) with encryption-at-rest + lifecycle.
- [ ] SSO wired to the org IdP; IdP groups mapped to SDPP roles; service accounts created.
- [ ] Logs shipped to the SIEM; alerts forwarded to the SOC/SOAR.
- [ ] `/metrics` scraped into Prometheus/Grafana; dashboards + alerting set.
- [ ] Production config validated (the app refuses to boot if insecure).
- [ ] Penetration test + (if regulated) crypto/FIPS review completed —
      see [`PRODUCTION_READINESS.md`](PRODUCTION_READINESS.md).

---

### One-line summary
Other systems call SDPP's API to protect and retrieve data; SDPP connects out to
the org's **IdP** (who can act), **KMS/HSM** (the master key), **object storage**
(the encrypted blobs), and **SIEM/SOC** (the security picture) — most via
configuration, with three small adapters (SSO, alert push, S3) for a full join.
