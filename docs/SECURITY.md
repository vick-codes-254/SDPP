# SDPP Security Design

This document describes the cryptographic and security architecture of the
Secure Data Protection Platform and the rationale behind each decision. It is the
authoritative reference for security reviewers.

> Status legend: ✅ implemented & tested · 🚧 in progress · 📋 planned

---

## 1. Cryptographic primitives

| Concern | Choice | Rationale | Status |
|---------|--------|-----------|--------|
| Bulk/file encryption | **AES-256-GCM** | NIST-approved AEAD; confidentiality + integrity in one pass; hardware-accelerated (AES-NI) | ✅ |
| Large files | **Chunked streaming AEAD** (Tink-style `prefix‖counter‖last` nonce) | bounded memory, per-chunk auth, truncation + reorder resistance | ✅ |
| Key wrapping | **Envelope encryption** (DEK per object, wrapped by KEK) | limits blast radius; cheap master-key rotation; DB breach ≠ plaintext | ✅ |
| Integrity | **SHA-256** | collision-resistant fingerprint, verified before access | ✅ |
| Passwords | **Argon2id** | memory-hard; OWASP-recommended; GPU/ASIC resistant | ✅ |
| Tokens | **JWT (HS256)**, short-lived access + rotating refresh | stateless auth, revocable refresh via `jti` | ✅ |
| Field encryption | **AES-256-GCM** with column-bound AAD + blind index | PII confidential at rest, still searchable by exact match | ✅ |
| Randomness | `os.urandom` (OS CSPRNG) | cryptographically secure entropy for all keys/nonces | ✅ |

All primitives live in [`backend/app/core/security/`](../backend/app/core/security/)
and are covered by 100+ unit & property-based tests (`pytest -m crypto`).

---

## 2. Envelope encryption workflow

```
Upload ─▶ Generate 256-bit DEK ─▶ Encrypt bytes with DEK (AES-256-GCM)
                                        │
                                        ▼
        Wrap DEK with Master Key (KMS) ─▶ store {ciphertext, wrapped DEK, SHA-256, metadata}
```

* **Unique DEK per file/field.** Two objects never share a key.
* **The DEK is never persisted in plaintext** — only its wrapped form.
* **Master key (KEK) never touches the database.** For cloud KMS it never leaves
  the HSM; for the local provider it is supplied via the environment/secret
  manager and held only in process memory.

### Master-key rotation is O(keys), not O(bytes)

Because only the small DEK envelope is encrypted under the master key, rotating
the master key means **re-wrapping DEKs**, not re-encrypting terabytes of data.
See `EnvelopeEncryptor.rewrap_dek` and `LocalMasterKeyProvider(previous_keys=...)`.

---

## 3. Streaming AEAD construction (large files)

On-disk format:

```
┌─────────── header (16 bytes, authenticated as AAD) ───────────┐
│ MAGIC "SDPP" (4) │ version (1) │ chunk_size (4) │ nonce_prefix (7) │
└───────────────────────────────────────────────────────────────┘
│ chunk₀ (ct+tag) │ chunk₁ (ct+tag) │ ... │ chunkₙ (ct+tag, last) │
```

Per-chunk nonce = `nonce_prefix(7) ‖ counter(4, big-endian) ‖ last_flag(1)` = 12 bytes.

* **Nonce uniqueness** — random 56-bit prefix per file + monotonic counter.
* **Reordering protection** — the counter is bound into the nonce; swapping chunks
  fails authentication.
* **Truncation protection** — the final chunk's nonce has `last_flag = 1`, so
  dropping it (or appending more) breaks authentication.
* **Header integrity** — the header is the AAD for every chunk; tampering with the
  declared chunk size / version is detected.

---

## 4. Key management

* Provider abstraction: `local` (symmetric KEK from env), `aws` (AWS KMS),
  `azure` (Key Vault), `vault` (HashiCorp Transit). Same `GenerateDataKey /
  Encrypt / Decrypt` model as AWS KMS, so application code is provider-agnostic.
* Lifecycle (🚧 service layer): generation, rotation, revocation, expiration,
  backup/recovery, and per-key audit. Key metadata lives in `encryption_keys`;
  rotations are recorded in `key_rotations`.
* **No hardcoded secrets.** All keys/secrets come from the environment or a KMS.
  Production configuration is validated at startup (`Settings._enforce_production_
  hardening`) and the process refuses to boot if insecure.

### Known limitation: in-memory key zeroization

CPython `bytes` are immutable and the GC may copy them, so plaintext DEKs cannot
be reliably wiped from memory after use (we `del` references as a best effort).
True zeroization requires keeping the key inside an HSM/KMS (the `aws`/`azure`/
`vault` providers) where SDPP never sees plaintext key material. This is
documented as an accepted residual risk for the `local` provider.

---

## 5. Integrity verification

* On upload, the SHA-256 of the **plaintext** is recorded (single pass during
  encryption) alongside the SHA-256 of the stored **ciphertext**.
* Ciphertext hash detects at-rest tampering/bit-rot **without** needing the key.
* Before every download/decrypt, integrity is re-checked; a mismatch ⇒ block
  access + raise a `critical` security alert + write an audit entry, and the file
  is moved to `quarantined`.

---

## 6. Audit trail immutability

* `audit_logs` is **append-only** and **hash-chained**: each row stores
  `entry_hash = SHA-256(canonical(fields) ‖ prev_hash)`. Altering or deleting any
  historical row breaks the chain, which the verifier (`audit:verify`) detects.
* Defense in depth: the application DB role is granted `INSERT, SELECT` only (no
  `UPDATE`/`DELETE`) on `audit_logs` — enforced in the migration / DB grants.

---

## 7. Transport & application hardening

* **TLS 1.3** terminated at Nginx; HTTP redirected to HTTPS.
* **HSTS** (2-year, preload), strict **CSP**, `X-Content-Type-Options`,
  `X-Frame-Options: DENY`, `Referrer-Policy`, `Permissions-Policy`.
* **Secure, HttpOnly, SameSite** cookies for refresh tokens.
* CORS allow-list (no wildcard in production).
* Request size limits; multipart streamed to disk, never fully buffered.

---

## 8. Threats explicitly addressed

See [`THREAT_MODEL.md`](THREAT_MODEL.md) for the full STRIDE analysis. Highlights:

| Threat | Mitigation |
|--------|------------|
| DB exfiltration | All sensitive fields + files are AES-256-GCM; keys are wrapped, not stored |
| Wrong key / tampered ciphertext | GCM authentication tag → `DecryptionError`, no oracle |
| File tampering at rest | SHA-256 ciphertext hash + GCM tags |
| Truncation / reorder of chunks | nonce counter + last-flag construction |
| Brute-force login | Argon2id + account lockout + alerts |
| Token theft/replay | short access TTL, rotating revocable refresh, `iss`/`aud`/`jti` checks |
| Audit tampering | hash chain + append-only DB grants |
| Secret leakage in logs | structured logging with key redaction |

---

## 9. Reporting a vulnerability

Email `security@sdpp.example` with details and a PoC. Do not open public issues
for security reports. We follow coordinated disclosure.
