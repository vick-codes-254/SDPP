# SDPP Threat Model

Methodology: **STRIDE** per component, plus a data-flow view and an attacker
model. Risk is rated `Likelihood × Impact` on a 1–5 scale (see
[`RISK_ASSESSMENT.md`](RISK_ASSESSMENT.md) for scored entries).

---

## 1. System assets (what we protect)

| Asset | Sensitivity | Where |
|-------|-------------|-------|
| Plaintext files / evidence | Critical | transient (memory), client |
| Data Encryption Keys (DEKs) | Critical | wrapped in DB; plaintext transient |
| Master Key (KEK) | Critical | KMS/HSM or env (local) |
| User PII (email, name, phone, IPs) | High | encrypted columns |
| Password hashes | High | `users.hashed_password` |
| Audit trail | High (integrity) | `audit_logs` (append-only) |
| Session/refresh tokens | High | client + `refresh_tokens` |

---

## 2. Attacker model / trust boundaries

```
 [ Internet ]───────TLS 1.3───────▶[ Nginx ]──────▶[ FastAPI ]
   untrusted                         DMZ              app trust
                                                       │
                              ┌────────────────────────┼───────────────┐
                              ▼                         ▼               ▼
                        [ PostgreSQL ]          [ File Vault ]     [ KMS/HSM ]
                        data trust              data trust         key trust (highest)
```

Adversaries considered:
1. **Remote unauthenticated attacker** (internet).
2. **Authenticated malicious/low-privilege user** (insider / stolen creds).
3. **Database/storage thief** (stolen DB dump, backup, or disk).
4. **Network MITM** (between client↔server, or service↔service).
5. **Malicious operator** with partial infra access (but *not* the KMS master key).

Out of scope: a fully-compromised host with both the running process memory *and*
the KMS master key (game over for any system); physical HSM compromise.

---

## 3. STRIDE by component

### 3.1 Authentication / Authorization
| Threat (STRIDE) | Vector | Mitigation |
|---|---|---|
| **S**poofing | Credential stuffing, weak passwords | Argon2id, password policy + history, account lockout, generic login errors |
| **T**ampering | JWT `alg:none`, claim forgery | algorithm allow-list, signature + `iss`/`aud`/`exp`/`nbf` validation |
| **R**epudiation | "I didn't do that" | every auth event in hash-chained audit log |
| **E**levation | Authorization bypass, IDOR | RBAC permission checks + per-object ownership checks; UUID (non-enumerable) ids |
| **I**nfo disclosure | Token leakage | short access TTL, HttpOnly/Secure cookies, refresh rotation + revocation |

### 3.2 Encryption / Key management
| Threat | Vector | Mitigation |
|---|---|---|
| **T**ampering | Bit-flip ciphertext, swap/reorder/truncate chunks | AES-GCM tags + streaming nonce (counter + last-flag) + ciphertext SHA-256 |
| **I**nfo disclosure | DB/backup theft | envelope encryption; DEKs wrapped by KEK; KEK not in DB |
| **I**nfo disclosure | Nonce reuse | random nonce (one-shot), unique prefix+counter (stream), unique DEK per object |
| **D**oS | Huge upload OOM | streaming chunked crypto (bounded memory), upload size cap |
| **E**levation | Key misuse across contexts | AAD binds key id / column identity |

### 3.3 File Vault
| Threat | Vector | Mitigation |
|---|---|---|
| **T**ampering | Modify blob on disk | ciphertext SHA-256 + GCM auth, integrity check before access |
| **R**epudiation | Deny upload/download | audit every vault op |
| **I**nfo disclosure | Path traversal, direct blob read | opaque storage keys, blobs are ciphertext, access mediated by API + authz |
| **D**oS | Storage exhaustion | quotas, size limits, monitoring widget |

### 3.4 Audit & Monitoring
| Threat | Vector | Mitigation |
|---|---|---|
| **T**ampering | Edit/delete log rows | hash chain + INSERT/SELECT-only DB grants |
| **R**epudiation | Backdating | server-side timestamps + monotonic `seq` + chain |
| **I**nfo disclosure | Secrets in logs | redaction processor strips sensitive keys |

### 3.5 Transport / Edge
| Threat | Vector | Mitigation |
|---|---|---|
| **S**poofing | MITM, downgrade | TLS 1.3, HSTS preload, cert validation |
| **T**ampering | Response/injection | CSP, security headers, output encoding |
| **I**nfo disclosure | Sniffing | TLS everywhere, secure cookies |

---

## 4. OWASP Top 10 (2021) coverage

| # | Category | Mitigation in SDPP |
|---|----------|--------------------|
| A01 | Broken Access Control | RBAC + ownership checks, deny-by-default, UUID ids |
| A02 | Cryptographic Failures | AES-256-GCM, Argon2id, TLS 1.3, envelope KMS |
| A03 | Injection | SQLAlchemy parameterization, Pydantic validation |
| A04 | Insecure Design | threat model, least privilege, secure defaults |
| A05 | Security Misconfiguration | startup config validation, hardened headers, no debug in prod |
| A06 | Vulnerable Components | `pip-audit` in CI, pinned deps |
| A07 | Auth Failures | lockout, strong hashing, token rotation |
| A08 | Integrity Failures | SHA-256, GCM tags, hash-chained audit, signed CI artifacts |
| A09 | Logging/Monitoring Failures | structured audit + alerts + dashboard |
| A10 | SSRF | allow-list outbound (KMS/Vault only), no user-supplied URLs fetched |

---

## 5. Residual risks (accepted)

| Risk | Why accepted | Compensating control |
|------|--------------|----------------------|
| In-memory key zeroization (local provider) | CPython immutability | use cloud KMS in prod; short-lived process; `del` refs |
| Compromise of running host + KMS access | unsolvable at app layer | infra hardening, least-priv IAM, HSM, alerting |
| Quantum threat to AES/SHA (future) | not current | AES-256/SHA-256 are post-quantum-resilient at 128-bit security |

---

## 6. Review triggers

Re-run this threat model when: adding a new data flow or external integration,
changing the auth/crypto design, adding a new storage backend, or before each
major release.
