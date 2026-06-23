# SDPP Risk Assessment

Scoring: **Likelihood (L)** × **Impact (I)**, each 1 (low) – 5 (critical). Risk =
L × I. Residual is after the listed controls. See [`THREAT_MODEL.md`](THREAT_MODEL.md).

| # | Risk | L | I | Inherent | Controls | Residual |
|---|------|---|---|----------|----------|----------|
| R1 | Database/backup theft exposes sensitive data | 3 | 5 | 15 | Field-level AES-256-GCM, envelope-wrapped DEKs, KEK not in DB | **4** (L2×I2) |
| R2 | Encrypted file tampered at rest | 2 | 4 | 8 | GCM auth tags, ciphertext SHA-256, verify-before-access, quarantine+alert | **2** |
| R3 | Chunk truncation/reordering of large files | 2 | 4 | 8 | Streaming nonce (counter + last-flag), header-as-AAD | **2** |
| R4 | Credential brute-force / stuffing | 4 | 4 | 16 | Argon2id, lockout, rate limit, alerts, no enumeration | **4** |
| R5 | Token theft / replay | 3 | 4 | 12 | Short access TTL, rotating revocable refresh, iss/aud/jti checks | **4** |
| R6 | Authorization bypass / IDOR | 3 | 5 | 15 | RBAC deny-by-default, server-side checks, UUID ids | **6** (monitor) |
| R7 | Audit log tampering to hide activity | 2 | 5 | 10 | Hash chain + append-only DB trigger + chain verification | **2** |
| R8 | Master key compromise | 1 | 5 | 5 | KMS/HSM, least-priv IAM, rotation via re-wrap, key audit | **5** |
| R9 | Secret leakage (logs, repo, image) | 3 | 5 | 15 | Log redaction, `.gitignore`, detect-secrets, env-only secrets | **4** |
| R10 | Insecure production misconfiguration | 3 | 4 | 12 | Fail-fast startup validation (DEBUG/secret/CORS/HSTS) | **3** |
| R11 | DoS via huge uploads / load | 3 | 3 | 9 | Streaming bounded-memory crypto, size caps, rate limits | **4** |
| R12 | Vulnerable dependency (supply chain) | 3 | 4 | 12 | Pinned deps, `pip-audit` + `bandit` in CI, minimal images | **4** |
| R13 | In-memory DEK not zeroizable (local KMS) | 2 | 3 | 6 | Use cloud KMS in prod; short-lived workers; documented residual | **4** |
| R14 | MITM / TLS downgrade | 2 | 5 | 10 | TLS 1.3, HSTS preload, modern ciphers, cert validation | **2** |

## Top residual risks to watch
- **R6 (Authorization/IDOR):** access is role-gated (shared evidence vault model),
  not per-object ownership. If tenant isolation is required, add owner-scoping or
  a `file:read_all` permission split. Tracked as an enhancement.
- **R8 (Master key):** the single highest-impact asset; mitigated by HSM-resident
  keys in production and strict IAM. Never reduce below "HSM + rotation + audit".
- **R5 (Token replay):** acceptable with short TTL + rotation; consider DPoP /
  token binding for very high-assurance deployments.

## Treatment summary
- **Mitigate:** R1–R5, R7, R9–R12, R14 (controls implemented).
- **Monitor:** R6, R13 (documented residuals + roadmap).
- **Transfer/Accept:** R8 residual accepted with HSM; physical HSM compromise out
  of scope.

## Review cadence
Re-assess quarterly and on any change to authn/authz, crypto, storage backends,
or external integrations.
