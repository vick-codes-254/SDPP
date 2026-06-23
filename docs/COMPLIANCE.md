# SDPP Compliance Mapping

SDPP maps its technical controls to four frameworks. The **authoritative,
machine-readable** mapping lives in
[`backend/app/core/compliance/controls.py`](../backend/app/core/compliance/controls.py)
and is evaluated against the live configuration by
[`evaluator.py`](../backend/app/core/compliance/evaluator.py). Scored reports are
generated on demand:

```
POST /api/v1/compliance/reports   {"framework": "owasp_asvs"}
GET  /api/v1/compliance/reports
```

## Frameworks covered
| Framework | Scope in SDPP |
|-----------|---------------|
| **OWASP ASVS v4** | App-level verification: auth, session, access control, crypto, headers, validation |
| **NIST CSF 2.0** | Function-level: Protect (PR.DS/PR.AC/PR.PS), Detect (DE.CM) |
| **NIST Crypto** | SP 800-38D (AES-GCM), SP 800-57 (key mgmt), SP 800-63B (Argon2id), FIPS 180-4 (SHA-256) |
| **ISO/IEC 27001:2022** | Annex A: A.5.15, A.8.24, A.8.5, A.5.17, A.8.15/16, A.8.12, A.8.10, A.8.28, A.8.9 |

## Representative control → implementation
| Control theme | SDPP implementation |
|---------------|---------------------|
| Approved cryptography (AEAD) | AES-256-GCM (`core/security/crypto.py`) |
| Unique keys / nonces | DEK per object + random/counter nonces |
| Key management | Envelope encryption + KMS abstraction + rotation/revocation |
| Memory-hard password storage | Argon2id (`core/security/passwords.py`) |
| Data in transit | TLS 1.3 + HSTS (`nginx/`) |
| Access control | RBAC, deny-by-default (`core/authz/`) |
| Tamper-evident logging | Hash-chained audit + PG append-only trigger |
| Integrity | SHA-256 recorded + verified before access |
| Secure config | Fail-fast production validation (`core/config.py`) |
| Secure SDLC | ruff/mypy/bandit/pip-audit in CI |

## How scoring works
Each control references an evaluable `check` key. The evaluator returns
`(passed, evidence)` per control from the current settings + implemented controls,
then `score = 100 × passed / total`. A default, hardened development configuration
scores ≥ 90% on every framework (see the compliance tests).

> Note: these reports demonstrate **implemented technical controls**. Formal
> certification (ISO 27001, SOC 2) additionally requires organizational evidence
> (policies, audits, training) that lives outside the platform.
