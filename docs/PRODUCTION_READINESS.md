# Production Readiness & Security Checklist

Gate for promoting SDPP to production. Each item is `[ ]` until verified in the
target environment. Legend: ✅ implemented in code · 🚧 partial · 📋 ops task.

---

## 1. Secrets & configuration
- [ ] `APP_ENV=production`, `DEBUG=false` (startup validation enforces) ✅
- [ ] `JWT_SECRET_KEY` ≥ 32 bytes, randomly generated, from secret manager ✅
- [ ] `MASTER_KEY` set (local) **or** cloud KMS provider configured ✅
- [ ] No secrets in source, images, or logs (`detect-secrets`, log redaction) ✅
- [ ] `.env` never committed; `.gitignore` covers it ✅
- [ ] CORS origins explicit (no `*`) — enforced for prod ✅

## 2. Cryptography
- [ ] AES-256-GCM for files & fields ✅
- [ ] Unique DEK per object; envelope wrapping verified ✅
- [ ] Nonce uniqueness (random + counter) property-tested ✅
- [ ] SHA-256 integrity recorded and checked before access ✅
- [ ] Argon2id cost params tuned for target hardware (≥ 64 MiB, ~0.5s) 🚧
- [ ] Master-key rotation runbook tested (rewrap DEKs) ✅ code / 📋 drill

## 3. Key management
- [ ] Cloud KMS/HSM used in prod (not local provider) 📋
- [ ] Key rotation schedule configured (`KEY_ROTATION_DAYS`) 🚧
- [ ] Key revocation + crypto-shred path tested 🚧
- [ ] KMS IAM least-privilege; encrypt/decrypt only 📋

## 4. AuthN / AuthZ
- [ ] Argon2id password hashing + policy + history ✅
- [ ] Account lockout + brute-force alerts ✅ (service)
- [ ] RBAC default roles seeded; least privilege ✅
- [ ] Access + refresh token rotation/revocation ✅
- [ ] MFA enabled for privileged roles 🚧

## 5. Transport & headers
- [ ] TLS 1.3 only; HTTP→HTTPS redirect 📋 (nginx)
- [ ] HSTS (preload), CSP, X-Frame-Options, X-Content-Type-Options ✅ (middleware+nginx)
- [ ] Secure, HttpOnly, SameSite cookies ✅
- [ ] Valid certificate (ACME/managed) 📋

## 6. Data protection
- [ ] PII columns encrypted at rest (verified via raw-DB test) ✅
- [ ] Backups encrypted; restore tested 📋
- [ ] DB least-privilege roles; `audit_logs` INSERT/SELECT-only 🚧 (migration)
- [ ] PITR / WAL archiving enabled 📋

## 7. Audit & monitoring
- [ ] Hash-chained audit log + chain verification job ✅ / 🚧
- [ ] Security alerts wired to dashboard + notification channel ✅ / 📋
- [ ] Logs shipped to SIEM; retention policy set 📋
- [ ] Health/readiness endpoints + metrics (Prometheus) 🚧

## 8. Testing & quality gates
- [ ] `pytest` green; coverage ≥ 85% ✅ (core) / 🚧 (full)
- [ ] Crypto property tests (`hypothesis`) ✅
- [ ] Security/attack-simulation tests pass ✅ (suite)
- [ ] Load test (Locust) meets SLOs at 100/500/1000 users 📋
- [ ] `bandit`, `ruff`, `mypy`, `pip-audit` clean in CI 🚧

## 9. Deployment & operations
- [ ] Docker images built, scanned (Trivy), non-root user 🚧
- [ ] `docker compose`/k8s manifests reviewed 🚧
- [ ] DB migrations run via Alembic in release pipeline ✅
- [ ] Rollback plan documented 📋
- [ ] On-call + incident response runbook 📋

## 10. Compliance
- [ ] OWASP ASVS L2 mapping reviewed ✅ (doc)
- [ ] NIST CSF / ISO 27001 control mapping reviewed ✅ (doc)
- [ ] Compliance report generation validated 🚧

---

### Sign-off
| Role | Name | Date |
|------|------|------|
| Security Architect | | |
| Engineering Lead | | |
| DevSecOps | | |
