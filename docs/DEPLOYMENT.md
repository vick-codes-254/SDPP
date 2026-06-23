# SDPP Deployment Guide

## 1. Prerequisites
- Docker + Docker Compose (or Kubernetes), or Python 3.13 + PostgreSQL 16 for bare-metal.
- A TLS certificate (Let's Encrypt / managed) for production.
- A KMS for the master key in production (AWS KMS / Azure Key Vault / HashiCorp Vault).

## 2. Configuration (secrets)
```bash
cp backend/.env.example backend/.env
# Generate strong secrets:
python -c "import os,base64;print('JWT_SECRET_KEY='+base64.b64encode(os.urandom(48)).decode())"
python -c "import os,base64;print('MASTER_KEY='+base64.b64encode(os.urandom(32)).decode())"
```
Set in `.env`: `APP_ENV=production`, `DEBUG=false`, strong `JWT_SECRET_KEY`,
`KMS_PROVIDER` (aws/azure/vault recommended), DB URLs, CORS origins (no wildcard),
and optionally `BOOTSTRAP_ADMIN_*` for the first administrator.

> The app **refuses to start** in production with DEBUG on, weak/empty JWT secret,
> missing master key, wildcard CORS, or HSTS disabled (fail-fast validation).

## 3. Docker Compose (single-host)
```bash
./scripts/gen-dev-certs.sh          # dev only; use a real cert in prod
docker compose up --build -d
docker compose logs -f backend      # watch migrations + startup bootstrap
```
Services: `db` (PostgreSQL), `backend` (FastAPI, runs Alembic on start), `frontend`
(static SPA), `nginx` (TLS 1.3 edge). Only nginx is exposed (80/443).

## 4. Database migrations
Run automatically by the backend entrypoint (`alembic upgrade head`). Manually:
```bash
cd backend && alembic upgrade head        # apply
cd backend && alembic downgrade -1        # roll back one
```
On PostgreSQL the `audit0001` migration installs the append-only audit trigger.

## 5. Production hardening checklist
See [`PRODUCTION_READINESS.md`](PRODUCTION_READINESS.md). Highlights:
- Use a cloud **KMS/HSM** (not the local provider).
- Grant the app DB role **INSERT/SELECT only** on `audit_logs`.
- Tune Argon2 cost to ~0.5s on target hardware.
- Ship logs to a SIEM; alert on integrity violations & lockouts.
- Scan images (Trivy), run `pip-audit`/`bandit` in CI (already wired).

## 6. Bare-metal (no Docker)
```bash
cd backend
python -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -r requirements.txt
alembic upgrade head
uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 4
# Front this with nginx using nginx/ configs.
```

## 7. Operations
- **Health:** `GET /health` (also the container healthcheck).
- **API docs:** `/docs` and `/redoc` (disabled automatically in production).
- **Metrics:** Prometheus client wired for export (scrape target optional).
- **Key rotation:** `POST /api/v1/keys/{id}/rotate` (master-key re-wrap) or schedule.
- **Audit verification:** `GET /api/v1/audit-logs/verify` walks the hash chain.
- **Backups:** back up PostgreSQL **and** the encrypted blob store; both are
  ciphertext, but restore drills must be tested. Keep the KMS master key recoverable.

## 8. Load & performance validation
```bash
# crypto throughput report
cd backend && python scripts/benchmark.py
# API load test (ramps 100 → 500 → 1000 users)
locust -f backend/tests/load/locustfile.py --host https://localhost --headless
```
