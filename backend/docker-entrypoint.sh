#!/usr/bin/env bash
# Backend container entrypoint: wait for the database, apply migrations, then exec the server.
set -euo pipefail

echo "[entrypoint] Applying database migrations..."
# Retry to tolerate the database still starting up.
for attempt in $(seq 1 30); do
    if alembic upgrade head; then
        echo "[entrypoint] Migrations applied."
        break
    fi
    echo "[entrypoint] Database not ready (attempt ${attempt}/30); retrying in 2s..."
    sleep 2
done

echo "[entrypoint] Starting: $*"
exec "$@"
