#!/usr/bin/env bash
# Generate a self-signed TLS certificate for LOCAL DEVELOPMENT ONLY.
# Production must use a CA-issued certificate (e.g. Let's Encrypt / managed TLS).
set -euo pipefail

CERT_DIR="$(dirname "$0")/../nginx/certs"
mkdir -p "$CERT_DIR"

if [[ -f "$CERT_DIR/server.crt" ]]; then
    echo "Certs already exist at $CERT_DIR — delete them to regenerate."
    exit 0
fi

openssl req -x509 -nodes -newkey rsa:4096 \
    -keyout "$CERT_DIR/server.key" \
    -out "$CERT_DIR/server.crt" \
    -days 365 \
    -subj "/C=US/ST=Dev/L=Dev/O=SDPP/OU=Dev/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

chmod 600 "$CERT_DIR/server.key"
echo "Self-signed dev certificate written to $CERT_DIR (valid 365 days)."
