#!/bin/bash
# Generate self-signed TLS certificates for inter-service communication
# Run once: ./scripts/generate-certs.sh

set -e

CERT_DIR="$(cd "$(dirname "$0")/.." && pwd)/certs"
mkdir -p "$CERT_DIR"

if [ -f "$CERT_DIR/server.crt" ] && [ -f "$CERT_DIR/server.key" ]; then
    echo "Certificates already exist at $CERT_DIR"
    openssl x509 -in "$CERT_DIR/server.crt" -noout -subject -dates
    echo "To regenerate, delete $CERT_DIR/server.crt and $CERT_DIR/server.key first"
    exit 0
fi

echo "Generating self-signed TLS certificate..."
openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
    -keyout "$CERT_DIR/server.key" \
    -out "$CERT_DIR/server.crt" \
    -subj "/C=US/ST=Security/L=Pentest/O=RagScanStack/CN=*.rag-scan-stack.local" \
    -addext "subjectAltName=DNS:rag-api,DNS:pentest-dashboard,DNS:nmap_scanner,DNS:web-scanner,DNS:nuclei-runner,DNS:pd-runner,DNS:osint-runner,DNS:brutus-runner,DNS:node-manager,DNS:playwright-scanner,DNS:autogen-agents,DNS:scan-recommender,DNS:exploit-runner,DNS:container-logs,DNS:embedder,DNS:kali-listener,DNS:localhost,IP:127.0.0.1"

chmod 644 "$CERT_DIR/server.crt"
# 644 (not 600): several services run as a dedicated non-root user (e.g.
# exploit-runner's "exploitrunner") and mount ./certs read-only. A 600 root-owned
# key is unreadable by those users and uvicorn crashes with PermissionError on
# load_cert_chain. This is an internal, self-signed, per-install cert on an
# isolated docker network — world-readable is acceptable here.
chmod 644 "$CERT_DIR/server.key"

echo "Certificate generated:"
openssl x509 -in "$CERT_DIR/server.crt" -noout -subject -dates -ext subjectAltName
echo ""
echo "Files:"
echo "  $CERT_DIR/server.crt"
echo "  $CERT_DIR/server.key"
