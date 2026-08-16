#!/usr/bin/env bash
# Build certs/ca-bundle.crt = public CA roots + this stack's self-signed cert.
#
# WHY THIS EXISTS
# ---------------
# Every service talks to its peers over HTTPS using certs/server.crt, which is
# self-signed (subject == issuer) with a SAN covering every internal hostname.
# Python's default trust store does not contain it, so any caller that did NOT
# pass verify=False failed with CERTIFICATE_VERIFY_FAILED. The prevailing fix was
# to sprinkle verify=False, which disables verification on a security tool —
# backwards, and it silently spread to ~19 in-stack call sites.
#
# Trusting the cert instead fixes every caller at once AND keeps verification
# real: a MITM inside the docker network is still rejected.
#
# The bundle MERGES the public roots rather than replacing them. Pointing
# SSL_CERT_FILE at server.crt alone would make internal calls work and break every
# EXTERNAL HTTPS call the stack makes — nuclei template downloads, CVE feeds,
# exploit-db syncs — because the public roots would be gone.
#
# Roots are taken from certifi inside a container, not from the host, so the
# result matches what the containers would otherwise have trusted.
set -euo pipefail

cd "$(dirname "$0")/.."
CERT="certs/server.crt"
OUT="certs/ca-bundle.crt"

[[ -f "$CERT" ]] || { echo "ERROR: $CERT not found — run the cert generation step first"; exit 1; }

echo "Extracting public CA roots from certifi..."
TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT
docker run --rm python:3.12-slim sh -c \
  'pip install --quiet certifi >/dev/null 2>&1 && cat "$(python -c "import certifi;print(certifi.where())")"' \
  > "$TMP"

ROOTS=$(grep -c "BEGIN CERTIFICATE" "$TMP" || echo 0)
[[ "$ROOTS" -gt 100 ]] || { echo "ERROR: only $ROOTS roots extracted — refusing to write a truncated bundle"; exit 1; }

{
  cat "$TMP"
  echo ""
  echo "# ---- RagScanStack internal self-signed cert (certs/server.crt) ----"
  cat "$CERT"
} > "$OUT"
chmod 644 "$OUT"

TOTAL=$(grep -c "BEGIN CERTIFICATE" "$OUT")
echo "Wrote $OUT — $ROOTS public roots + 1 internal = $TOTAL certificates"
echo
echo "Services consume it via REQUESTS_CA_BUNDLE / SSL_CERT_FILE=/certs/ca-bundle.crt"
echo "Regenerate after replacing certs/server.crt, or internal TLS will fail closed."
