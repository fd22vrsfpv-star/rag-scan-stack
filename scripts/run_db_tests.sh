#!/usr/bin/env bash
#
# Run the database-backed tests against the live rag-postgres.
#
# WHY THIS EXISTS
# ---------------
# ~30 tests skip with "no database at postgresql://app:app@localhost:5433/scans"
# and could NEVER have run, for two independent reasons:
#
#   1. rag-postgres publishes no host port at all. docker-compose.yml carries
#      `# ports: ["5432:5432"]  # Disabled external port` — a deliberate choice,
#      and the right one for a database in a pentest stack.
#   2. pg_hba requires scram-sha-256 for anything but loopback-inside-the-
#      container, so the hard-coded `app:app` in those defaults would fail
#      authentication even with a port open.
#
# So the tests skipped cleanly, the suite stayed green, and the dedup triggers
# and artifact queue were never actually exercised anywhere.
#
# This does NOT open a standing port. It starts a throwaway socat forwarder on
# the compose network, bound to 127.0.0.1 only, runs the tests with the real
# DSN, and tears the forwarder down on any exit path. Nothing is recreated, so
# a running engagement is undisturbed.
#
# Usage:
#   scripts/run_db_tests.sh                    # the DB-backed test modules
#   scripts/run_db_tests.sh tests/test_x.py    # or whatever you name
#   PYTEST=/path/to/pytest scripts/run_db_tests.sh
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"

HOST_BIND="${DB_TEST_BIND:-127.0.0.1}"
HOST_PORT="${DB_TEST_PORT:-5433}"
FWD_NAME="rag-db-test-forward-$$"
NETWORK="${DB_TEST_NETWORK:-agents_net}"

# An image already present locally, so this never needs a pull. kali-listener
# ships socat; alpine/socat is the fallback for a checkout without that image.
FWD_IMAGE="${DB_TEST_FWD_IMAGE:-}"
if [[ -z "$FWD_IMAGE" ]]; then
    if docker image inspect rag-scan-stack-public-kali-listener >/dev/null 2>&1; then
        FWD_IMAGE="rag-scan-stack-public-kali-listener"
    else
        FWD_IMAGE="alpine/socat"
    fi
fi

cleanup() { docker rm -f "$FWD_NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT INT TERM

if ! docker inspect rag-postgres >/dev/null 2>&1; then
    echo "rag-postgres is not running — nothing to test against." >&2
    exit 2
fi

# The real password. Reading .env rather than assuming app:app is half the fix.
PGPASS="$(grep -m1 '^POSTGRES_PASSWORD=' .env 2>/dev/null | cut -d= -f2-)"
PGUSER="$(grep -m1 '^POSTGRES_USER=' .env 2>/dev/null | cut -d= -f2-)"
PGDB="$(grep -m1 '^POSTGRES_DB=' .env 2>/dev/null | cut -d= -f2-)"
PGUSER="${PGUSER:-app}"; PGDB="${PGDB:-scans}"
if [[ -z "$PGPASS" ]]; then
    echo "POSTGRES_PASSWORD not found in .env; cannot authenticate." >&2
    exit 2
fi

echo "→ forwarding ${HOST_BIND}:${HOST_PORT} -> rag-postgres:5432 (${FWD_IMAGE})"
docker run -d --rm --name "$FWD_NAME" --network "$NETWORK" \
    -p "${HOST_BIND}:${HOST_PORT}:5432" --entrypoint socat "$FWD_IMAGE" \
    TCP-LISTEN:5432,fork,reuseaddr TCP:rag-postgres:5432 >/dev/null || {
        echo "could not start the forwarder" >&2; exit 2; }

# Wait for the listener rather than sleeping a guessed interval.
for _ in $(seq 1 30); do
    if docker exec "$FWD_NAME" true 2>/dev/null && \
       (exec 3<>"/dev/tcp/${HOST_BIND}/${HOST_PORT}") 2>/dev/null; then
        break
    fi
    sleep 0.3
done

export TEST_DB_DSN="postgresql://${PGUSER}:${PGPASS}@${HOST_BIND}:${HOST_PORT}/${PGDB}"
echo "→ TEST_DB_DSN=postgresql://${PGUSER}:***@${HOST_BIND}:${HOST_PORT}/${PGDB}"

PYTEST="${PYTEST:-pytest}"
if ! command -v "$PYTEST" >/dev/null 2>&1; then
    echo "pytest not found. Set PYTEST=/path/to/pytest (there is no system pytest here)." >&2
    exit 2
fi

TARGETS=("$@")
if [[ ${#TARGETS[@]} -eq 0 ]]; then
    TARGETS=(tests/test_db_dedup_integration.py
             tests/test_raw_artifacts.py
             tests/test_web_scan_parsers.py
             tests/test_phase0_jobs.py)
fi

# Word-split, or PYTEST_ARGS="-q --tb=short" reaches pytest as ONE argument
# and it exits 4 with "unrecognized arguments".
read -r -a EXTRA_ARGS <<< "${PYTEST_ARGS:--q}"
"$PYTEST" "${TARGETS[@]}" -p no:cacheprovider "${EXTRA_ARGS[@]}"
rc=$?
echo "→ exit $rc"
exit $rc
