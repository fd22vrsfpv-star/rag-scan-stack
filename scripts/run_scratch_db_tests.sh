#!/usr/bin/env bash
#
# Run the suite against a THROWAWAY Postgres on the compose network.
#
# WHY THIS EXISTS
# ---------------
# 438 tests skipped in the default offline run. The largest block — 13 modules,
# ~91 skips — reached the database with `docker exec rag-postgres psql`. Under
# `db_mode=remote_direct` there IS no rag-postgres container: the name is only a
# network alias the DB tunnel publishes. Those modules could therefore never run
# in this deployment, whatever was configured, and the Python/SQL dedup-trigger
# agreement CLAUDE.md calls load-bearing was being verified nowhere.
#
# They now resolve the database through `tests/conftest.py::psql_argv`, which
# prefers TEST_DB_DSN and falls back to the container. This script supplies that
# DSN.
#
# WHY A SCRATCH DATABASE AND NOT THE LIVE ONE
# -------------------------------------------
# scripts/run_db_tests.sh forwards to the LIVE rag-postgres. That is fine for the
# four modules it names, but pointing the WHOLE suite at production is not: test
# pollution of live tables has already been observed in this repo (rules
# persisted under `__pytest_phase`, an uncaptured pending_exploits row). A
# disposable database costs one container and removes the question.
#
# The schema comes from db_init/ensure_all_tables.sql — the same DDL the
# installer applies — so a column this suite needs and the installer does not
# create fails HERE rather than in production.
#
# WHAT IT DOES NOT COVER
# ----------------------
# Two other skip tiers are out of reach and stay skipped, by design:
#   * service tier  — tests that call rag-api/BFF over HTTP. Reachable on
#                     agents_net, but the live stack answers slowly enough that
#                     a full run does not complete in a useful time.
#   * docker-exec tier — tests that run python INSIDE a service container. They
#                     need the docker socket, which this deliberately does not
#                     mount.
#
# Usage:
#   scripts/run_scratch_db_tests.sh                 # whole suite
#   scripts/run_scratch_db_tests.sh tests/test_fingerprint.py
#   KEEP_DB=1 scripts/run_scratch_db_tests.sh       # leave the DB up to inspect
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"

NETWORK="${DB_TEST_NETWORK:-agents_net}"
DB_NAME="${SCRATCH_DB_NAME:-test-postgres-$$}"
DB_IMAGE="${SCRATCH_DB_IMAGE:-pgvector/pgvector:pg16}"
DB_USER=app
DB_PASS=test
DB_DB=scans
SCHEMA="db_init/ensure_all_tables.sql"

cleanup() {
    if [[ -n "${KEEP_DB:-}" ]]; then
        echo "→ KEEP_DB set; leaving $DB_NAME running"
        return
    fi
    docker rm -f "$DB_NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

if ! docker network inspect "$NETWORK" >/dev/null 2>&1; then
    echo "network '$NETWORK' does not exist — is the stack up?" >&2
    exit 2
fi
[[ -f "$SCHEMA" ]] || { echo "$SCHEMA not found" >&2; exit 2; }

echo "→ starting scratch database $DB_NAME ($DB_IMAGE)"
docker run -d --rm --name "$DB_NAME" --network "$NETWORK" \
    -e POSTGRES_USER="$DB_USER" -e POSTGRES_PASSWORD="$DB_PASS" \
    -e POSTGRES_DB="$DB_DB" "$DB_IMAGE" >/dev/null || {
        echo "could not start the scratch database" >&2; exit 2; }

# Wait for readiness rather than sleeping a guessed interval.
ready=""
for _ in $(seq 1 60); do
    if docker exec "$DB_NAME" pg_isready -U "$DB_USER" -d "$DB_DB" >/dev/null 2>&1; then
        ready=1; break
    fi
    sleep 1
done
[[ -n "$ready" ]] || { echo "scratch database never became ready" >&2; exit 2; }

echo "→ applying $SCHEMA"
if ! docker exec -i "$DB_NAME" psql -U "$DB_USER" -d "$DB_DB" -v ON_ERROR_STOP=1 \
        -q < "$SCHEMA" > /tmp/scratch-schema.$$.log 2>&1; then
    echo "schema failed to apply — see /tmp/scratch-schema.$$.log" >&2
    tail -20 "/tmp/scratch-schema.$$.log" >&2
    exit 2
fi
rm -f "/tmp/scratch-schema.$$.log"
tables=$(docker exec "$DB_NAME" psql -U "$DB_USER" -d "$DB_DB" -tAc \
    "SELECT count(*) FROM information_schema.tables WHERE table_schema='public' AND table_type='BASE TABLE'")
echo "→ schema applied: $tables tables"

DSN="postgresql://${DB_USER}:${DB_PASS}@${DB_NAME}:5432/${DB_DB}"
TARGETS=("$@"); [[ ${#TARGETS[@]} -eq 0 ]] && TARGETS=(tests/)
read -r -a EXTRA_ARGS <<< "${PYTEST_ARGS:--q}"

echo "→ running ${TARGETS[*]}"
# DB_DSN/DATABASE_URL as well as TEST_DB_DSN: several modules predate the
# TEST_ prefix and read the plain names (tests/test_scope_conflicts.py,
# tests/test_credential_followups.py). Pointing all three at the SCRATCH database
# is safe precisely because it is disposable.
#
# postgresql-client is installed in the test container because psql_argv shells
# out to the psql CLI on BOTH paths, so stdout stays byte-identical to the
# container path each module's output parsing was written against.
docker run --rm --network "$NETWORK" \
    -e TEST_DB_DSN="$DSN" \
    -e DB_DSN="$DSN" -e DATABASE_URL="$DSN" \
    -v "$REPO":/repo -w /repo python:3.12-slim \
    sh -c "apt-get update -qq >/dev/null 2>&1 \
        && apt-get install -y -qq postgresql-client >/dev/null 2>&1 \
        && pip install -q -r tests/requirements.txt >/dev/null 2>&1 \
        && python -m pytest ${TARGETS[*]} -p no:cacheprovider ${EXTRA_ARGS[*]}"
rc=$?
echo "→ exit $rc"
exit $rc
