#!/usr/bin/env bash
set -euo pipefail
DB_USER="${POSTGRES_USER:-app}"
DB_NAME="${POSTGRES_DB:-scans}"
echo "Applying schema to ${DB_NAME} as ${DB_USER} ..."
docker exec -i rag-postgres bash -lc "psql -U '${DB_USER}' -d '${DB_NAME}' -f /docker-entrypoint-initdb.d/setup_alldb.sql"
echo "Done."
