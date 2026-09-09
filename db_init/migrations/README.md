# db_init/migrations/

These files are **migrations and one-off repairs**, not init scripts. They are
here rather than in `db_init/` because the postgres image runs **every** top-level
`*.sql` / `*.sh` in `/docker-entrypoint-initdb.d` alphabetically, with
`ON_ERROR_STOP=1`.

`add_engagement_id_to_scan_tables.sql` sorts **first** alphabetically and its
opening statement is `ALTER TABLE public.jobs ...`. On a fresh volume that table
does not exist yet, so the statement failed, the entrypoint aborted, and the
container **exited 3** — before `ensure_all_tables.sql` (the authoritative
schema), before `setup_alldb.sql` (roles, the `n8n` / `exploitdb` databases,
`rag_documents`) and before `create_exploits.sh` (the `exploits` database).
Compose then restarted the container; PGDATA was already initialised, so init
never ran again and nobody saw the exit. A fresh install came up with a partial
schema and no `exploits` database.

Applying one of these by hand, against a database that already has the base
schema, is exactly what they are for:

    docker exec -i rag-postgres psql -U app -d scans \
      -f /docker-entrypoint-initdb.d/migrations/<file>.sql

`db_init/` is still bind-mounted at `/docker-entrypoint-initdb.d`, so these
remain reachable at that path — the entrypoint just does not run a subdirectory.

For routine schema repair prefer `scripts/ensure_db_schema.sh`, which applies
`ensure_all_tables.sql` (idempotent, and the only thing that reaches a remote
database).

See MIGRATION_GUIDE.md in this directory for per-file notes.
