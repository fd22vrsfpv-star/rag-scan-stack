-- Terminate every backend on the `scans` database whose transaction has been
-- open longer than 10 minutes (the multi-hour rule-engine / osint sweeps that
-- hold AccessShare on `assets` and block DDL + every reader behind it), then
-- show the lock state afterwards. Operator-run only; see Docs/OPEN_ITEMS.md
-- "Orphaned idle-in-transaction DB sessions". Clients reconnect and restart.
--
--   ! docker exec -i -e PGDSN='postgresql://app:app@rag-postgres:5432/scans?sslmode=require' kali-listener sh -c 'psql "$PGDSN" -A -f -' < scripts/sql/terminate_long_transactions.sql
--
SELECT 'before' AS t,
       count(*) FILTER (WHERE wait_event_type = 'Lock')                       AS waiting,
       count(*) FILTER (WHERE state = 'idle in transaction')                  AS idle_in_tx,
       count(*) FILTER (WHERE now() - xact_start > interval '10 min')         AS xact_over_10m
FROM pg_stat_activity WHERE datname = 'scans';

SELECT pid, client_addr, (now() - xact_start)::text AS xact_age, state,
       left(regexp_replace(query, '\s+', ' ', 'g'), 60) AS last_query,
       pg_terminate_backend(pid) AS terminated
FROM pg_stat_activity
WHERE datname = 'scans'
  AND pid <> pg_backend_pid()
  AND now() - xact_start > interval '10 min'
ORDER BY xact_start;

SELECT pg_sleep(3);

SELECT 'after' AS t,
       count(*) FILTER (WHERE wait_event_type = 'Lock')                       AS waiting,
       count(*) FILTER (WHERE state = 'idle in transaction')                  AS idle_in_tx,
       count(*) FILTER (WHERE now() - xact_start > interval '10 min')         AS xact_over_10m,
       count(*)                                                               AS total
FROM pg_stat_activity WHERE datname = 'scans';
