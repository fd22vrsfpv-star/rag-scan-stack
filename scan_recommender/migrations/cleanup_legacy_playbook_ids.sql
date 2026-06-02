-- Cleanup legacy playbook chunks with non-deterministic `edb_id` values.
--
-- Background:
--   The prior playbook ingest used `-abs(hash(filename)) % 1000000` to
--   generate a per-file `edb_id`.  Two bugs:
--     1. Python's hash() is PYTHONHASHSEED-dependent, so the same file got
--        a different id after every interpreter restart -- breaking the
--        atomic-replace idempotency.
--     2. `-abs(x) % 1_000_000` is always non-negative in Python, so the
--        "negative range to avoid ExploitDB collisions" never triggered.
--        Playbook rows landed in 0..999_999, same as ExploitDB.
--
-- The new `_stable_playbook_id()` writes deterministic ids in the range
-- [-1_000_000_001, -1].  After deploying that change, any old playbook
-- chunks (positive `edb_id`) in the `knowledge_base` source_repo are
-- stale and will never be referenced again -- the next /rag/playbooks/
-- ingest will write fresh rows with the new negative ids.
--
-- This migration deletes those stale rows.  Idempotent: re-running is a
-- no-op once they're gone.
--
-- Safe to run BEFORE re-ingest -- the new code creates the proper
-- negative-id rows on the next /rag/playbooks/ingest call.

DELETE FROM public.exploit_chunks
WHERE source_repo = 'knowledge_base'
  AND edb_id >= 0;
