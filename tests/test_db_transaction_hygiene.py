"""2026-10-10: the four-hour-transaction incident, fixed end to end.

Seventeen OSINT sweep transactions from one installation, each hours old, held
AccessShare on `assets`; `ensure_db_schema.sh`'s ALTER queued behind them and
every reader of `assets` queued behind the ALTER (16 waiters, BFF 400s). Root
cause: the BFF recon agent sent `?since_minutes=N` while rag-api read a JSON
body, saw 0 and swept a YEAR of findings in ONE transaction, every cycle, with
overlapping cycles contending on the same follow-up rows. Five fixes, each
pinned here (sabotage-provable — every assertion is a string the fix added):

  1. /agent/scan honours the query form, caps the window at 24 h unless full=true
  2. one sweep at a time (pg_try_advisory_lock), reported when skipped
  3. short transactions: commit after the rule pass, commit per follow-up,
     5 s lock / 2 min idle caps on the sweep's own connection
  4. db-txn-watchdog in rag-api (alert / optional terminate) + health-check line,
     because Postgres 16 has no transaction_timeout
  5. ensure_db_schema.sh: lock_timeout, information_schema guard on ADD COLUMN,
     tagged inner psql killed by the EXIT trap, one retry on lock timeouts

Same-class fixes elsewhere (the "analysis for this problem elsewhere"):
  etl/access.py refresh() and scan_recommender/exploits_rag.py commit per
  iteration instead of holding a transaction across network probes / embeds.

    docker run --rm -v /opt/rag-scan-stack:/work:ro -w /work python:3.12-slim \
      sh -c 'pip install -q pytest && PYTHONPATH=. python -m pytest tests/test_db_transaction_hygiene.py -v'
"""
from __future__ import annotations

import ast as _ast
import logging
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
API = REPO / "app" / "rag-api" / "api.py"
OSINT = REPO / "app" / "rag-api" / "osint_agent.py"
RECON = REPO / "dashboard" / "bff" / "services" / "recon_agent.py"
SCHEMA_SH = REPO / "scripts" / "ensure_db_schema.sh"
CHECK_SH = REPO / "scripts" / "post-install-check.sh"
SQL = REPO / "db_init" / "ensure_all_tables.sql"
ACCESS = REPO / "etl" / "access.py"
XRAG = REPO / "scan_recommender" / "exploits_rag.py"


def _func_src(name: str, path=API) -> str | None:
    src = path.read_text()
    tree = _ast.parse(src)
    for node in _ast.walk(tree):
        if isinstance(node, (_ast.FunctionDef, _ast.AsyncFunctionDef)) and node.name == name:
            return _ast.get_source_segment(src, node)
    return None


# ── 1. the window ────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def window():
    ns = {}
    exec("AGENT_SCAN_DEFAULT_MINUTES = 1440\nAGENT_SCAN_FULL_MINUTES = 525600\n", ns)
    exec(_func_src("_agent_scan_window"), ns)
    return ns["_agent_scan_window"]


@pytest.mark.parametrize("q,body,full,expect", [
    (None, 0, False, 1440),       # the periodic trigger's old effective input → 24 h, not a year
    (5, 0, False, 5),             # query form (what the recon agent sends)
    (None, 90, False, 90),        # body form (what the Follow-ups page sends)
    (5, 90, False, 5),            # query wins
    (None, 0, True, 525600),      # explicit full sweep
    (5, 0, True, 525600),
])
def test_agent_scan_window(window, q, body, full, expect):
    assert window(q, body, full) == expect


def test_agent_scan_endpoint_reads_query_and_body():
    src = _func_src("trigger_agent_scan")
    assert src
    assert "since_minutes: Optional[int] = Query(None" in src
    assert "full: bool = Query(False" in src
    assert "_agent_scan_window(since_minutes, body.since_minutes" in src
    assert "525600" not in src.split("_agent_scan_window")[0]   # the "a year" literal left the handler
    recon = RECON.read_text()
    seg = recon[recon.index('f"{s.rag_api_url}/agent/scan"'):]
    seg = seg[:seg.index("headers=headers")]
    assert 'params={"since_minutes": since_minutes' in seg and 'json={"since_minutes": since_minutes}' in seg


# ── 2 + 3. the sweep ─────────────────────────────────────────────────────────

def test_sweep_is_single_flight_clamped_and_short_transactions():
    src = _func_src("scan_new_findings", OSINT)
    assert src
    assert "pg_try_advisory_lock(%s)" in src and "pg_advisory_unlock(%s)" in src
    assert '"reason": "sweep_already_running"' in src and '"osint_sweep_skipped_overlap"' in src
    assert "if not full and requested > SWEEP_MAX_MINUTES" in src
    # the rule pass ends its transaction before the inserts start
    i_rules = src.index("matches = engine.execute_all(cur, since_minutes)")
    i_commit = src.index("conn.commit()", i_rules)
    i_loop = src.index("for match in matches:")
    assert i_rules < i_commit < i_loop
    # one transaction per follow-up; the old all-or-nothing savepoint is gone
    loop = src[i_loop:src.index('"osint_sweep_completed"')]
    assert loop.count("conn.commit()") >= 2 and "conn.rollback()" in loop
    assert "SAVEPOINT followup_insert" not in src
    conn = _func_src("_get_conn", OSINT)
    assert "idle_in_transaction_session_timeout=120000" in conn and "lock_timeout=5000" in conn
    osint = OSINT.read_text()
    assert 'SWEEP_MAX_MINUTES = int(os.environ.get("OSINT_SWEEP_MAX_MINUTES", "1440")' in osint


# ── 4. the watchdog ──────────────────────────────────────────────────────────

@pytest.fixture()
def watchdog():
    ns = {"logging": logging, "_DB_TXN_ALERTED": {}}
    exec(_func_src("_db_txn_watchdog_pass"), ns)
    return ns


def test_watchdog_alerts_once_per_hour_and_terminates_only_past_the_threshold(watchdog):
    rows = [{"pid": 11, "client_addr": "10.0.0.9", "xact_age_sec": 20 * 60, "state": "idle in transaction", "query": "SAVEPOINT x"},
            {"pid": 12, "client_addr": "10.0.0.9", "xact_age_sec": 90 * 60, "state": "active", "query": "INSERT ..."}]
    terminated_calls, emitted = [], []
    watchdog["_get_setting"] = lambda k, d="": {"db_txn_alert_after_min": "15", "db_txn_terminate_after_min": "60"}[k]
    watchdog["_db_long_transactions"] = lambda min_age_min=10.0, limit=50: rows
    watchdog["_db_terminate_backends"] = lambda pids: (terminated_calls.append(list(pids)) or list(pids))
    import types, sys
    fake = types.ModuleType("webhooks")
    fake.emit_webhook = lambda et, src, data, **k: emitted.append((et, data))
    sys.modules["webhooks"] = fake
    try:
        r1 = watchdog["_db_txn_watchdog_pass"](now=1_000_000)
        assert r1["alerted"] == [11, 12] and r1["terminated"] == [12]
        assert terminated_calls == [[12]]
        assert [e[0] for e in emitted] == ["db_long_transaction_detected", "db_long_transaction_detected",
                                           "db_long_transaction_terminated"]
        # 10 minutes later: no re-alert (hourly), terminate still applies
        r2 = watchdog["_db_txn_watchdog_pass"](now=1_000_600)
        assert r2["alerted"] == [] and r2["terminated"] == [12]
        # alert-only mode (the default): nothing is terminated
        watchdog["_get_setting"] = lambda k, d="": {"db_txn_alert_after_min": "15", "db_txn_terminate_after_min": "0"}[k]
        terminated_calls.clear()
        r3 = watchdog["_db_txn_watchdog_pass"](now=1_010_000)
        assert r3["terminated"] == [] and terminated_calls == []
    finally:
        sys.modules.pop("webhooks", None)


def test_watchdog_is_wired_and_the_endpoint_exists():
    api = API.read_text()
    # interval arithmetic, not make_interval(mins => %s): psycopg2 binds a float as
    # numeric and `make_interval(mins => numeric)` does not exist (caught live)
    assert "def _db_long_transactions(" in api and "now() - xact_start > (%s::float8 * interval '1 minute')" in api
    assert "pid <> pg_backend_pid()" in api and "datname = current_database()" in api
    assert '@app.get("/db/long-transactions"' in api
    assert "def _start_db_txn_watchdog" in api and "_ensure_db_txn_watchdog()" in api
    assert 'name="db-txn-watchdog"' in api
    sql = SQL.read_text()
    assert "('db_txn_alert_after_min'" in sql and "('db_txn_terminate_after_min'" in sql
    check = CHECK_SH.read_text()
    assert "now() - xact_start > interval '30 min'" in check
    assert "db_txn_terminate_after_min" in check


# ── 5. the schema script ─────────────────────────────────────────────────────

def test_schema_script_fails_fast_guards_add_column_and_kills_its_psql():
    sh = SCHEMA_SH.read_text()
    assert "SET lock_timeout = '10s';" in sh
    assert "_guard_add_column" in sh and "information_schema.columns" in sh
    assert 'SCHEMA_RUN_TAG="ensure_db_schema_run=' in sh and "trap _kill_inner_psql EXIT INT TERM" in sh
    assert 'pkill -f "$SCHEMA_RUN_TAG"' in sh
    assert 'grep -c "canceling statement due to lock timeout"' in sh and "retrying once" in sh
    assert subprocess.run(["bash", "-n", str(SCHEMA_SH)], capture_output=True).returncode == 0


def test_guard_add_column_rewrites_only_the_single_line_do_block():
    sh = SCHEMA_SH.read_text()
    fn = sh[sh.index("_guard_add_column() {"):]
    fn = fn[:fn.index("\n}\n") + 3]
    sample = (
        "DO $$ BEGIN ALTER TABLE public.assets ADD COLUMN IF NOT EXISTS hostname text; EXCEPTION WHEN OTHERS THEN NULL; END $$;\n"
        "DO $$ BEGIN ALTER TABLE scope_suggestions ADD COLUMN IF NOT EXISTS score numeric DEFAULT 0; EXCEPTION WHEN OTHERS THEN NULL; END $$;\n"
        "    ALTER TABLE public.assets ADD COLUMN IF NOT EXISTS provider text[] DEFAULT '{}'::text[];\n"
        "CREATE TABLE IF NOT EXISTS x (id int);\n")
    out = subprocess.run(["bash", "-c", fn + "\n_guard_add_column"], input=sample, capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    lines = out.stdout.splitlines()
    assert "table_name='assets' AND column_name='hostname'" in lines[0]
    assert "THEN ALTER TABLE public.assets ADD COLUMN IF NOT EXISTS hostname text; END IF;" in lines[0]
    assert "table_name='scope_suggestions' AND column_name='score'" in lines[1]
    assert "ALTER TABLE scope_suggestions ADD COLUMN IF NOT EXISTS score numeric DEFAULT 0;" in lines[1]
    assert lines[2] == "    ALTER TABLE public.assets ADD COLUMN IF NOT EXISTS provider text[] DEFAULT '{}'::text[];"
    assert lines[3] == "CREATE TABLE IF NOT EXISTS x (id int);"


# ── elsewhere: same class ────────────────────────────────────────────────────

def test_access_refresh_and_exploit_embedding_commit_per_iteration():
    refresh = _func_src("refresh", ACCESS)
    assert refresh
    first_loop = refresh[refresh.index("for cand in candidates:"):refresh.index("# Reconcile what we still THINK")]
    assert "conn.commit()" in first_loop
    stale_loop = refresh[refresh.index("for kind, handle, port, transport in stale:"):refresh.index("# Mirror held access")]
    assert "conn.commit()" in stale_loop
    assert "idle_in_transaction_session_timeout=120000" in _func_src("_connect", ACCESS)
    emb = _func_src("_ensure_exploit_embedded", XRAG)
    loop = emb[emb.index("for idx, ch in enumerate(chunks):"):emb.index('logger.info(f"[embed] On-demand')]
    assert "conn.commit()" in loop and "conn.rollback()" in loop
    ing = _func_src("_ingest", XRAG)
    rec_loop = ing[ing.index("for rec in records:"):ing.index('logger.info(f"[ingest] Complete!')]
    assert rec_loop.count("conn.commit()") >= 1 and "conn.rollback()" in rec_loop
    assert "lock_timeout=5000" in _func_src("_conn", XRAG)
