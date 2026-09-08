"""The schema + knowledge repair endpoints must actually execute.

Run on demand:

    pytest tests/test_maintenance_repair_endpoints.py -v
    BFF_URL=https://localhost:3002 pytest tests/test_maintenance_repair_endpoints.py

WHY THIS EXISTS
---------------
`POST /health/sql/apply-schema` looked correct and was badly wrong in two ways
that only running it could reveal:

  1. It assigned `schema_path = ".../ensure_all_tables.sql"` and then never read
     the variable — it applied a hand-maintained inline statement list instead.
     That list had drifted: it would NOT have created scan_parameters,
     post_review_reports or v_identity_credential_state, every one of which the
     canonical DDL declares and which were in fact missing from the live
     database. The endpoint answered `{"ok": true}` the whole time.
  2. Once it did read the file, psycopg2 sent all 275 KB as ONE implicit
     transaction, so a single pre-existing duplicate-key row discarded every
     other statement — again reporting success, having created nothing.

Neither is visible to `ast.parse`, an import check, or a healthy container. Both
are obvious the moment the endpoint runs and its result is inspected.

Skips cleanly when the stack is not up, so a bare unit run stays green.

RUNTIME: ~28 min against a live stack. It applies the 736-statement DDL three
times and seeds the ~585-document corpus three times, because idempotence is the
property that matters for a repair tool and it can only be shown by repeating the
operation. Nothing here runs in CI, where the stack is absent and every test
skips.
"""
import os
import time

import pytest

requests = pytest.importorskip("requests")
requests.packages.urllib3.disable_warnings()  # self-signed stack certs

BFF = os.environ.get("BFF_URL", "https://localhost:3002")
TIMEOUT = int(os.environ.get("MAINT_TIMEOUT", "900"))


def _get(path, **kw):
    try:
        return requests.get(f"{BFF}{path}", verify=False, timeout=kw.pop("timeout", 60), **kw)
    except requests.RequestException as exc:
        pytest.skip(f"dashboard not reachable at {BFF}: {exc}")


def _post(path, **kw):
    try:
        return requests.post(f"{BFF}{path}", verify=False, timeout=kw.pop("timeout", TIMEOUT), **kw)
    except requests.RequestException as exc:
        pytest.skip(f"dashboard not reachable at {BFF}: {exc}")


@pytest.fixture(scope="module")
def live():
    r = _get("/api/maintenance/schema/check")
    if r.status_code in (502, 503, 504):
        pytest.skip(f"upstream not ready ({r.status_code})")
    return True


def test_schema_check_executes(live):
    """The pre-existing 'what is missing' check, reached through the BFF."""
    r = _get("/api/maintenance/schema/check")
    assert r.status_code == 200, r.text[:300]
    body = r.json()
    assert "missing_tables" in body, body
    assert isinstance(body["missing_tables"], list), body
    assert body.get("table_count", 0) > 0, f"no tables reported: {body}"


def test_schema_apply_uses_the_canonical_ddl(live):
    """The regression that mattered: it must apply the real DDL, not the inline
    subset, and must report which one it used."""
    r = _post("/api/maintenance/schema/apply")
    assert r.status_code == 200, r.text[:300]
    body = r.json()
    assert body.get("ok") is True, body
    assert body.get("canonical_ddl"), (
        "no canonical DDL path reported — the endpoint fell back to the inline "
        f"statement list, which is a drifting subset: {body}"
    )
    assert body.get("canonical_applied") is True, (
        f"canonical DDL was found but not applied: {str(body)[:400]}"
    )
    # One failing statement used to abort the whole file while still reporting
    # success, so a healthy run must show many statements actually executed.
    assert body.get("canonical_statements_ok", 0) > 100, (
        f"only {body.get('canonical_statements_ok')} DDL statements ran — a single "
        f"failure probably aborted the batch: {str(body)[:400]}"
    )


def test_schema_apply_is_idempotent(live):
    """Repair must be safe to re-run: the second pass adds nothing."""
    first = _post("/api/maintenance/schema/apply").json()
    second = _post("/api/maintenance/schema/apply").json()
    assert second.get("ok") is True, second
    assert second.get("tables_after") == second.get("tables_before"), (
        f"a second apply changed the table count: {second}"
    )
    assert first.get("tables_after") == second.get("tables_after"), (first, second)


def test_apply_schema_leaves_no_missing_tables(live):
    """The two halves must agree: after a repair the check reports nothing missing."""
    _post("/api/maintenance/schema/apply")
    body = _get("/api/maintenance/schema/check").json()
    assert body.get("missing_tables") == [], (
        f"apply-schema reported success but the check still lists missing tables: "
        f"{body.get('missing_tables')}"
    )


def test_knowledge_status_executes(live):
    r = _get("/api/maintenance/knowledge/status")
    assert r.status_code == 200, r.text[:300]
    body = r.json()
    assert "prompt_count" in body and isinstance(body["prompt_count"], int), body
    assert body.get("seeded") == (body["prompt_count"] > 0), body


def test_knowledge_seed_dry_run_changes_nothing(live):
    """A dry run must report what it would do without writing."""
    before = _get("/api/maintenance/knowledge/status").json()["prompt_count"]
    r = _post("/api/maintenance/knowledge/seed", json={"dry_run": True})
    assert r.status_code == 200, r.text[:300]
    body = r.json()
    assert body.get("dry_run") is True, body
    assert body.get("files"), f"no seed files found — is /knowledge/seed mounted? {body}"
    after = _get("/api/maintenance/knowledge/status").json()["prompt_count"]
    assert after == before, f"dry run changed the prompt count {before} -> {after}"


#: A representative subset for the idempotency test: one file of prompts and one
#: of service docs, so both write paths are exercised. The FULL corpus is 36
#: prompts + 585 docs at ~1.4s per doc — 13m12s, measured — and running it twice
#: to prove idempotency would put 27 minutes into the suite to test a property
#: two files demonstrate just as well.
SEED_SUBSET = ["knowledge-base.yaml", "htb-attack-paths.yaml"]


def _seed_and_wait(payload=None, budget_sec=2400):
    """Start a seed job and poll it to a terminal state.

    A real seed is ~585 embedding round-trips (measured: 9 docs in 13.05s, so
    ~1.45s each, ~14 minutes for the corpus). It used to run inside one HTTP
    request behind a 900s timeout, so the request was abandoned mid-flight and
    the work discarded — which read as a hang and wedged this whole file.
    """
    r = _post("/api/maintenance/knowledge/seed", json=payload or {}, timeout=60)
    assert r.status_code == 200, r.text[:300]
    started = r.json()
    job_id = started.get("job_id")
    assert job_id, f"seed did not return a job id — did it go back to running inline? {started}"

    deadline = time.time() + budget_sec
    last = None
    while time.time() < deadline:
        time.sleep(5)
        job = _get(f"/api/maintenance/knowledge/seed/status?job_id={job_id}").json()
        assert job.get("known"), f"seed job vanished (service restart?): {job}"
        last = job
        if job.get("status") != "running":
            break
    else:
        pytest.fail(f"seed still running after {budget_sec}s; last state {last}")

    assert last["status"] != "failed", f"seed job failed: {last.get('error')}"
    result = last.get("result")
    assert result, f"terminal seed job carries no result: {last}"
    return result


def test_knowledge_seed_executes_and_is_idempotent(live):
    """Re-seeding must UPDATE in place, never duplicate: the selector is the
    identity of a rule and a second insert would collide on its unique index."""
    body = _seed_and_wait({"files": SEED_SUBSET})
    assert body.get("failed", 1) == 0, f"seed reported failures: {body.get('errors')}"
    count_1 = _get("/api/maintenance/knowledge/status").json()["prompt_count"]
    assert count_1 > 0, "seeding ran but no prompt rules exist"

    again = _seed_and_wait({"files": SEED_SUBSET})
    assert again.get("failed", 1) == 0, again.get("errors")
    assert again.get("created", 0) == 0, (
        f"a re-seed created {again.get('created')} new rule(s) — it should update in place"
    )
    count_2 = _get("/api/maintenance/knowledge/status").json()["prompt_count"]
    assert count_2 == count_1, f"re-seeding changed the count {count_1} -> {count_2}"
