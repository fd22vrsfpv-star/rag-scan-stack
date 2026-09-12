"""The operator can overrule what the platform learned.

Run on demand:

    pytest tests/test_tool_selection_review.py -v

WHY THIS EXISTS
---------------
`tool_selection_learned` shipped with a `status`, a `reviewed_by` and a
`rejected` state that the upsert in `etl/tool_learning.py` honours — and no way
for anybody to reach them. Undoing a wrong conclusion meant a psql session, so
in practice a bad rule would have stayed in service.

That is worse than it sounds, because these rules are DERIVED. Nobody typed
them, nobody reviewed them, and they change which tool runs first. A learner
with no correction surface is a learner whose mistakes are permanent.

WHAT IS ENFORCED
----------------
  * Every endpoint here is EXECUTED, not just imported. CLAUDE.md: a mutating
    endpoint ships an executing test in the same commit.
  * `reject` must survive new evidence — the point of the button. A rejection
    that the next observation quietly overturns is not a rejection.
  * Reviewing must record WHO, or the audit trail says a rule changed itself.
  * Approving must not widen authorisation. These rules order tools that were
    already authorised; if approving one could do anything else, this surface
    would be an approval bypass.

Skips cleanly when the stack or the database is not reachable.
"""
import os
import sys
import uuid

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, REPO)

requests = pytest.importorskip("requests", reason="requests not installed")
tl = pytest.importorskip("etl.tool_learning", reason="etl/tool_learning.py not importable")

RAG_API = os.environ.get("RAG_API_URL", "https://localhost:8000")
API_KEY = os.environ.get("API_KEY", "changeme")
HEADERS = {"x-api-key": API_KEY, "X-Operator": "pytest"}


def _get(path, **kw):
    return requests.get(f"{RAG_API}{path}", headers=HEADERS, verify=False, timeout=20, **kw)


def _post(path, **kw):
    return requests.post(f"{RAG_API}{path}", headers=HEADERS, verify=False, timeout=60, **kw)


@pytest.fixture(scope="module")
def live():
    try:
        r = requests.get(f"{RAG_API}/health", verify=False, timeout=10)
    except Exception as e:  # noqa: BLE001
        pytest.skip(f"rag-api unreachable at {RAG_API}: {e}")
    if r.status_code >= 500:
        pytest.skip(f"rag-api unhealthy: {r.status_code}")
    if not tl.available():
        pytest.skip("learning store unreachable")


@pytest.fixture
def rule(live):
    """A real learned rule, created the way the platform creates them."""
    svc = f"__pytest_{uuid.uuid4().hex[:8]}"
    sig, phrase = tl.error_signature("[ERROR] the peer closed the connection unexpectedly")
    learned = tl.observe_sequence(
        [{"tool": "toolA", "success": False, "signature": sig, "phrase": phrase},
         {"tool": "toolB", "success": True}],
        service=svc, emit=False)
    assert learned, "could not create a rule to review"
    yield {"id": learned[0]["id"], "service": svc, "signature": sig, "phrase": phrase}
    try:
        import psycopg2
        with psycopg2.connect(tl.DB_DSN) as conn, conn.cursor() as cur:
            cur.execute("DELETE FROM public.tool_selection_learned WHERE service=%s", (svc,))
            cur.execute("DELETE FROM public.tool_attempts WHERE service=%s", (svc,))
    except Exception:
        pass


# ── The endpoints execute ──────────────────────────────────────────────────

def test_listing_returns_the_rule(rule):
    r = _get("/tool-selection/learned", params={"service": rule["service"]})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["count"] >= 1, body
    ids = [x["id"] for x in body["learned"]]
    assert rule["id"] in ids, body
    row = next(x for x in body["learned"] if x["id"] == rule["id"])
    assert row["failed_tool"] == "toolA" and row["preferred_tool"] == "toolB"
    assert row["status"] == "active"
    assert isinstance(row["confidence"], float), (
        "confidence came back as a Decimal, which JSON-serialises to a string "
        "and breaks the percentage in the UI")


def test_listing_counts_by_status(rule):
    body = _get("/tool-selection/learned", params={"service": rule["service"]}).json()
    assert body["by_status"]["active"] >= 1, body["by_status"]


def test_the_evidence_behind_a_rule_is_reachable(rule):
    """A conclusion nobody can check is not reviewable."""
    tl.record_attempt("toolA", service=rule["service"], target="198.51.100.7",
                      port=443, success=False, signature=rule["signature"],
                      phrase=rule["phrase"], chosen_because="default_order")
    r = _get("/tool-selection/attempts", params={"signature": rule["signature"]})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["count"] >= 1, body
    assert any(a["tool"] == "toolA" for a in body["attempts"]), body


def test_reject_then_reset_round_trip(rule):
    r = _post(f"/tool-selection/learned/{rule['id']}/reject")
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "rejected", r.text
    assert r.json()["actor"] == "pytest", "the review did not record who did it"

    r = _post(f"/tool-selection/learned/{rule['id']}/reset")
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "proposed", r.text

    r = _post(f"/tool-selection/learned/{rule['id']}/approve")
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "active", r.text


def test_an_unknown_action_is_refused(rule):
    r = _post(f"/tool-selection/learned/{rule['id']}/delete")
    assert r.status_code == 400, r.text


def test_an_unknown_rule_is_a_404(live):
    r = _post(f"/tool-selection/learned/{uuid.uuid4()}/approve")
    assert r.status_code == 404, r.text


# ── The thing the button is for ────────────────────────────────────────────

def test_a_rejection_survives_new_evidence(rule):
    """The whole point. A rejection the next observation quietly overturns is
    not a rejection, and the operator would never know it came back."""
    assert _post(f"/tool-selection/learned/{rule['id']}/reject").status_code == 200

    tl.observe_sequence(
        [{"tool": "toolA", "success": False, "signature": rule["signature"],
          "phrase": rule["phrase"]},
         {"tool": "toolB", "success": True}],
        service=rule["service"], emit=False)

    body = _get("/tool-selection/learned", params={"service": rule["service"]}).json()
    row = next(x for x in body["learned"] if x["id"] == rule["id"])
    assert row["status"] == "rejected", (
        "new evidence reinstated a rule the operator rejected")
    assert row["reviewed_by"] == "pytest", "the rejection lost its reviewer"

    tool, reason, _ = tl.next_tool("toolA", rule["signature"], ["toolB"],
                                   service=rule["service"])
    assert reason != "learned", (
        "a rejected rule is still being applied, so rejecting it changed nothing")


def test_reviewing_does_not_widen_authorisation(rule):
    """These rules order tools that were already authorised. If approving one
    could reach outside the caller's candidate list, this surface would be an
    approval bypass rather than a correction surface."""
    assert _post(f"/tool-selection/learned/{rule['id']}/approve").status_code == 200
    tool, _reason, _rid = tl.next_tool("toolA", rule["signature"], ["somethingElse"],
                                       service=rule["service"])
    assert tool != "toolB", (
        "an approved rule returned a tool the caller never offered")


# ── Backfill ───────────────────────────────────────────────────────────────

def test_backfill_executes_and_reports_what_it_saw(live):
    """Reads history only — it dispatches nothing and touches no target."""
    r = _post("/tool-selection/backfill", json={"since_hours": 1,
                                                "phase": "__pytest_phase"})
    assert r.status_code == 200, r.text
    body = r.json()
    for key in ("examined", "failures", "fruitless", "rules", "cleared"):
        assert key in body, body
    assert body["actor"] == "pytest"


def test_backfill_reset_clears_before_deriving(live):
    r = _post("/tool-selection/backfill", json={"reset": True,
                                                "phase": "__pytest_phase"})
    assert r.status_code == 200, r.text
    assert r.json()["ok"] is True


# ── One coherent status per execution, for manual review ───────────────────

def _any_execution_id():
    import psycopg2
    with psycopg2.connect(tl.DB_DSN) as conn, conn.cursor() as cur:
        cur.execute("""SELECT id::text FROM tool_executions
                        WHERE COALESCE(output,'') <> '' ORDER BY started_at DESC LIMIT 1""")
        row = cur.fetchone()
    return row[0] if row else None


def test_an_execution_reports_what_the_learner_made_of_it(live):
    """A reviewer reading a tool's output needs to know what the platform
    concluded about it. Three modules each hold a piece of that — what to DO
    about the run, what was IN it, what was LEARNED from it — and a reviewer
    who has to reconcile three answers by hand will not do it."""
    eid = _any_execution_id()
    if not eid:
        pytest.skip("no stored executions with output")
    r = _get(f"/agent/post-review/executions/{eid}")
    assert r.status_code == 200, r.text
    body = r.json()
    for block in ("classification", "analysis", "learning"):
        assert block in body, f"{block} is missing from the manual-review payload"

    learning = body["learning"]
    assert learning["available"] is True, learning
    assert learning["outcome"] in ("errored", "fruitless", "unmeasured", "productive"), learning
    assert learning["why"], "the outcome has no explanation, so it cannot be reviewed"


def test_the_outcome_matches_the_learner_rather_than_being_re_derived(live):
    """A second copy of this judgement would drift from the one that actually
    trains the rules, and the panel would then show a status the platform never
    acted on."""
    eid = _any_execution_id()
    if not eid:
        pytest.skip("no stored executions with output")
    body = _get(f"/agent/post-review/executions/{eid}").json()
    ex, learning = body["execution"], body["learning"]
    failed = tl.execution_failed(ex.get("status"), ex.get("exit_code"),
                                 ex.get("error") or "", ex.get("output") or "")
    assert (learning["outcome"] == "errored") == failed, (learning, ex.get("status"),
                                                          ex.get("exit_code"))


def test_no_suggestions_is_not_the_same_as_could_not_look(live):
    eid = _any_execution_id()
    if not eid:
        pytest.skip("no stored executions with output")
    learning = _get(f"/agent/post-review/executions/{eid}").json()["learning"]
    assert learning.get("suggestions_state") in (
        "not_applicable", "looked", "store_unreachable"), learning
    if learning["outcome"] in ("productive", "unmeasured"):
        assert learning["suggestions_state"] == "not_applicable", (
            "a run with no failure signature reports the store as unreachable, "
            "which reads as 'we looked and nothing has ever worked after this' "
            "— a different claim entirely, and the reviewer acts on it wrongly")


def test_an_unknown_execution_is_a_404(live):
    assert _get(f"/agent/post-review/executions/{uuid.uuid4()}").status_code == 404
