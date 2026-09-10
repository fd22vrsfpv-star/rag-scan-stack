"""News enrichment is operator-driven, not automatic.

Ingest used to LLM-enrich every freshly-touched item (up to 200 per cycle) and
then auto-run stage 2 across everything it flagged -- an unbounded LLM bill on
every cycle, mostly spent on stories nobody looked at. Enrichment now happens
only on the items the operator selected.

These are the tests that FAIL if that regresses:

  * fetch_all_sources() must not call _enrich_pending / _stage2_for_flagged_items
  * the KEV rule must have exactly ONE owner (_kev_for_cves)
  * POST /jobs/enrich must accept many ids, and SHED (429) past the cap
  * POST /jobs/stage2 must exist and execute

Source is read with `ast` rather than imported wherever possible, so the guards
still run on a bare checkout with no psycopg2/feedparser present.

Standalone: pytest tests/test_news_enrichment_ondemand.py
"""
import ast
import io
import os
import sys

import pytest

REPO = os.path.join(os.path.dirname(__file__), "..")
AGENT = os.path.join(REPO, "news_runner", "news_agent.py")
MAIN = os.path.join(REPO, "news_runner", "main.py")


def _tree(path):
    if not os.path.exists(path):
        pytest.skip(f"{path} not present in this checkout")
    return ast.parse(io.open(path, encoding="utf-8").read())


def _func(tree, name):
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    return None


def _called_names(node):
    """Every function name called anywhere inside `node`."""
    out = set()
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call):
            f = sub.func
            if isinstance(f, ast.Name):
                out.add(f.id)
            elif isinstance(f, ast.Attribute):
                out.add(f.attr)
    return out


# ---------------------------------------------------------------------------
# The guard: ingest does not enrich
# ---------------------------------------------------------------------------

def test_ingest_does_not_auto_enrich():
    """fetch_all_sources must not kick off LLM enrichment.

    Sabotage check: re-add `_enrich_pending(limit=200)` to fetch_all_sources
    and this fails on the first assert.
    """
    fn = _func(_tree(AGENT), "fetch_all_sources")
    assert fn is not None, "fetch_all_sources not found"
    called = _called_names(fn)
    assert "_enrich_pending" not in called, (
        "fetch_all_sources calls _enrich_pending -- ingest is LLM-enriching "
        "again. Enrichment belongs on operator-selected items "
        "(POST /jobs/enrich)."
    )
    assert "_stage2_for_flagged_items" not in called, (
        "fetch_all_sources calls _stage2_for_flagged_items -- stage 2 is "
        "operator-triggered (POST /jobs/stage2)."
    )


def test_ingest_still_applies_the_cheap_kev_flag():
    """The KEV flag costs no LLM call and is the signal the operator selects
    on. If ingest stops applying it, every freshly-ingested row has no flags
    at all and there is nothing to triage."""
    fn = _func(_tree(AGENT), "fetch_all_sources")
    assert "_apply_kev_flags" in _called_names(fn), (
        "fetch_all_sources no longer applies the KEV flag -- new items will "
        "carry no flags at all"
    )


def test_kev_rule_has_exactly_one_owner():
    """The deterministic KEV lookup must live only in _kev_for_cves.

    Two copies of this rule drift, and a drifted KEV flag is invisible: the
    row just shows the wrong badge.
    """
    tree = _tree(AGENT)
    offenders = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef) or node.name == "_kev_for_cves":
            continue
        for sub in ast.walk(node):
            if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
                if "cisa_kev_cache" in sub.value and "cve_id = ANY" in sub.value:
                    offenders.append(node.name)
    assert not offenders, (
        f"the KEV lookup is duplicated in {sorted(set(offenders))} -- it must "
        f"go through _kev_for_cves so the two cannot drift"
    )


def test_enrich_batch_cap_is_declared_not_invented():
    """A select-all must not become thousands of LLM calls."""
    src = io.open(MAIN, encoding="utf-8").read() if os.path.exists(MAIN) else ""
    if not src:
        pytest.skip("news_runner/main.py not present")
    assert "MAX_ENRICH_BATCH" in src, "no batch cap on bulk enrichment"
    assert "429" in src, "over-cap batches must be SHED (429), not accepted"


# ---------------------------------------------------------------------------
# Endpoints that actually execute
# ---------------------------------------------------------------------------

@pytest.fixture()
def client(monkeypatch):
    """TestClient over news_runner.main with the LLM + DB calls stubbed.

    Skips (not fails) when fastapi/psycopg2 are unavailable -- "cannot run
    here" is not the same as "broken".
    """
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    pytest.importorskip("psycopg2")
    from fastapi.testclient import TestClient

    sys.path.insert(0, os.path.join(REPO, "news_runner"))
    import news_agent  # type: ignore
    import main as news_main  # type: ignore

    calls = {"enrich": [], "stage2": 0, "emits": []}

    def _fake_enrich(limit=200, item_ids=None):
        calls["enrich"].append({"limit": limit, "item_ids": list(item_ids or [])})
        n = len(item_ids or [])
        # Mirrors the real return shape: a bare count cannot tell "bad items"
        # from "quota exhausted".
        return {"requested": n, "enriched": n, "rate_limited": 0, "failed": 0}

    monkeypatch.setattr(news_agent, "_enrich_pending", _fake_enrich)
    monkeypatch.setattr(news_agent, "_stage2_for_flagged_items",
                        lambda: calls.__setitem__("stage2", calls["stage2"] + 1) or 7)
    monkeypatch.setattr(news_agent, "_emit_webhook",
                        lambda et, src, data: calls["emits"].append((et, src)))

    # TestClient without a context manager does not fire startup events, so
    # the CISA-KEV pull and scheduler thread stay out of the test.
    return TestClient(news_main.app), calls, news_main


def test_jobs_enrich_single_runs_inline(client):
    c, calls, _ = client
    r = c.post("/jobs/enrich", json={"item_id": "11111111-1111-1111-1111-111111111111"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["requested"] == 1
    assert body["enriched"] == 1
    assert body["queued"] == 0
    assert calls["enrich"][0]["item_ids"] == ["11111111-1111-1111-1111-111111111111"]
    assert any(et == "news_items_enriched" for et, _ in calls["emits"])


def test_jobs_enrich_accepts_many_ids(client):
    """The whole point: the operator's multi-select goes through in one call."""
    c, calls, _ = client
    ids = [f"1111111{i}-1111-1111-1111-111111111111" for i in range(4)]
    r = c.post("/jobs/enrich", json={"item_ids": ids})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["requested"] == 4
    assert body["queued"] == 4
    assert body["enriched"] is None, "a backgrounded batch cannot report a count yet"
    # BackgroundTasks run after the response is returned by TestClient
    assert calls["enrich"] and calls["enrich"][-1]["item_ids"] == ids


def test_jobs_enrich_dedupes_and_merges_both_fields(client):
    c, calls, _ = client
    r = c.post("/jobs/enrich", json={"item_id": "a", "item_ids": ["a", "b", "b", "c"]})
    assert r.status_code == 200, r.text
    assert r.json()["requested"] == 3
    assert calls["enrich"][-1]["item_ids"] == ["a", "b", "c"]


def test_jobs_enrich_requires_at_least_one_id(client):
    c, _, _ = client
    r = c.post("/jobs/enrich", json={})
    assert r.status_code == 400, r.text


def test_jobs_enrich_sheds_over_the_cap(client):
    """Shed, do not queue: 429 rather than accepting work that will time out."""
    c, calls, news_main = client
    ids = [str(i) for i in range(news_main.MAX_ENRICH_BATCH + 1)]
    r = c.post("/jobs/enrich", json={"item_ids": ids})
    assert r.status_code == 429, r.text
    assert "NEWS_MAX_ENRICH_BATCH" in r.text
    assert not calls["enrich"], "an over-cap batch must not start any enrichment"


def test_jobs_stage2_executes(client):
    c, calls, _ = client
    r = c.post("/jobs/stage2", json={})
    assert r.status_code == 200, r.text
    assert r.json()["queued"] is True
    assert calls["stage2"] == 1, "stage 2 did not actually run"


def test_match_assets_rejects_a_missing_item_id(client):
    """item_id became Optional when item_ids was added -- the single-item jobs
    must still refuse an empty body rather than pass None to psycopg2."""
    c, _, _ = client
    r = c.post("/jobs/match-assets", json={})
    assert r.status_code == 400, r.text


# ---------------------------------------------------------------------------
# Rate limiting: a 429 from the provider is not "nothing to do"
# ---------------------------------------------------------------------------

def test_enrich_reports_rate_limit_instead_of_a_silent_zero(client, monkeypatch):
    """A single item that got rate-limited must surface as 429, not enriched:0.

    Before this, _call_llm swallowed the 429 and returned None, the item was
    recorded as simply not enriched, and the operator saw a success response
    with a zero in it.
    """
    c, _, news_main = client
    import news_agent  # type: ignore
    monkeypatch.setattr(
        news_agent, "_enrich_pending",
        lambda limit=200, item_ids=None: {
            "requested": 1, "enriched": 0, "rate_limited": 1, "failed": 0},
    )
    r = c.post("/jobs/enrich", json={"item_id": "x"})
    assert r.status_code == 429, r.text
    assert "quota" in r.text.lower()


def test_partial_success_is_not_reported_as_a_rate_limit(client, monkeypatch):
    """If some items enriched before the quota ran out, that is a 200 carrying
    the counts -- throwing away the work that succeeded would be worse."""
    c, _, _ = client
    import news_agent  # type: ignore
    monkeypatch.setattr(
        news_agent, "_enrich_pending",
        lambda limit=200, item_ids=None: {
            "requested": 1, "enriched": 1, "rate_limited": 1, "failed": 0},
    )
    r = c.post("/jobs/enrich", json={"item_id": "x"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["enriched"] == 1
    assert body["rate_limited"] == 1


def test_call_llm_distinguishes_429_from_failure(monkeypatch):
    """_call_llm returns the _RATE_LIMITED sentinel on 429 and None on a real
    failure. Collapsing them loses the difference between "retry later" and
    "this item is bad"."""
    pytest.importorskip("psycopg2")
    sys.path.insert(0, os.path.join(REPO, "news_runner"))
    import news_agent  # type: ignore

    class _R429:
        status_code = 429
        text = '{"error":{"code":"RateLimitReached"}}'

        def raise_for_status(self):
            raise AssertionError("must not raise before the 429 check")

    monkeypatch.setattr(news_agent.requests, "post", lambda *a, **kw: _R429())
    assert news_agent._call_llm("p") is news_agent._RATE_LIMITED

    class _Boom:
        status_code = 200

        def raise_for_status(self):
            raise RuntimeError("connection reset")

    monkeypatch.setattr(news_agent.requests, "post", lambda *a, **kw: _Boom())
    assert news_agent._call_llm("p") is None


def test_news_has_its_own_model_knob():
    """News must be able to run a different (cheaper or local) model than the
    agents -- that is the point of NEWS_LLM_MODEL."""
    src = io.open(os.path.join(REPO, "news_runner", "news_agent.py"),
                  encoding="utf-8").read()
    assert "NEWS_LLM_MODEL" in src
    assert '"model": NEWS_LLM_MODEL' in src, (
        "the per-consumer model is declared but not actually sent"
    )
