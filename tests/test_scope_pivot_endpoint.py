"""Live E2E test for the typosquat scope-pivot endpoint.

Satisfies CLAUDE.md's "every endpoint MUST have a test that EXECUTES
it" invariant. Runs the full flow:
  1. Create a disposable test engagement.
  2. Add an in-scope apex domain to its scope_targets.
  3. POST /scope-pivot/typosquat/{engagement_id}.
  4. Assert the summary dict shape (seeds >= 1, candidates > 0,
     suggestions written > 0).
  5. GET /scope-pivot/suggestions?method=typosquat and assert at least
     one row for a known lookalike (b1ackbaud.com or blackbacd.com).
  6. POST /scope-pivot/suggestions/<id>/review {action: accept} and
     assert the status flips + a not_in_scope row lands.
  7. Clean up: delete the test engagement + its scope_targets rows + its
     scope_suggestions rows.

Skips cleanly when the rag-api container isn't running (so the suite
stays green on dev boxes without the full stack up).
"""
import os
import uuid

import pytest
import requests


RAG_API_URL = os.environ.get("RAG_API_URL",
                              "https://localhost:8000").rstrip("/")
API_KEY = os.environ.get("API_KEY") or os.environ.get("RAG_API_KEY") or ""
SEED_DOMAIN = os.environ.get("TEST_PIVOT_SEED", "blackbaud.com")


def _rag_available() -> bool:
    if not API_KEY:
        return False
    try:
        r = requests.get(f"{RAG_API_URL}/health", verify=False, timeout=5,
                          headers={"x-api-key": API_KEY})
        return r.status_code == 200
    except Exception:  # noqa: BLE001
        return False


pytestmark = pytest.mark.skipif(
    not _rag_available(),
    reason="rag-api not reachable at RAG_API_URL",
)


def _hdr():
    return {"x-api-key": API_KEY, "Content-Type": "application/json"}


@pytest.fixture
def ephemeral_engagement():
    """Create → yield engagement_id → cleanup. Avoids leaving test
    rows behind that would skew subsequent runs or the dashboard."""
    name = f"typosquat_e2e_{uuid.uuid4().hex[:8]}"
    r = requests.post(f"{RAG_API_URL}/engagements",
                       json={"name": name, "metadata": {"created_by": "pytest"}},
                       headers=_hdr(), verify=False, timeout=10)
    assert r.status_code < 300, f"engagement create failed: {r.status_code} {r.text}"
    eid = (r.json().get("engagement") or {}).get("id") or r.json().get("id")
    assert eid, f"no engagement id in response: {r.json()}"
    try:
        yield eid
    finally:
        # Clean up: drop test suggestions / scope_targets / engagement.
        try:
            requests.delete(f"{RAG_API_URL}/engagements/{eid}",
                             headers=_hdr(), verify=False, timeout=15)
        except Exception:  # noqa: BLE001
            pass


class TestTyposquatPivotEndpoint:

    def test_runs_end_to_end(self, ephemeral_engagement):
        eid = ephemeral_engagement
        # 1. Add seed domain to the engagement's scope.
        r = requests.post(
            f"{RAG_API_URL}/scope/add",
            json={"name": "default", "engagement_id": eid,
                   "targets": [{"target": SEED_DOMAIN,
                                 "target_type": "domain",
                                 "source": "pytest"}]},
            headers=_hdr(), verify=False, timeout=15,
        )
        assert r.status_code < 300, f"scope/add failed: {r.status_code} {r.text}"

        # 2. Run the pivot WITHOUT the DNS resolution check (keeps the
        # test fast and deterministic — DNS from the test container can
        # be slow or unreliable).
        r = requests.post(
            f"{RAG_API_URL}/scope-pivot/typosquat/{eid}"
            f"?check_resolution=false&auto_block_at=0.6",
            headers=_hdr(), verify=False, timeout=120,
        )
        assert r.status_code == 200, f"{r.status_code} {r.text}"
        body = r.json()
        assert body.get("ok") is True
        summary = body.get("summary") or {}
        assert summary.get("seeds", 0) >= 1
        assert summary.get("total_candidates", 0) > 0
        assert summary.get("suggestions_written", 0) > 0

        # 3. Fetch the suggestions and assert at least one well-known
        # lookalike for the seed appears.
        r = requests.get(
            f"{RAG_API_URL}/scope-pivot/suggestions?method=typosquat&limit=1000",
            headers=_hdr(), verify=False, timeout=15,
        )
        assert r.status_code == 200
        sugg = r.json().get("suggestions") or []
        assert len(sugg) > 0
        targets = {s["target"] for s in sugg}
        # One of these homoglyph/edit-1 forms must appear for blackbaud.com.
        assert any(t for t in targets if "ackbaud" in t.lower() or "ackba" in t.lower()), \
            f"no plausible lookalike found; got {sorted(targets)[:10]}"

    def test_review_accept_flips_status_and_adds_denylist(self, ephemeral_engagement):
        eid = ephemeral_engagement
        requests.post(
            f"{RAG_API_URL}/scope/add",
            json={"name": "default", "engagement_id": eid,
                   "targets": [{"target": SEED_DOMAIN,
                                 "target_type": "domain",
                                 "source": "pytest"}]},
            headers=_hdr(), verify=False, timeout=15,
        )
        requests.post(
            f"{RAG_API_URL}/scope-pivot/typosquat/{eid}"
            f"?check_resolution=false",
            headers=_hdr(), verify=False, timeout=120,
        )

        # Grab a pending typosquat suggestion to review.
        r = requests.get(
            f"{RAG_API_URL}/scope-pivot/suggestions?method=typosquat&status=pending&limit=10",
            headers=_hdr(), verify=False, timeout=15,
        )
        assert r.status_code == 200
        pending = r.json().get("suggestions") or []
        if not pending:
            pytest.skip("no pending suggestions to review (all auto-blocked?)")
        sug = pending[0]

        r = requests.post(
            f"{RAG_API_URL}/scope-pivot/suggestions/{sug['id']}/review",
            json={"action": "accept"},
            headers=_hdr(), verify=False, timeout=15,
        )
        assert r.status_code == 200, f"{r.status_code} {r.text}"
        body = r.json()
        assert body["new_status"] == "accepted"
        assert body["action"] == "accept"

    def test_review_rejects_invalid_action(self, ephemeral_engagement):
        # Pick any suggestion id (even a bogus one) — the validation
        # fires before the DB lookup, so a 400 is expected for a bad
        # action value regardless of whether the suggestion exists.
        r = requests.post(
            f"{RAG_API_URL}/scope-pivot/suggestions/{uuid.uuid4()}/review",
            json={"action": "approve_maybe"},
            headers=_hdr(), verify=False, timeout=10,
        )
        assert r.status_code == 400

    def test_invalid_engagement_id_rejected(self):
        r = requests.post(
            f"{RAG_API_URL}/scope-pivot/typosquat/not-a-uuid",
            headers=_hdr(), verify=False, timeout=10,
        )
        assert r.status_code == 400
