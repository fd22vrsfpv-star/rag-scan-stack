"""Post-review re-runs must be an operator CHOICE between "queue for review" and
"queue for dispatch", not a code default that auto-dispatches.

Regression (Docs/OPEN_ITEMS.md): propose_reruns wrote status='pending', and the
recon-agent drain selects every 'pending' row regardless of source — so a
post-review proposal was dispatched 29 minutes after being queued, with no row in
tool_executions. The endpoint even claimed "a human still presses Run".

These are structural guards (the insert path is DB-heavy): they pin that re-runs
default to a HELD status, that a conflict only promotes a held row (never resets a
completed one), and that the drain does not dispatch held rows. Each fails if the
fix is reverted.
"""
from pathlib import Path

ROOT = Path(__file__).parent.parent
AGENT = ROOT / "app" / "rag-api" / "post_review_agent.py"
RECON = ROOT / "dashboard" / "bff" / "services" / "recon_agent.py"


def test_reruns_default_to_hold_for_review():
    src = AGENT.read_text()
    assert "hold_for_review=True" in src, "re-runs no longer default to held-for-review"
    assert 'rec_status = "review" if hold_for_review else "pending"' in src, (
        "the held vs dispatch status is not driven by hold_for_review")


def test_conflict_only_promotes_a_held_row():
    src = AGENT.read_text()
    # Promote 'review' -> the new status on an operator dispatch, but never reset a
    # row that already ran or is queued.
    assert "status = CASE WHEN scan_recommendations.status = 'review'" in src, (
        "an ON CONFLICT that unconditionally set status could re-dispatch "
        "completed work")


def test_endpoint_exposes_the_dispatch_choice():
    api = (ROOT / "app" / "rag-api" / "api.py").read_text()
    assert "dispatch_reruns" in api, (
        "the operator has no way to choose dispatch over review")


def test_recon_drain_does_not_dispatch_held_rows():
    src = RECON.read_text()
    assert "sr.status = 'pending'" in src, "the drain no longer filters to pending"
    # A held row is status='review'; the drain must not pick it up.
    assert "sr.status = 'review'" not in src, (
        "the drain would dispatch held-for-review rows")
