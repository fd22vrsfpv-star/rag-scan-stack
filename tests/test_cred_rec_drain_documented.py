"""The langgraph session's recommend-but-don't-run divergence must stay documented.

Run on demand:

    pytest tests/test_cred_rec_drain_documented.py -v

WHY THIS EXISTS
---------------
`autogen_agents/langgraph_engine.py` INSERTs pending `scan_recommendations`
rows (post-access playbook steps, `_enumerate_post_access`) but the session
deliberately does NOT auto-dispatch them from inside the graph — draining
pending rows is the BFF recon-agent loop's job
(`dashboard/bff/services/recon_agent.py`, via
`dashboard/bff/routers/assets.py::run_scan_recommendations`), or an operator's.
Unattended wordlist/brute (`start_brutus`) dispatch is withheld on purpose
(account-lockout risk is an operator policy call).

That split is correct, but from the outside "recommended but not run" reads as
a bug — it was filed as one (OPEN_ITEMS: "A langgraph session never drains
pending credential recommendations"). This guard pins the explanatory comment
in place so the intent cannot silently vanish and get re-filed a fourth time.

SABOTAGE PROOF
--------------
Delete the "DIVERGENCE (recommended-but-not-run is INTENTIONAL)" comment above
the `INSERT INTO scan_recommendations` (or in the deterministic credential
block) and the matching assertion below fails.
"""
import ast
import os

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
ENGINE = os.path.join(REPO, "autogen_agents", "langgraph_engine.py")

MARKER = "DIVERGENCE (recommended-but-not-run is INTENTIONAL)"


def _read(path):
    if not os.path.exists(path):
        pytest.skip(f"{path} not present")
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def test_engine_source_is_parseable():
    """A guard that documents behaviour is worthless if the module it guards
    no longer parses."""
    ast.parse(_read(ENGINE))


def test_insert_site_documents_the_divergence():
    """The scan_recommendations INSERT must be preceded by the divergence note,
    so a reader sees the queue-only behaviour is deliberate, not a missed POST."""
    src = _read(ENGINE)
    idx = src.find("INSERT INTO scan_recommendations")
    assert idx != -1, "the scan_recommendations INSERT is gone — re-audit this guard"
    # The explanatory comment sits in the window immediately above the INSERT.
    window = src[max(0, idx - 2600):idx]
    assert MARKER in window, (
        "the divergence comment above the scan_recommendations INSERT is gone — "
        "'recommended but not run' will read as a bug and be re-filed")
    assert "recon_agent" in window or "run_scan_recommendations" in window, (
        "the comment no longer names the BFF recon-agent loop as the drainer, so "
        "it does not say WHOSE job draining actually is")


def test_credential_block_documents_the_divergence():
    """The deterministic credential block must say it does checking only and does
    NOT fire start_brutus / drain pending rows unattended."""
    src = _read(ENGINE)
    idx = src.find("DETERMINISTIC credential testing")
    assert idx != -1, "the deterministic credential block is gone — re-audit this guard"
    window = src[idx:idx + 1400]
    assert MARKER in window, (
        "the deterministic credential block no longer documents that it checks "
        "credentials only and does not auto-dispatch brute/pending work")
    assert "start_brutus" in window, (
        "the note no longer names start_brutus as the intentionally-withheld "
        "unattended dispatch")
