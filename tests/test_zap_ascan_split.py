"""The ZAP active scan runs as per-category passes, not one monolith.

Run on demand:

    pytest tests/test_zap_ascan_split.py -v

WHY THIS EXISTS
---------------
A single active scan is all-or-nothing. When one rule wedges or blows up memory,
the whole scan dies and every rule after it never runs. Measured: DomXssScanRule
drove ZAP from 2.34 GiB to 11.93 GiB in 78 seconds and killed a scan that still
had categories left to execute.

ZAP already partitions every active-scan rule into five policy CATEGORIES, so
that is the unit to split on — no bespoke rule list to maintain, and
`ascan.setEnabledPolicies` gates them directly. Verified live against 2.16.1:

    0 Information Gathering   2 Server Security   3 Miscellaneous
    1 Client Browser                              4 Injection

Two properties carry the whole design, and each has a test below:

* **Client Browser runs LAST.** It is the pass that launches a real browser
  (DomXssScanRule -> Firefox via Selenium) and is by far the likeliest to fail.
  Running it first would put everything else behind the riskiest work.
* **Findings are banked between passes.** Otherwise a later category that kills
  ZAP takes the earlier passes' results with it, which is precisely what
  splitting is supposed to prevent.

Static — no ZAP needed, runs in CI.

Sabotage checks:
  - move Client Browser off the end of ZAP_ASCAN_CATEGORIES -> RED
  - drop the between-pass drain -> RED
  - let a failing pass raise instead of returning -> RED
"""
import ast
import os

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
WEB_SCAN = os.path.join(REPO, "web_scanner", "web_scan.py")

#: ZAP's own policy ids, read live from ascan/view/policies on 2.16.1.
ZAP_POLICY_IDS = {0: "Information Gathering", 1: "Client Browser",
                  2: "Server Security", 3: "Miscellaneous", 4: "Injection"}


def _src():
    if not os.path.exists(WEB_SCAN):
        pytest.skip("web_scan.py not present")
    return open(WEB_SCAN, encoding="utf-8").read()


def _node(src, name):
    for n in ast.walk(ast.parse(src)):
        if isinstance(n, (ast.FunctionDef, ast.ClassDef)) and n.name == name:
            return ast.get_source_segment(src, n) or ""
    raise AssertionError(f"{name} not found — this guard would pass vacuously")


def _categories():
    """The declared pass order, as [(id, label), ...]."""
    for n in ast.walk(ast.parse(_src())):
        if (isinstance(n, ast.Assign)
                and any(getattr(t, "id", "") == "ZAP_ASCAN_CATEGORIES"
                        for t in n.targets)):
            return ast.literal_eval(n.value)
    raise AssertionError("ZAP_ASCAN_CATEGORIES not found")


def test_categories_match_zaps_own_policy_ids():
    """A wrong id silently scans the wrong category — ZAP does not complain."""
    cats = _categories()
    assert len(cats) == len(ZAP_POLICY_IDS), (
        f"{len(cats)} categories declared, ZAP has {len(ZAP_POLICY_IDS)} — a "
        "missing one is rules that never run"
    )
    for pid, label in cats:
        assert pid in ZAP_POLICY_IDS, f"policy id {pid} is not one of ZAP's"
        assert ZAP_POLICY_IDS[pid] == label, (
            f"id {pid} is labelled {label!r} but ZAP calls it "
            f"{ZAP_POLICY_IDS[pid]!r} — the log would name the wrong pass"
        )
    assert len({p for p, _ in cats}) == len(cats), "a policy id is repeated"


def test_client_browser_runs_last():
    """The riskiest pass must not block the cheap reliable ones."""
    cats = _categories()
    assert cats[-1][1] == "Client Browser", (
        f"pass order ends with {cats[-1][1]!r}. Client Browser launches a real "
        "browser (DomXssScanRule -> Firefox) and is the likeliest to kill ZAP; "
        "anything after it may never run"
    )


def test_findings_are_banked_between_passes():
    body = _node(_src(), "_zap_scan_with_urls_inner")
    assert 'drain_zap_alerts(url, label=f"after {label}")' in body, (
        "no drain between category passes — a later pass that kills ZAP takes "
        "the earlier passes' findings with it, which is the thing splitting "
        "is supposed to prevent"
    )


def test_a_failing_pass_does_not_abort_the_remaining_passes():
    """Isolation is the entire point; a raise would re-couple them."""
    body = _node(_src(), "_run_active_pass")
    assert "return 0, False" in body, (
        "_run_active_pass raises instead of reporting failure, so one bad "
        "category still kills every category after it"
    )
    assert "except Exception" in body


def test_each_pass_is_individually_bounded():
    """One slow category must not eat the whole window."""
    body = _node(_src(), "_zap_scan_with_urls_inner")
    assert "per_pass" in body and "max_wait / max(len(cats), 1)" in body, (
        "passes are not given an equal share of the budget, so a slow early "
        "category starves the rest"
    )


def test_policies_are_restored_however_the_scan_ends():
    """Policy enablement is SERVER-global and outlives the scan.

    Leaving a subset enabled silently narrows every later scan in this ZAP —
    invisible from the outside, exactly like the passive-scan case.
    """
    body = _node(_src(), "ascan_policies_restored")
    assert "finally" in body, "policies are not restored on the error path"
    assert "set_enabled_policies" in body
    assert "before or " in body, (
        "an unreadable 'before' leaves a partial policy set enabled forever; "
        "fall back to all categories instead"
    )
    assert "logger.error" in body, (
        "a failed restore is logged below error, so a permanently narrowed "
        "scanner looks like a quiet scan"
    )


def test_split_is_switchable():
    src = _src()
    assert 'os.environ.get("ZAP_ASCAN_SPLIT"' in src, "no env switch for the split"
    body = _node(src, "_zap_scan_with_urls_inner")
    assert "if not _split:" in body, (
        "the single-pass path is gone — there is no way back to the previous "
        "behaviour if splitting turns out to cost too much wall-clock"
    )
