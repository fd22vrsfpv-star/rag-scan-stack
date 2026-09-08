"""ZAP passive-scan tuning: the levers that exist, and the one that does not.

Run on demand:

    pytest tests/test_zap_pscan_tuning.py -v

WHY THIS EXISTS
---------------
ZAP's passive scanner runs every enabled rule against EVERY message it sees, on
a bounded thread pool fed by an UNBOUNDED queue holding whole HTTP messages.
When one rule is slow the queue is what grows, so the failure is a memory sink,
not a CPU one. Raising the heap 3g -> 8g therefore did nothing: ZAP grew to
11.98 GiB and died at the same point in the scan.

Measured on demo.testfire.net: 327 "Passive Scan rule ... took N seconds"
warnings, every single one naming "Tech Detection Passive Scanner", at 40-51
seconds per message.

THE THING THIS FILE MOSTLY GUARDS
---------------------------------
`pscan.disableScanners` CANNOT disable that rule, and the API gives no hint of
it — it returns {"Result":"OK"} for an id it has never heard of. Verified live
against ZAP 2.16.1: `pscan.scanners` lists 70 rules and none matches "tech" or
"wappalyzer", because the add-on manifest (wappalyzer-release-21.50.0) declares
only <extensions> and no <pscanrules>, so the scanner is registered directly as
a raw PassiveScanner with no rule id to address.

So an unvalidated id list is a disable that silently does nothing — the exact
"unreachable reported as absent" failure this repo keeps re-learning. The guard
below pins the validation, not just the call.

Static — no ZAP needed, runs in CI.

Sabotage checks:
  - drop the `pscan.scanners` validation from apply_zap_tuning -> RED
  - swap the `with pscan_paused(...)` back to a bare enter/exit pair -> RED
  - default ZAP_PSCAN_DURING_ACTIVE_SCAN to "true" -> RED
"""
import ast
import os

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
WEB_SCAN = os.path.join(REPO, "web_scanner", "web_scan.py")
PIPELINE = os.path.join(REPO, "web_scanner", "scan_pipeline.py")


def _src(path=WEB_SCAN):
    if not os.path.exists(path):
        pytest.skip(f"{os.path.basename(path)} not present")
    return open(path, encoding="utf-8").read()


def _node(src, name):
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name == name:
            return ast.get_source_segment(src, node) or ""
    raise AssertionError(f"{name} not found — this guard would pass vacuously")


# ── the levers exist and are the real API names ───────────────────────────────

def test_tuning_uses_zap_api_names_that_actually_exist():
    """Every method named here was called live against ZAP 2.16.1 and returned OK.

    A typo'd client method is an AttributeError at scan time, in a background
    task, on the phase that only runs against a real target.
    """
    body = _node(_src(), "apply_zap_tuning")
    for call in ("disable_scanners", "set_scan_only_in_scope", "set_max_alerts_per_rule"):
        assert f"pscan.{call}" in body, f"apply_zap_tuning never calls pscan.{call}"


def test_pause_uses_set_enabled():
    assert "pscan.set_enabled" in _node(_src(), "pscan_paused")


# ── the validation that stops a silent no-op ──────────────────────────────────

def test_rule_ids_are_validated_against_zaps_own_registry():
    """disableScanners returns OK for ids ZAP does not know.

    Without this check a typo, or an attempt to disable Tech Detection by
    guessing an id, is a rule that stays enabled while the log says it was
    disabled.
    """
    body = _node(_src(), "apply_zap_tuning")
    assert "pscan.scanners" in body, (
        "rule ids are passed to ZAP unvalidated; an unknown id is accepted with "
        "OK and silently does nothing"
    )
    assert "unknown" in body.lower(), "unknown ids are dropped without being reported"


def test_the_tech_detection_limitation_is_written_down():
    """The next person WILL try to disable it by rule id. Say so where they look."""
    src = _src()
    assert "Tech Detection" in src, (
        "nothing records that Tech Detection has no rule id — this gets "
        "re-derived from a failed scan every time"
    )


# ── defaults ──────────────────────────────────────────────────────────────────

def test_passive_scanning_is_off_during_the_active_scan_by_default():
    """The lever that actually reaches Tech Detection.

    The active scan is the phase that generates the message volume that
    overruns the passive queue. The crawl's passive findings are already banked
    by the post-spider drain, so pausing here costs passive coverage of
    active-scan traffic only — and keeps the add-on installed, which
    uninstalling wappalyzer does not.
    """
    src = _src()
    line = [l for l in src.splitlines() if "ZAP_PSCAN_DURING_ACTIVE_SCAN" in l
            and "environ" in l]
    assert line, "ZAP_PSCAN_DURING_ACTIVE_SCAN has no env default"
    assert '"false"' in line[0], (
        f"default is not false ({line[0].strip()!r}) — the memory fix is off by "
        "default and scans will keep dying"
    )


def test_defaults_are_overridable_per_scan():
    """Every field defaults to None = 'use the env default'.

    A field defaulting to a concrete value would change the shape of scans that
    never asked for tuning.
    """
    body = _node(_src(), "ZapTuning")
    for field in ("disable_pscan_rules", "pscan_only_in_scope",
                  "max_alerts_per_rule", "pscan_during_active_scan"):
        assert f"{field}: Optional" in body, f"{field} is not optional"
        assert f"{field}: Optional[List[str]] = None" in body or \
               f"{field}: Optional[bool] = None" in body or \
               f"{field}: Optional[int] = None" in body, \
               f"{field} does not default to None"


# ── restoration ───────────────────────────────────────────────────────────────

def test_pausing_is_exception_safe():
    """A scan that raises must not leave ZAP deaf for the NEXT scan.

    Passive scanning is process-wide state on a long-lived ZAP. Restoring it
    only on the happy path means one failed scan silently costs every passive
    finding until someone restarts the container.
    """
    body = _node(_src(), "pscan_paused")
    assert "finally" in body, "passive scanning is not restored on the error path"

    inner = _node(_src(), "_zap_scan_with_urls_inner")
    assert "with pscan_paused(" in inner, (
        "the active scan does not use pscan_paused as a context manager — a "
        "hand-rolled enter/exit pair skips the exit when the loop raises"
    )
    assert "__exit__" not in inner, (
        "a manual __exit__ call is not exception-safe; use `with`"
    )


def test_a_failed_restore_is_loud():
    body = _node(_src(), "pscan_paused")
    assert "logger.error" in body, (
        "failing to re-enable passive scanning is logged below error, so a "
        "session-wide capability loss looks like a quiet scan"
    )


# ── plumbing ──────────────────────────────────────────────────────────────────

def test_tuning_reaches_the_scan_from_both_routes():
    src = _src()
    assert "zap_tuning: Optional[ZapTuning] = None" in src, (
        "no request model accepts zap_tuning, so the API cannot set it"
    )
    inner = _node(src, "_zap_scan_with_urls_inner")
    assert "apply_zap_tuning(zap" in inner, "the scan never applies the tuning"

    pipe = _src(PIPELINE)
    assert "tuning=getattr(self" in pipe, (
        "the pipeline's ZAP stage drops the tuning, so pipeline scans keep the "
        "old behaviour while web-scan gets the fix"
    )


def test_tuning_is_applied_before_any_traffic():
    """Settings applied after seeding would miss the messages already queued."""
    inner = _node(_src(), "_zap_scan_with_urls_inner")
    assert inner.index("apply_zap_tuning(zap") < inner.index("zap.urlopen("), (
        "tuning is applied after seeding — the seeded messages are passive-"
        "scanned under the old settings"
    )


def test_a_rejected_setting_does_not_abort_the_scan():
    body = _node(_src(), "apply_zap_tuning")
    assert "except Exception" in body, (
        "one unsupported setting would fail the whole scan; a worse-tuned scan "
        "is better than no scan"
    )
