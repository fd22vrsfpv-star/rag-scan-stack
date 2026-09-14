"""Generic output-vs-findings reconciliation for every scan ingest.

Run on demand:

    pytest tests/test_ingest_reconciliation.py -v

WHY THIS EXISTS
---------------
A credential check reported 11 valid while only 8 became findings and nothing
flagged it. The fix was generalised: every `/ingest/*` endpoint funnels through
`_emit_ingest_event(tool, stats)`, which now runs `etl.reconcile.reconcile_ingest`
so ANY scan whose parser dropped records to errors / non-dedup skips is surfaced
(a `scan_count_mismatch` webhook), for nmap / nuclei / zap / nessus / brutus alike.

The hard part is NOT flagging legitimate reduction: dedup and scope/false-positive
filtering routinely make stored < seen, and `total` > `inserted` is dedup, not
loss. So the signal is the parser's OWN report of records it could not process
(errors, non-dedup skips), never a raw count comparison.

SABOTAGE PROOF
--------------
* Add "duplicate" handling to the `error`/`skip` branch (so dedup counts as a
  drop) and test_dedup_is_not_a_loss fails.
* Remove the `_emit_ingest_event` call to reconcile_ingest and
  test_ingest_chokepoint_reconciles fails.
"""
import ast
import os

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
API = os.path.join(REPO, "app", "rag-api", "api.py")

import sys
sys.path.insert(0, REPO)
from etl.reconcile import normalize_ingest_stats, reconcile_ingest  # noqa: E402


# ── The loss signal fires on errors / non-dedup skips ────────────────────────

def test_errors_are_a_loss():
    assert not reconcile_ingest("nuclei", {"total": 10, "inserted": 7, "errors": 3})["matched"]
    # errors as a LIST (nmap/zap/nessus report it that way) counts too
    assert not reconcile_ingest("nmap", {"ports": 25, "errors": ["bad row", "xml"]})["matched"]


def test_nondedup_skip_is_a_loss():
    assert not reconcile_ingest("brutus",
        {"records_seen": 11, "credentials_found": 8, "skipped": 3, "errors": 0})["matched"]
    assert not reconcile_ingest("nessus",
        {"ports": 5, "vulns": 5, "skipped_zero_port": 2, "errors": []})["matched"]


def test_total_ingestion_failure_is_flagged():
    # output had records, nothing stored, nothing deduped, no errors reported
    r = reconcile_ingest("subfinder", {"total": 5, "inserted": 0, "errors": 0})
    assert not r["matched"]
    assert any("none were stored" in x for x in r["reasons"])


# ── Legitimate reduction must NOT flag (the whole difficulty) ─────────────────

def test_dedup_is_not_a_loss():
    # nuclei dedups: total 10 > inserted 7, no errors — MATCH
    assert reconcile_ingest("nuclei", {"total": 10, "inserted": 7, "errors": 0})["matched"]
    # zap: duplicate + false-positive + out-of-scope are all legitimate
    r = reconcile_ingest("zap", {"total_alerts": 40, "inserted": 12,
                                 "skipped_duplicate": 25, "skipped_false_positive": 3,
                                 "out_of_scope": 0, "errors": []})
    assert r["matched"], r["reasons"]
    assert r["deduped"] == 28


def test_clean_ingest_matches():
    assert reconcile_ingest("brutus",
        {"records_seen": 8, "credentials_found": 8, "skipped": 0, "errors": 0})["matched"]


def test_normalizer_folds_heterogeneous_keys():
    n = normalize_ingest_stats({"total_alerts": 40, "inserted": 12,
                                "skipped_duplicate": 25, "errors": ["a", "b"]})
    assert n["seen"] == 40 and n["stored"] == 12
    assert n["deduped"] == 25 and n["dropped"] == 2


# ── The shared chokepoint actually calls it ──────────────────────────────────

def test_ingest_chokepoint_reconciles():
    src = open(API, encoding="utf-8").read()
    tree = ast.parse(src)
    fn = next((n for n in ast.walk(tree)
               if isinstance(n, ast.FunctionDef) and n.name == "_emit_ingest_event"), None)
    assert fn, "_emit_ingest_event not found — guard is stale"
    body = ast.get_source_segment(src, fn)
    assert "reconcile_ingest" in body, (
        "_emit_ingest_event must run reconcile_ingest so every scan type is "
        "reconciled at the shared ingest chokepoint")
    assert "scan_count_mismatch" in body, (
        "a mismatch must emit a scan_count_mismatch webhook, not pass silently")
