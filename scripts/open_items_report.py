#!/usr/bin/env python3
"""Monitor Docs/OPEN_ITEMS.md and report what can be burned down.

WHY REPORT-ONLY. That file exists because findings were lost — the credential
phase being unreachable, post-ex never running and the manual approve path
recording no reviewer were each noticed and forgotten more than once. An agent
that CLOSES an item it could not verify would reintroduce exactly that, with
more confidence and less paper trail. So this proposes; a human disposes, and
CLAUDE.md's rule stands: resolved items are deleted by hand, git keeps the
record.

THREE OUTCOMES per item, never two:

    close_candidate   its enforcing test now PASSES, so either the item is
                      fixed or its evidence has gone stale. Both need a human
                      to look; neither is "still broken".
    still_open        its enforcing test FAILS — the item is live and the
                      guard is doing its job.
    unverifiable      `Enforced by: not enforced`, or the test could not run
                      here. NOT the same as "fine": it means nothing would
                      tell us if this regressed or resolved.

An item whose test cannot RUN is never reported as a close candidate. "Could
not check" and "checked and clean" are different answers.

    python3 scripts/open_items_report.py            # human-readable
    python3 scripts/open_items_report.py --json     # for an endpoint/panel
    python3 scripts/open_items_report.py --no-run   # parse only, no pytest
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OPEN_ITEMS = os.path.join(REPO, "Docs", "OPEN_ITEMS.md")

_FIELD = re.compile(r"\*\*(Found|Evidence|Where|Done when|Enforced by)[:\*]*\*\*\s*(.+?)"
                    r"(?=\n\*\*|\Z)", re.S)
_TESTS = re.compile(r"(tests/[\w/]+\.py)(?:::([\w\[\]:.-]+))?")
_NOT_ENFORCED = re.compile(r"\bnot\s+enforced\b", re.I)

CLOSE, OPEN, UNVERIFIABLE = "close_candidate", "still_open", "unverifiable"


def parse(path=OPEN_ITEMS) -> list:
    """Items with their declared fields, and the section each sits under.

    THE FILE IS TWO LEVELS. `##` are sections — several are pure containers
    ("Vector coverage", "Access reconnection") — and `###` are the items.
    Splitting on `##` alone counted 11 "items" when there are 32, and handed
    each section the fields of its FIRST child, so an entry about a sentinel
    value was reported with evidence about news ingest. A heading only counts
    as an item when it actually declares a field; a container does not.

    A heading WITH fields but missing some is still an item — a malformed
    entry has to be visible, not skipped, which is the whole point of the
    format check.
    """
    try:
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
    except OSError as e:
        return [{"title": "(OPEN_ITEMS unreadable)", "error": str(e), "fields": {},
                 "section": None}]
    out, section = [], None
    # Split on any heading, keeping the heading with its body.
    for block in re.split(r"\n(?=#{2,3} )", text):
        m = re.match(r"(#{2,3}) (.+)", block)
        if not m:
            continue
        level, title = len(m.group(1)), m.group(2).strip()
        body = block[len(m.group(0)):]
        if level == 2:
            section = title
        # Fields BEFORE the next heading only — a section must not inherit
        # its first child's fields.
        head = re.split(r"\n#{2,3} ", body)[0]
        fields = {k.lower(): " ".join(v.split()) for k, v in _FIELD.findall(head)}
        if not fields:
            continue        # a container, or the preamble
        out.append({"title": title, "fields": fields, "raw": block,
                    "section": section if level == 3 else None})
    return out


def tests_named(item) -> list:
    """(file, nodeid-or-None) pairs from `Enforced by`."""
    enf = item.get("fields", {}).get("enforced by", "")
    if not enf or _NOT_ENFORCED.search(enf):
        return []
    return [(m.group(1), m.group(2)) for m in _TESTS.finditer(enf)]


def run_tests(pairs, timeout=900) -> dict:
    """{passed, ran, detail}. `ran` False means we could not check — which is
    never reported as a clean result."""
    if not pairs:
        return {"ran": False, "passed": None, "detail": "no test named"}
    targets = [f"{f}::{n}" if n else f for f, n in pairs]
    missing = [f for f, _ in pairs if not os.path.exists(os.path.join(REPO, f))]
    if missing:
        return {"ran": False, "passed": None,
                "detail": "named test file does not exist: %s" % ", ".join(missing)}
    try:
        p = subprocess.run([sys.executable, "-m", "pytest", "-q", *targets],
                           cwd=REPO, capture_output=True, text=True, timeout=timeout,
                           env={**os.environ, "PYTHONPATH": REPO + ":" + os.path.join(REPO, "tests")})
    except FileNotFoundError:
        return {"ran": False, "passed": None, "detail": "pytest is not available here"}
    except subprocess.TimeoutExpired:
        return {"ran": False, "passed": None, "detail": "timed out"}
    tail = (p.stdout or p.stderr or "").strip().splitlines()
    return {"ran": True, "passed": p.returncode == 0,
            "detail": tail[-1][:200] if tail else "exit %d" % p.returncode}


def classify(item, result) -> tuple:
    enf = item.get("fields", {}).get("enforced by", "")
    if not enf:
        return UNVERIFIABLE, "no `Enforced by` field — the format requires one"
    if _NOT_ENFORCED.search(enf):
        return UNVERIFIABLE, "declared `not enforced`: nothing fails while this is open"
    if not result.get("ran"):
        return UNVERIFIABLE, "could not check: %s" % result.get("detail")
    if result.get("passed"):
        return CLOSE, ("its enforcing test PASSES — the item is fixed, or its "
                       "evidence is stale. Re-verify, then delete or rewrite.")
    return OPEN, "its enforcing test fails, as it should while the item is open"


def report(run=True) -> dict:
    items = parse()
    out = []
    for it in items:
        pairs = tests_named(it)
        res = run_tests(pairs) if (run and pairs) else {
            "ran": False, "passed": None,
            "detail": "not run" if pairs else "no test named"}
        state, why = classify(it, res)
        out.append({"title": it["title"], "state": state, "why": why,
                    "tests": [f"{f}::{n}" if n else f for f, n in pairs],
                    "found": it["fields"].get("found"),
                    "evidence": (it["fields"].get("evidence") or "")[:300],
                    "test_result": res})
    counts = {s: sum(1 for o in out if o["state"] == s)
              for s in (CLOSE, OPEN, UNVERIFIABLE)}
    return {"items": out, "counts": counts, "total": len(out)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--no-run", action="store_true")
    a = ap.parse_args()
    rep = report(run=not a.no_run)
    if a.json:
        print(json.dumps(rep, indent=2))
        return 0
    c = rep["counts"]
    print("OPEN ITEMS: %d total — %d close candidates, %d still open, %d unverifiable"
          % (rep["total"], c[CLOSE], c[OPEN], c[UNVERIFIABLE]))
    for group, label in ((CLOSE, "CLOSE CANDIDATES (verify, then delete or rewrite)"),
                         (OPEN, "STILL OPEN (guard is failing, as intended)"),
                         (UNVERIFIABLE, "UNVERIFIABLE (nothing would tell us either way)")):
        rows = [o for o in rep["items"] if o["state"] == group]
        if not rows:
            continue
        print("\n%s" % label)
        for o in rows:
            print("  - %s" % o["title"][:96])
            print("      %s" % o["why"])
            if o["tests"]:
                print("      tests: %s" % ", ".join(o["tests"])[:110])
    return 0


if __name__ == "__main__":
    sys.exit(main())
