"""2026-10-22: the vulnerable COMPONENT was derived and then thrown away.

Operator: "Glowlogix WP Frontend Profile WordPress plugin -- this is for PoC
CVE-2023-51483 and it doesn't seem to focus on this, the description wording is
key, but it seemed to ignore this."

They were right, and it is measurable. In `derived_cve_specs`, **21 of 35** rows
carry the correct component inside the `spec` JSON while the `product` COLUMN —
which everything downstream reads — says `unknown`:

    CVE-2023-51483  column='unknown'  json='Glowlogix WP Frontend Profile'
    CVE-2023-37999  column='unknown'  json='HasThemes HT Mega'
    CVE-2024-30542  column='unknown'  json='Wholesale WholesaleX'

Both INSERTs wrote the column from the SCANNED TARGET's fingerprint
("WordPress 6.8.3", or "unknown") rather than the spec's own product, and
neither ON CONFLICT clause updated `product` at all, so a stale 'unknown' could
never be replaced. Recon therefore pinned the platform and never probed
/wp-content/plugins/wp-frontend-profile/ or its AJAX action — the CVE-2023-51483
trace contains "glowlogix" 0 times and "wp-frontend-profile" 0 times.

Second operator ask: "if we land at unknown for product, we should loop back for
a deeper dig." The dig is deterministic and offline — the name is in prose we
already fetched.

    docker run --rm -v /opt/rag-scan-stack:/work:ro -w /work python:3.12-slim \
      sh -c 'pip install -q pytest && PYTHONPATH=. python -m pytest tests/test_spec_product_identity.py -v'
"""
from __future__ import annotations

import ast as _ast
import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
API = REPO / "app" / "rag-api" / "api.py"

# Real notes text from derived_cve_specs, CVE-2023-51483.
REAL_51483_NOTES = (
    "AUTO-DERIVED from advisory + patch diff. Evidence: Public advisory and "
    "consolidated brief state the plugin allows unauthenticated privilege "
    "escalation via an admin-ajax action that changes a user's role "
    "(e.g. action=wp_frontend_profile_change_role&user_id=2&role=administrator)."
)
# Real early deep-dive prose from the CVE-2023-51483 build trace.
REAL_51483_DEEPDIVE = (
    "The WP Frontend Profile plugin (<=1.3.1) contains an AJAX handler that "
    "performs user creation/updates and role assignment without any capability "
    "or authentication checks."
)


@pytest.fixture(scope="module")
def helpers():
    src = API.read_text()
    tree = _ast.parse(src)
    want = {"_mine_product_from_spec", "_spec_product", "_is_product_name"}
    chunks = [_ast.get_source_segment(src, n) for n in tree.body
              if isinstance(n, _ast.FunctionDef) and n.name in want]
    consts = [_ast.get_source_segment(src, n) for n in tree.body
              if isinstance(n, _ast.Assign)
              and any(getattr(t, "id", "") in ("_PRODUCT_UNKNOWN", "_NOT_A_PRODUCT")
                      for t in n.targets)]
    assert len(chunks) == 3, f"missing helpers: {want}"
    ns: dict = {"_poc_trace": lambda *a, **k: None}
    exec("\n\n".join(consts + chunks), ns)  # noqa: S102
    return ns


def test_the_specs_own_product_wins_over_the_platform(helpers):
    """The whole bug: 'WordPress' is where it lives, not what is broken."""
    out = helpers["_spec_product"]({"product": "Glowlogix WP Frontend Profile"},
                                   "WordPress")
    assert out == "Glowlogix WP Frontend Profile"


def test_a_stale_unknown_does_not_win(helpers):
    assert helpers["_spec_product"]({"product": "HasThemes HT Mega"},
                                    "unknown") == "HasThemes HT Mega"


@pytest.mark.parametrize("prose,expected", [
    (REAL_51483_DEEPDIVE, "WP Frontend Profile"),
    ("The Glowlogix WP Frontend Profile plugin allows privilege escalation.",
     "Glowlogix WP Frontend Profile"),
    ("A flaw in HasThemes HT Mega before 2.2.1 permits unauthenticated access.",
     "HasThemes HT Mega"),
    ("The Wholesale WholesaleX plugin for WordPress is vulnerable.",
     "Wholesale WholesaleX"),
])
def test_the_deeper_dig_reads_the_advisory_prose(helpers, prose, expected):
    """The operator's loop-back: when the product field is empty the name is
    almost always sitting in text we already fetched."""
    assert helpers["_mine_product_from_spec"]({"description": prose}) == expected


def test_the_dig_runs_when_the_product_field_is_empty(helpers):
    """End to end through _spec_product, on the REAL notes text."""
    out = helpers["_spec_product"]({"notes": REAL_51483_NOTES,
                                    "description": REAL_51483_DEEPDIVE},
                                   "WordPress")
    assert out == "WP Frontend Profile", out


def test_a_bare_platform_name_is_not_a_component(helpers):
    """'the WordPress plugin' names no component — returning 'WordPress' would
    just re-assert the fallback while looking like a finding."""
    assert helpers["_mine_product_from_spec"](
        {"description": "The WordPress plugin is vulnerable."}) == ""


def test_unknown_is_still_possible_and_honest(helpers):
    """No prose, no product, no fingerprint: say unknown rather than guess."""
    assert helpers["_spec_product"]({}, "") == "unknown"
    assert helpers["_spec_product"]({"notes": "A flaw permits access."},
                                    "unknown") == "unknown"
    assert helpers["_mine_product_from_spec"](None) == ""
    assert helpers["_mine_product_from_spec"]({"notes": ""}) == ""


def test_landing_on_unknown_is_traced(helpers):
    """It must be visible: an unidentified component is the single thing most
    likely to send recon at the wrong surface."""
    seen = []
    ns = dict(helpers)
    ns["_poc_trace"] = lambda rid, phase, **kw: seen.append(phase)
    # rebuild _spec_product against the instrumented trace
    src = API.read_text()
    fn = next(n for n in _ast.parse(src).body
              if isinstance(n, _ast.FunctionDef) and n.name == "_spec_product")
    exec(_ast.get_source_segment(src, fn), ns)  # noqa: S102 - deps already in ns
    assert ns["_spec_product"]({}, "unknown", cve="CVE-X", run_id="r1") == "unknown"
    assert "product_unknown_needs_dig" in seen, seen
    # and NOT traced when a product was found
    seen.clear()
    ns["_spec_product"]({"product": "Dolibarr"}, "unknown", cve="CVE-X", run_id="r1")
    assert seen == []


# --- the write path: a derived name must reach the column -------------------

def test_both_inserts_write_the_resolved_product():
    src = API.read_text()
    calls = [n for n in _ast.walk(_ast.parse(src))
             if isinstance(n, _ast.Call) and isinstance(n.func, _ast.Name)
             and n.func.id == "_spec_product"]
    assert len(calls) >= 2, \
        f"only {len(calls)} insert site(s) resolve the product; both must"


def test_on_conflict_can_replace_a_stale_unknown():
    """Neither ON CONFLICT clause updated `product`, so the first 'unknown'
    written was permanent — and must never be overwritten BY an unknown."""
    src = API.read_text()
    # Scope to THIS table: other upserts also key on (cve).
    blocks = re.findall(
        r"INSERT INTO public\.derived_cve_specs(.{0,2000}?)\"\"\"", src, re.S)
    assert len(blocks) == 2, f"found {len(blocks)} derived_cve_specs inserts"
    upserts = []
    for b in blocks:
        m = re.search(r"ON CONFLICT \(cve\) DO UPDATE SET(.*)$", b, re.S)
        assert m, "a derived_cve_specs insert has no ON CONFLICT clause"
        upserts.append(m.group(1))
    for body in upserts:
        assert re.search(r"product\s*=", body), \
            "an upsert still cannot replace a stale product"
        assert "unknown" in body, \
            "the upsert does not guard against overwriting a real name with unknown"


# --- a vuln class is not a product ------------------------------------------
#
# The backfill dry run surfaced two rows whose spec's OWN product field held a
# vulnerability class: CVE-2024-34070 product='Blind XSS' and CVE-2024-3552
# product='The Web'. Writing either into the column is worse than `unknown`,
# because downstream reads it as a real component and probes a surface that
# does not exist. So every tier is validated, the spec's own field included.


@pytest.mark.parametrize("junk", [
    "Blind XSS", "Stored XSS", "SQLi", "The Web", "the", "web", "RCE",
    "SSRF", "privilege escalation", "path traversal", "auth bypass",
])
def test_vuln_classes_and_generic_nouns_are_rejected(helpers, junk):
    assert helpers["_is_product_name"](junk) is False, junk


@pytest.mark.parametrize("real", [
    "Glowlogix WP Frontend Profile", "HasThemes HT Mega", "Dolibarr",
    "man-group/dtale", "Itsourcecode Payroll", "Fluent Bit", "SeaCMS",
    "PrestaShop", "Zabbix", "LyLme_spage", "Wholesale WholesaleX",
])
def test_real_component_names_are_accepted(helpers, real):
    assert helpers["_is_product_name"](real) is True, real


def test_a_junk_product_field_does_not_beat_the_prose(helpers):
    """Tier 1 is validated too, so a spec whose product says 'Blind XSS' still
    gets the real name mined out of its description."""
    out = helpers["_spec_product"](
        {"product": "Blind XSS",
         "description": "The Glowlogix WP Frontend Profile plugin is vulnerable."},
        "WordPress")
    assert out == "Glowlogix WP Frontend Profile", out


def test_a_platform_is_not_the_vulnerable_component(helpers):
    """'WordPress'/'Apache' name where it runs, not what is broken — and that
    confusion is the whole bug. Falling to unknown fires the dig signal."""
    assert helpers["_spec_product"]({"product": "WordPress"}, "WordPress") == "unknown"
    assert helpers["_spec_product"]({"product": "Apache"}, "unknown") == "unknown"
