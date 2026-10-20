"""SQL injection can be proven without a clock.

Why this exists — see Docs/plans/SQLI_PROOF_PATH.md
--------------------------------------------------
`knowledge/vuln_classes.yaml` declared `proof: [echo, timing, oob]` for sqli,
so a blind SQLi had exactly one route: timing. The archive (5,269 dispatched
rows) says what that costs:

    920  latency_too_fast        the injected SLEEP delayed nothing
    178  latency_too_slow
     74  latency_not_executed
     23  latency_unconfirmable
    305  latency                 landed in the window
     31  regex                   in-band proof

1,215 timing attempts wrong against 305 that landed, dominated by
`latency_too_fast` — a SLEEP(5) that returned instantly was never evaluated.

The two cheapest certain proofs were missing from the vocabulary:

  * ERROR    one request. A DB parser error naming the engine proves attacker
             input reached the parser. Nothing else emits that string.
  * BOOLEAN  two requests. `AND 1=1` vs `AND 1=2` differing proves the DB
             EVALUATED the expression. No clock, so immune to a slow target
             or a WAF with a fixed delay — the two things that make a latency
             verdict unreliable.

Both are ADDITIONAL routes to anchored. Neither is a way around the canary
chain, the scope gate, or the timing confirmation.
"""
from __future__ import annotations

import pathlib
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

try:
    from etl.proof_anchor import (DB_ERROR_SIGNATURES, anchored_boolean,
                                  anchored_error, db_error_engine, is_anchored)
except Exception:  # noqa: BLE001
    pytest.skip("etl/proof_anchor.py not importable", allow_module_level=True)

CANARY = "POCzabc123"
MYSQL_ERR = "You have an error in your SQL syntax"
PAYLOAD = "curl -s -d \"username=admin'--\" http://t:9090/login.php"


# ── error-based ─────────────────────────────────────────────────────────────

@pytest.mark.parametrize("engine", sorted(DB_ERROR_SIGNATURES))
def test_every_engine_signature_is_recognised(engine):
    for sig in DB_ERROR_SIGNATURES[engine]:
        assert db_error_engine("...%s..." % sig) == engine


def test_a_generic_error_page_is_not_a_database(): 
    """The whole risk of an error-based proof: a 500 page containing the words
    "error" or "syntax" must not anchor a SQLi."""
    for text in ("Internal Server Error", "A syntax error occurred",
                 "error: something went wrong", "500 Server Error", ""):
        assert db_error_engine(text) is None, f"{text!r} read as a DB error"


def test_error_proof_needs_both_the_signature_and_a_provoking_payload():
    # Both halves present -> anchored.
    assert anchored_error({"expect_regex": MYSQL_ERR}, PAYLOAD) is True
    # Signature required but nothing in the command would provoke it: the error
    # was already there, which is pre-existing state, not this exploit.
    assert anchored_error({"expect_regex": MYSQL_ERR},
                          "curl -s http://t:9090/login.php") is False
    # Provoking payload but the assertion does not require a DB error.
    assert anchored_error({"expect_regex": "Welcome"}, PAYLOAD) is False
    # Nothing at all.
    assert anchored_error({}, PAYLOAD) is False
    assert anchored_error({"expect_regex": MYSQL_ERR}, "") is False


# ── boolean differential ────────────────────────────────────────────────────

GOOD_DIFF = {"differential": {"true": "' AND 1=1--", "false": "' AND 1=2--",
                              "must_differ": "body"}}


def test_a_boolean_proof_anchors_on_the_differential():
    assert anchored_boolean(GOOD_DIFF, PAYLOAD) is True


def test_a_single_response_cannot_anchor_a_boolean_proof():
    """"The page rendered" is not evidence. The assertion has to declare BOTH
    arms, by construction — a lone regex cannot express a differential."""
    assert anchored_boolean({"expect_regex": "Welcome"}, PAYLOAD) is False
    assert anchored_boolean({"differential": {"true": "' AND 1=1--"}}, PAYLOAD) is False
    assert anchored_boolean({"differential": {}}, PAYLOAD) is False


def test_identical_arms_are_not_a_differential():
    """Asserting that two identical requests differ is a flake or a fabricated
    proof — it will pass roughly at random."""
    same = {"differential": {"true": "' AND 1=1--", "false": "' AND 1=1--",
                             "must_differ": "body"}}
    assert anchored_boolean(same, PAYLOAD) is False


def test_a_differential_with_nothing_to_compare_is_not_a_proof():
    no_field = {"differential": {"true": "a", "false": "b"}}
    assert anchored_boolean(no_field, PAYLOAD) is False


# ── wiring into is_anchored ─────────────────────────────────────────────────

def test_the_new_kinds_anchor_through_is_anchored():
    ok, why = is_anchored({"expect_regex": MYSQL_ERR}, CANARY,
                          proof_kinds=["error", "timing"], command=PAYLOAD)
    assert ok is True and "error:" in why and "mysql" in why

    ok, why = is_anchored(GOOD_DIFF, CANARY,
                          proof_kinds=["boolean", "timing"], command=PAYLOAD)
    assert ok is True and "boolean:" in why


def test_a_kind_not_on_the_class_cannot_anchor():
    """The class table decides which proofs a vulnerability can offer. An
    error signature must not anchor a class that does not claim `error` —
    otherwise any class becomes provable by any means."""
    ok, _ = is_anchored({"expect_regex": MYSQL_ERR}, CANARY,
                        proof_kinds=["timing"], command=PAYLOAD)
    assert ok is False


def test_the_new_kinds_do_not_bypass_the_target_contact_rule():
    """A command that never reaches the target cannot prove anything about it,
    whatever its assertion matches — the 2026-10-20 false positive."""
    ok, why = is_anchored({"expect_regex": MYSQL_ERR}, CANARY,
                          proof_kinds=["error"],
                          command="echo 'You have an error in your SQL syntax'")
    assert ok is False
    assert "never contacts the target" in why


def test_error_is_tried_before_timing():
    """Cheapest and most certain first. Timing is the last resort: it is the
    only kind whose verdict depends on how fast the target answers."""
    import ast
    src = (REPO / "etl" / "proof_anchor.py").read_text(encoding="utf-8")
    fn = [n for n in ast.walk(ast.parse(src))
          if isinstance(n, ast.FunctionDef) and n.name == "is_anchored"][0]
    seg = ast.get_source_segment(src, fn) or ""
    assert seg.index("anchored_error") < seg.index("anchored_timing")
    assert seg.index("anchored_boolean") < seg.index("anchored_timing")
