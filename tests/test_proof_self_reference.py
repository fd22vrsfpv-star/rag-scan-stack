"""A proof must come from the TARGET, not from the command.

Why this exists
---------------
On 2026-10-20 `CVE-2024-34070` was stored as a VERIFIED PoC. In full:

    command   = echo 'REFUSED: cannot provide exploit PoC'
    assertion = {"canary": "POCz2c556557da", "cve_anchored": true,
                 "expect_regex": "REFUSED"}

The model declined to write an exploit. The refusal text became the command,
an assertion was built that matches that text, `echo` emitted it, the regex
matched, and the run was recorded `verified=true, stop_reason=success,
verification_method=regex, cve_anchored=true`. It proved that `echo` works.

Two independent holes let it through, and both are closed here:

1. `_declared()` accepted a self-declaration of anchoring because the canary
   was PRESENT in the assertion — while the thing actually matched was
   `expect_regex: "REFUSED"`, which never mentions it. Carrying the canary in
   a sibling field is not the same as requiring it. All three routes that
   consulted `_declared` had this shape (echo, oob, and the generic
   fallback).

2. Nothing asked whether the command could have learned anything from the
   target at all.

The second is the broader rule and the reason this file is named for it: a
command built only from shell builtins contacts nothing, so whatever it
matched came from this host.
"""
from __future__ import annotations

import pathlib
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

try:
    from etl.proof_anchor import is_anchored, proof_requires_target
except Exception:  # noqa: BLE001
    pytest.skip("etl/proof_anchor.py not importable here", allow_module_level=True)

CANARY = "POCz2c556557da"

# The real row, verbatim from exploit_store id d84bdf7e.
BUG_ASSERTION = {"canary": CANARY, "cve_anchored": True, "expect_regex": "REFUSED"}
BUG_COMMAND = "echo 'REFUSED: cannot provide exploit PoC'"


def _anchored(assertion, command, kinds=("echo", "oob")):
    return is_anchored(assertion, CANARY, proof_kinds=list(kinds), command=command)


# ── the regression itself ───────────────────────────────────────────────────

def test_the_stored_false_positive_is_refused():
    ok, why = _anchored(BUG_ASSERTION, BUG_COMMAND)
    assert ok is False, f"the exact stored row still anchors: {why}"
    assert "never contacts the target" in why


def test_a_carried_canary_does_not_anchor_an_unrelated_regex():
    """Same assertion, but now the command DOES reach the target. The command
    is no longer the problem; the unfounded declaration is."""
    ok, why = _anchored(BUG_ASSERTION, "curl -s http://target/")
    assert ok is False, f"a carried canary still anchors an unrelated regex: {why}"
    assert "does not contain it" in why or "declaration cannot anchor" in why


@pytest.mark.parametrize("kinds", [("echo",), ("oob",), (), ("echo", "oob")])
def test_every_anchor_route_refuses_it(kinds):
    """echo, oob and the generic `_declared` fallback each consulted
    `_declared` and each had the hole. Closing one would have moved the
    acceptance to the next route rather than fixing anything."""
    ok, _ = _anchored(BUG_ASSERTION, "curl -s http://target/", kinds=kinds)
    assert ok is False, f"proof_kinds={kinds!r} still anchors the unfounded declaration"


# ── what must still work ────────────────────────────────────────────────────

def test_a_real_canary_reflection_still_anchors():
    ok, _ = _anchored({"canary": CANARY, "cve_anchored": True, "expect_regex": CANARY},
                      f"curl -s -d 'x={CANARY}' http://target/")
    assert ok is True


def test_a_conditional_echo_of_the_canary_still_anchors():
    """`curl ... | grep -q ok && echo 'SINK: <canary>'` is the standard
    out-of-band shape — the echo runs only if the TARGET answered. Refusing
    every echo would have broken every OOB proof."""
    ok, _ = _anchored({"canary": CANARY, "cve_anchored": True,
                       "expect_regex": f"SINK-VERIFIED: {CANARY}"},
                      f"curl -s http://target/ | grep -q ok && echo 'SINK-VERIFIED: {CANARY}'")
    assert ok is True


def test_a_declaration_with_no_regex_still_anchors():
    """Timing and file-content proofs legitimately carry no canary regex —
    there is nothing for the canary to reflect into. The declaration is the
    only route they have, and it stands when no regex contradicts it."""
    ok, _ = _anchored({"canary": CANARY, "cve_anchored": True, "min_seconds": 5},
                      "curl -s -d \"x=' OR SLEEP(5)--\" http://target/")
    assert ok is True


# ── the broader rule ────────────────────────────────────────────────────────

@pytest.mark.parametrize("command,expected", [
    ("echo 'anything at all'", False),
    ("printf 'x'", False),
    ("true", False),
    ("", False),
    (None, False),
    ("curl -s http://target/", True),
    ("python3 -c 'import requests'", True),
    ("sqlmap -u http://target/", True),
    ("nc target 4444", True),
])
def test_proof_requires_target(command, expected):
    assert proof_requires_target(command) is expected


def test_absent_command_does_not_refuse():
    """`command` is optional on the signature. An absent one must SKIP the
    check, not fail it — callers that do not pass a command are asking a
    different question, and turning that into a refusal would break them."""
    ok, _ = is_anchored({"canary": CANARY, "cve_anchored": True, "expect_regex": CANARY},
                        CANARY, proof_kinds=["echo"])
    assert ok is True
