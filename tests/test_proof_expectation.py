"""What is realistic to expect back, per class — instead of always a canary.

The live synth prompt hard-coded inject-and-reflect as THE proof model:

    Make the PoC CAUSE the exact marker '{canary}' to appear as a DIRECT RESULT
    of exploiting {cve} ... then read it back
    "assertion": {"expect_regex": "{canary}"}
    "rationale": "<why this proves {cve}, and how the exploit injects {canary}>"

Two shapes were offered (canary, timing) for a table that declares six, the
assertion was pre-filled as a canary regex, and nothing checked the assertion
against the class. For most classes that instruction cannot be followed:

  * a file read INJECTS NOTHING — a canary coming back is a refutation
  * Log4Shell returns a plain 200 by definition; proof is ['oob'] only
  * an IDOR proof is another tenant's record, which you did not inject
  * CSRF and prototype pollution prove in a SECOND request a single-response
    regex cannot see

Worse, the class guidance already said "a canary is the WRONG proof" for a file
read while the same prompt demanded one — contradictory instructions in one
request. That is how CVE-2026-21589, a path traversal, got a canary assertion.

    docker run --rm -v /opt/rag-scan-stack:/work:ro -w /work \
      python:3.12-slim sh -c 'pip install -q pytest pyyaml && \
      PYTHONPATH=.:tests python -m pytest tests/test_proof_expectation.py -v'
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

import pytest

pytest.importorskip("yaml")

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from etl import payload_variants as pv  # noqa: E402
from etl import vuln_classes as vc  # noqa: E402

API = REPO / "app" / "rag-api" / "api.py"
SRC = API.read_text(encoding="utf-8")
TREE = ast.parse(SRC)
CANARY = "pocK9x2Q"


def _node(name, kind=ast.FunctionDef):
    for n in ast.walk(TREE):
        if isinstance(n, kind) and getattr(n, "name", "") == name:
            return n
    return None


def _const(name):
    for n in ast.walk(TREE):
        if isinstance(n, ast.Assign) and any(getattr(t, "id", "") == name for t in n.targets):
            return ast.literal_eval(n.value)
    pytest.fail("%s not found" % name)


def _block():
    # The block now appends the TARGET-shaped payloads and proof regexes, so
    # the real variant table is bound too — the prompt and the test must not
    # disagree about what a windows box is offered.
    ns = {"chr": chr, "_vc_proof_kinds": vc.proof_kinds, "_vc_canonical": vc.canonical,
          "_pv_selection": pv.variants_for, "_pv_payloads": pv.payloads_for,
          "_pv_proof": pv.proof_for, "_pv_caveats": pv.proof_caveats_for,
          "_pv_preferred_proof": pv.preferred_proof}
    inst = next(n for n in TREE.body if isinstance(n, ast.Assign)
                and any(getattr(t, "id", "") == "_PROOF_KIND_INSTRUCTION" for t in n.targets))
    fn = _node("_proof_expectation_block")
    assert fn is not None, "_proof_expectation_block missing"
    exec(compile(ast.Module([inst, fn], []), "<api>", "exec"), ns)
    return ns["_proof_expectation_block"]


BLOCK = _block()


# ── per class, what it says ────────────────────────────────────────────────

@pytest.mark.unit
class TestBlock:
    def test_an_echo_class_still_gets_the_canary_instruction(self):
        out = BLOCK("sqli", CANARY)
        assert CANARY in out
        assert "ECHO" in out

    def test_a_file_read_is_told_the_canary_is_a_refutation(self):
        """The contradiction this removes: the class guidance said the canary
        is wrong while the prompt demanded one."""
        for cls in ("path-traversal", "lfi"):
            out = BLOCK(cls, CANARY)
            assert "FILE CONTENT" in out, cls
            assert "injects NOTHING" in out or "INJECTS NOTHING" in out, cls
            assert "REFUTATION" in out.upper(), cls

    def test_a_class_that_cannot_echo_is_told_so_explicitly(self):
        out = BLOCK("path-traversal", CANARY)
        assert "canary regex cannot prove this class" in out.lower()

    def test_an_echo_class_is_not_told_the_canary_is_invalid(self):
        out = BLOCK("sqli", CANARY)
        assert "canary regex cannot prove this class" not in out.lower()

    def test_jndi_gets_out_of_band_only(self):
        """Its proof kinds are ['oob'] and nothing else — the response is a
        plain 200 by definition."""
        assert vc.proof_kinds("jndi-injection") == ["oob"]
        out = BLOCK("jndi-injection", CANARY)
        assert "OUT-OF-BAND" in out
        assert "ECHO" not in out
        assert CANARY not in out, "a canary was offered to a blind-only class"

    def test_a_two_request_class_is_told_the_proof_is_a_difference(self):
        assert "DIFFERENCE" in BLOCK("idor", CANARY)
        assert "follow-up" in BLOCK("csrf", CANARY).lower()

    def test_timing_demands_a_real_payload(self):
        out = BLOCK("sqli", CANARY)
        assert "TIMING" in out and "SLEEP" in out

    def test_an_unknown_class_returns_empty_so_the_caller_keeps_its_fallback(self):
        """Losing the instruction entirely would be worse than the old one."""
        assert BLOCK("not-a-class", CANARY) == ""
        assert BLOCK("unknown", CANARY) == ""

    def test_a_misconfiguration_gets_no_proof_instruction(self):
        assert BLOCK("webdav-put", CANARY) == ""

    def test_every_proof_kind_in_the_table_has_an_instruction(self):
        """A kind with no text is a class that silently gets less guidance."""
        inst = _const("_PROOF_KIND_INSTRUCTION")
        declared = set()
        for name in vc.names():
            declared |= set(vc.proof_kinds(name))
        missing = sorted(declared - set(inst))
        assert not missing, "proof kinds with no instruction: %s" % missing

    def test_the_block_names_the_class(self):
        assert "path-traversal" in BLOCK("directory-traversal", CANARY), (
            "the block should name the CANONICAL class, so an alias in the "
            "advisory does not produce a prompt about a different thing")


# ── the prompt that actually runs ──────────────────────────────────────────

@pytest.mark.unit
class TestPromptWiring:
    def test_the_unconditional_canary_mandate_is_gone(self):
        fn = ast.get_source_segment(SRC, _node("_synthesize_cve_poc")) or ""
        assert "appear as a DIRECT RESULT of " not in fn, (
            "the prompt still mandates inject-and-reflect for every class")

    def test_the_prompt_uses_the_class_driven_block(self):
        fn = ast.get_source_segment(SRC, _node("_synthesize_cve_poc")) or ""
        assert "_proof_expectation_block" in fn
        assert "_proof_block" in fn

    def test_the_assertion_template_is_not_a_canary_for_a_non_echo_class(self):
        """Name-only ("is `_assert_tmpl` mentioned?") passes while the branch
        still hands a canary to a file read. Check the BRANCH.

        The chain is: no class -> canary fallback; class CAN echo -> canary;
        otherwise -> a placeholder. Only the last branch is under test.
        """
        fn = _node("_synthesize_cve_poc")
        assert fn is not None
        chain = None
        for n in ast.walk(fn):
            if (isinstance(n, ast.If)
                    and "_proof_block" in ast.unparse(n.test)
                    and any("_assert_tmpl" in ast.unparse(x) for x in ast.walk(n))):
                chain = n
                break
        assert chain is not None, "no _assert_tmpl branch found"
        # Walk to the final else (the non-echo case).
        node, tail = chain, None
        while node is not None:
            if node.orelse and isinstance(node.orelse[0], ast.If):
                node = node.orelse[0]
                continue
            tail = node.orelse
            break
        assert tail, "the chain has no final else — every class gets a canary"
        src = " ".join(ast.unparse(x) for x in tail)
        assert "_assert_tmpl" in src
        # The per-kind DECISION moved into `_assert_template_for` (2026-10-20),
        # so the old check — "the word `canary` must not appear here" — now
        # fails on the ARGUMENT NAME in `_assert_template_for(vc, canary)`
        # while the behaviour is correct. Asserting the absent substring would
        # mean reverting a fix to satisfy a guard.
        #
        # What still has to hold at THIS call site is that the branch delegates
        # to the selector and passes the class, so the choice is made in the one
        # place that is executable-tested. The invariant itself — a class that
        # cannot echo is never handed a canary template — is proven by RUNNING
        # the selector in tests/test_sqli_proof_path.py
        # (test_a_file_read_is_never_offered_a_canary,
        #  test_sqli_is_offered_the_error_template_not_the_canary_one,
        #  test_an_unknown_class_gets_no_invented_shape), which a source
        # substring could never establish.
        call = next((n for n in ast.walk(ast.parse(src))
                     if isinstance(n, ast.Call)
                     and getattr(n.func, "id", "") == "_assert_template_for"), None)
        assert call is not None, (
            "the non-echo branch no longer delegates to _assert_template_for — "
            "it is picking a template inline, where nothing executes it: %s" % src)
        assert call.args, "_assert_template_for is called without the vuln class"

    def test_the_rationale_no_longer_presupposes_injection(self):
        fn = ast.get_source_segment(SRC, _node("_synthesize_cve_poc")) or ""
        assert "how the exploit injects" not in fn, (
            "asking the model to explain HOW it injected the canary "
            "presupposes that injection happened")

    def test_the_fallback_survives_for_an_unknown_class(self):
        """An unknown class must not lose the instruction altogether."""
        fn = ast.get_source_segment(SRC, _node("_synthesize_cve_poc")) or ""
        assert "if not _proof_block:" in fn

    def test_the_class_is_derived_before_the_prompt_is_built(self):
        fn = ast.get_source_segment(SRC, _node("_synthesize_cve_poc")) or ""
        assert fn.index("_listener_vc =") < fn.index("_proof_block =")
        assert fn.index("canary = _poc_canary()") < fn.index("_proof_block =")
