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


# ── the plan can express these proofs without hand-written shell ────────────
#
# A boolean proof needs two requests and a comparison; a timing proof needs
# clock arithmetic. Neither fits a plain request, so the model fell back to
# `command` and wrote the shell by hand — and that fallback is where FOUR of
# the five shell_syntax refusals in the 2026-10-20 run came from, all on
# timing exploits. A declarative step moves the shell-writing to the renderer.

try:
    from etl.http_request import target_of, to_script, validate_plan
    from etl.http_request import RequestSpecError as _ReqErr
except Exception:  # noqa: BLE001
    to_script = None

pytestmark_steps = pytest.mark.skipif(to_script is None,
                                      reason="etl/http_request.py not importable")

BOOL_STEP = [{"id": "bool-proof", "differential": {
    "true": {"request": {"method": "POST", "url": "http://t:9090/login.php",
                         "body": "username=x' AND 1=1-- &password=y"}},
    "false": {"request": {"method": "POST", "url": "http://t:9090/login.php",
                          "body": "username=x' AND 1=2-- &password=y"}},
    "must_differ": "body"}}]

TIME_STEP = [{"id": "blind-sleep", "timing": {
    "expect_seconds": 5,
    "request": {"method": "POST", "url": "http://t:9090/login.php",
                "body": "username=x' OR SLEEP(5)-- &password=y"}}}]


@pytestmark_steps
@pytest.mark.parametrize("plan,marker", [
    (BOOL_STEP, "DIFFERENTIAL-CONFIRMED"),
    (TIME_STEP, "ELAPSED="),
])
def test_the_step_renders_to_valid_shell(plan, marker):
    import shutil
    import subprocess
    script = to_script(plan, canary=CANARY)
    assert marker in script
    if not shutil.which("bash"):
        pytest.skip("bash not available")
    r = subprocess.run(["bash", "-n", "-c", script],
                       capture_output=True, text=True, timeout=10)
    assert r.returncode == 0, f"generated shell does not parse: {r.stderr.strip()[:200]}"


@pytestmark_steps
def test_the_target_is_read_through_the_wrapper():
    """A differential or timing step WRAPS its request. The probe still has to
    get the real target out of it, which is the whole reason it reads the plan
    instead of inferring from a rendered command."""
    assert target_of(BOOL_STEP) == ("POST", "http://t:9090/login.php")
    assert target_of(TIME_STEP) == ("POST", "http://t:9090/login.php")


@pytestmark_steps
def test_a_differential_needs_both_arms_and_something_to_compare():
    with pytest.raises(_ReqErr) as e:
        validate_plan([{"id": "x", "differential": {
            "true": {"request": {"url": "http://t/a"}}, "must_differ": "body"}}])
    assert "BOTH" in str(e.value) or "both" in str(e.value)

    with pytest.raises(_ReqErr) as e:
        validate_plan([{"id": "x", "differential": {
            "true": {"request": {"url": "http://t/a"}},
            "false": {"request": {"url": "http://t/b"}}}}])
    assert "must_differ" in str(e.value)


@pytestmark_steps
def test_a_timing_step_must_declare_the_delay_it_injects():
    """Without `expect_seconds` there is nothing for the verdict to check the
    elapsed time against, and the scaled-payload confirmation has no baseline."""
    with pytest.raises(_ReqErr) as e:
        validate_plan([{"id": "x", "timing": {
            "request": {"url": "http://t/a"}}}])
    assert "expect_seconds" in str(e.value)


@pytestmark_steps
def test_the_differential_compares_coarsely_on_purpose():
    """A boolean SQLi flips the whole response — a row comes back or it does
    not. Comparing lengths cannot be fooled by a nonce or a timestamp, which
    a full-text diff would flag on every request."""
    script = to_script(BOOL_STEP)
    assert "${#_t1}" in script and "${#_f1}" in script
    assert "DIFFERENTIAL-ABSENT" in script, (
        "the absent case must be announced too — a silent non-difference reads "
        "as the exploit failing rather than as no differential")


# ── step 5: a tool this platform ran is a scan ──────────────────────────────
#
# sqlmap ran 173 times through the build-PoC tool handoff and
# `tool_executions` held ZERO rows for it: the handoff dispatches the tool
# directly rather than through the recorded route. An operator asking "what
# have we run against this host?" got an answer missing every one of them.

GRAPH_SRC = REPO / "app" / "rag-api" / "build_poc_graph.py"
API_SRC = REPO / "app" / "rag-api" / "api.py"


def _fn(path, name):
    import ast
    src = path.read_text(encoding="utf-8")
    for n in ast.walk(ast.parse(src)):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name:
            return ast.get_source_segment(src, n) or ""
    return ""


@pytest.mark.skipif(not GRAPH_SRC.exists(), reason="build_poc_graph not present")
def test_the_handoff_records_the_run_as_a_scan():
    seg = _fn(GRAPH_SRC, "node_tool_handoff")
    assert "_record_tool_execution" in seg, (
        "a tool the platform RAN must land in tool_executions — otherwise it is "
        "invisible to scan history and every audit view")


@pytest.mark.skipif(not GRAPH_SRC.exists(), reason="build_poc_graph not present")
def test_recording_a_run_cannot_fail_the_build():
    """Bookkeeping must never cost a build. The recording is inside its own
    try/except, separate from the validation's."""
    import ast
    src = GRAPH_SRC.read_text(encoding="utf-8")
    fn = [n for n in ast.walk(ast.parse(src))
          if isinstance(n, ast.FunctionDef) and n.name == "node_tool_handoff"][0]
    # The call site imports it under an alias, so match on the Try block as a
    # whole — which contains the ImportFrom naming it — rather than on the
    # call's own dump, where only the alias appears.
    guarded = False
    for node in ast.walk(fn):
        if isinstance(node, ast.Try) and "_record_tool_execution" in ast.dump(node):
            guarded = bool(node.handlers)
            break
    assert guarded, "the tool_executions write is not wrapped in its own try/except"


@pytest.mark.skipif(not API_SRC.exists(), reason="rag-api source not present")
def test_the_recorded_output_is_capped():
    """An uncapped text column is a latent outage here: 127 MB of captured
    stderr once emptied two dashboard pages, and a verbose sqlmap run is
    exactly that shape."""
    seg = _fn(API_SRC, "_record_tool_execution")
    assert seg, "_record_tool_execution missing"
    assert "_OUT_CAP" in seg and "[:_OUT_CAP]" in seg, "output is not capped"


@pytest.mark.skipif(not API_SRC.exists(), reason="rag-api source not present")
def test_the_writer_only_uses_columns_that_exist():
    """tool_executions has no engagement_id. Naming a column the table lacks
    passes import, passes ast.parse, reports a healthy container, and 500s
    only when the path executes."""
    import re
    seg = _fn(API_SRC, "_record_tool_execution")
    m = re.search(r"INSERT INTO tool_executions\s*\(([^)]*)\)", seg, re.S)
    assert m, "no INSERT found"
    cols = {c.strip() for c in m.group(1).replace("\n", " ").split(",") if c.strip()}
    known = {"tool", "command", "target", "port", "service", "status", "exit_code",
             "output", "error", "scan_id", "started_at", "completed_at",
             "parsed_results", "id"}
    assert cols <= known, f"columns not on tool_executions: {sorted(cols - known)}"
    assert "engagement_id" not in cols


# ── step 6: proof and exploitation are different jobs ───────────────────────

@pytest.mark.skipif(not GRAPH_SRC.exists(), reason="build_poc_graph not present")
def test_sqlmap_is_not_run_in_the_proof_path():
    """Proving a CVE and exploiting it are different jobs. sqlmap ran 173
    times in the proof path and confirmed 7 (4%) — all 7 simple form POSTs.
    Elsewhere it got a crippled technique set or a broken request, so it was
    spending build time on a question `anchored_error` / `anchored_boolean`
    now answer in one or two requests."""
    import ast
    src = GRAPH_SRC.read_text(encoding="utf-8")
    fn = [n for n in ast.walk(ast.parse(src))
          if isinstance(n, ast.FunctionDef) and n.name == "node_tool_handoff"][0]
    seg = ast.get_source_segment(src, fn) or ""
    assert "deferred_to_release" in seg, "the proof path still executes the tool"
    # The gate must be read BEFORE the validation CALL, or it is dead code.
    # Compare against the call site, not the function's import line — the
    # import is at the top and would satisfy any ordering.
    gate = seg.index("_run_tools")
    call = seg.index("_run_tool_validation(")
    assert gate < call, (
        "the deferral gate is read after the tool is already dispatched")


@pytest.mark.skipif(not GRAPH_SRC.exists(), reason="build_poc_graph not present")
def test_the_derived_command_is_still_recorded():
    """Only the EXECUTION moves. The derived command is what a released run
    executes, so losing it would make phase two start from nothing."""
    import ast
    src = GRAPH_SRC.read_text(encoding="utf-8")
    fn = [n for n in ast.walk(ast.parse(src))
          if isinstance(n, ast.FunctionDef) and n.name == "node_tool_handoff"][0]
    seg = ast.get_source_segment(src, fn) or ""
    assert '"derived"' in seg and 't.get("command")' in seg


@pytest.mark.skipif(not GRAPH_SRC.exists(), reason="build_poc_graph not present")
def test_the_split_is_reversible_without_a_rebuild():
    """Phase two is not wired yet. Until it is, an operator must be able to
    put tool execution back — the LITELLM_ROUTER_ENABLED pattern."""
    import ast
    src = GRAPH_SRC.read_text(encoding="utf-8")
    fn = [n for n in ast.walk(ast.parse(src))
          if isinstance(n, ast.FunctionDef) and n.name == "node_tool_handoff"][0]
    assert "BUILD_POC_RUN_TOOLS" in (ast.get_source_segment(src, fn) or "")


# ── step 7: the model can actually reach these proofs ───────────────────────
#
# Capability is not reachability. Verified against the real model
# (DeepSeek-V4-Pro) rather than assumed, and three defects came out of that:
#
#  1. Told the vuln was BLIND, it chose ERROR-based — one request, a broken
#     quote, asserting on MySQL's parser message. Before this change a blind
#     SQLi had only `timing`, so it would have written a SLEEP and joined the
#     920 `latency_too_fast` rows.
#  2. It sent `"data"` instead of `"body"`, and normalise SILENTLY DROPPED it:
#     both arms of a boolean proof rendered as bare POSTs with no payload.
#  3. It referenced arms BY STEP ID rather than inlining them — a better shape
#     than the one designed — and as written that would have issued four
#     requests for a two-request proof.

@pytestmark_steps
def test_an_unknown_request_field_is_refused_not_dropped():
    """The model sent `data`; normalise kept only keys it knew and the payload
    vanished with nothing said. That is the unreachable-is-not-absent shape
    this repo keeps hitting: a proof that could not possibly fire, and no
    reason recorded anywhere."""
    from etl.http_request import normalise
    with pytest.raises(_ReqErr) as e:
        normalise({"url": "http://t/a", "bodyy": "typo"})
    assert "unknown request field" in str(e.value)
    assert "bodyy" in str(e.value)
    # ...and the message names what IS supported, so it is actionable.
    assert "body" in str(e.value)


@pytestmark_steps
@pytest.mark.parametrize("alias,canonical", [
    ("data", "body"), ("payload", "body"), ("params", "query"),
    ("cookie", "cookies"), ("header", "headers"),
])
def test_the_names_the_model_reaches_for_are_accepted(alias, canonical):
    from etl.http_request import normalise
    val = {"body": "x=1", "query": {"a": "b"}, "cookies": {"s": "1"},
           "headers": {"H": "v"}}[canonical]
    assert normalise({"url": "http://t/a", alias: val})[canonical] == \
        normalise({"url": "http://t/a", canonical: val})[canonical]


# The plan the model actually produced, verbatim in shape.
REF_PLAN = [
    {"id": "bool-true", "request": {"method": "POST", "url": "http://t:9090/login.php",
                                    "data": "u=x' AND 1=1-- "}},
    {"id": "bool-false", "request": {"method": "POST", "url": "http://t:9090/login.php",
                                     "data": "u=x' AND 1=2-- "}},
    {"id": "bool-diff", "differential": {"true": "bool-true", "false": "bool-false",
                                         "must_differ": "body"}},
]


@pytestmark_steps
def test_a_differential_arm_may_be_a_step_reference():
    validate_plan(REF_PLAN)
    assert target_of(REF_PLAN) == ("POST", "http://t:9090/login.php")


@pytestmark_steps
def test_a_referenced_arm_is_not_issued_twice():
    """The model declares the pair as steps AND references them. Emitting both
    the steps and the differential would send four requests for a two-request
    proof — and double the traffic of every boolean proof."""
    script = to_script(REF_PLAN, canary=CANARY)
    assert script.count("curl ") == 2, (
        f"issued {script.count('curl ')} requests for a two-request differential")
    assert "AND 1=1" in script and "AND 1=2" in script, "an arm lost its payload"


@pytestmark_steps
def test_a_reference_to_a_step_that_does_not_exist_is_refused():
    bad = [{"id": "d", "differential": {"true": "nope", "false": "also-nope",
                                        "must_differ": "body"}}]
    with pytest.raises(_ReqErr):
        validate_plan(bad)
