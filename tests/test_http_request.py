"""A PoC request rendered from DATA, not written as a shell string.

Why this exists
---------------
Synth asks the model for a shell command, as one string, inside a JSON field.
Measured on the trace archive (5,269 dispatched rows):

    444  shell_syntax        a shell string inside a JSON field is escaped
                             twice and the model loses the quoting
    296  prerun_probe_fail   the probe RE-PARSED that string to find the
                             target and picked the payload's callback sink
     83  prerun_tool_missing `SELECT` / `auth` reached the shell as a program

None of those are the model failing to find a vulnerability.

The contract this file pins:

* rendering is LOSSLESS — everything `to_curl` emits must parse back to the
  same request through `_curl_to_request`, the parser the Python lane already
  uses. If the two disagree, the structured path is a third dialect rather
  than a fix.
* quoting is never the model's problem — a body of `' OR 1=1--`, embedded
  single quotes, or a JSON document all survive.
* `{{CANARY}}` is substituted HERE, not by a shell. Every `$CANARY` probe
  failure in the archive was a command that DID set the variable; the probe
  read the text without a shell and saw a literal.
* the target is READ, not guessed.
"""
from __future__ import annotations

import pathlib
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

try:
    from etl.http_request import (CANARY_TOKEN, RequestSpecError, normalise,
                                  substitute, target_of, to_curl, to_script,
                                  validate_plan)
except Exception:  # noqa: BLE001
    pytest.skip("etl/http_request.py not importable", allow_module_level=True)

API = REPO / "app" / "rag-api" / "api.py"


def _real_parser():
    """`_curl_to_request` from api.py, without importing the whole module."""
    if not API.exists():
        pytest.skip("rag-api source not present")
    src = API.read_text(encoding="utf-8")
    i = src.index("def _curl_to_request")
    j = src.index("\ndef ", i + 10)
    ns: dict = {}
    exec(compile(src[i:j], "<parser>", "exec"), ns)  # noqa: S102
    return ns["_curl_to_request"]


# Shapes that actually appear in PoCs, including the ones that break quoting.
ROUNDTRIP = [
    ("plain get", {"url": "http://t:9090/a"}),
    ("sqli body", {"method": "POST", "url": "http://t:9090/login",
                   "body": "user=admin' OR 1=1-- &pw=x"}),
    ("json sugar", {"method": "POST", "url": "http://t:9090/api",
                    "json": {"name": "../../../../etc/passwd", "q": 'He said "hi"'}}),
    ("headers and cookies", {"method": "PUT", "url": "http://t:9090/x",
                             "headers": {"X-CSRF": "a b'c"},
                             "cookies": {"PHPSESSID": "abc123"}}),
    # The shape that produced the syntax refusals: a payload that is itself
    # a quoting exercise.
    ("shell metacharacters", {"method": "POST", "url": "http://t:9090/p",
                              "body": """x='"'"'; echo pwned; #"""}),
    ("query string", {"url": "http://t:9090/s", "query": {"q": "a b&c=d"}}),
]


@pytest.mark.parametrize("label,spec", ROUNDTRIP, ids=[c[0] for c in ROUNDTRIP])
def test_render_round_trips_through_the_real_parser(label, spec):
    parse = _real_parser()
    back = parse(to_curl(spec))
    want = normalise(spec)
    assert back["method"] == want["method"]
    assert back["url"].split("?")[0] == want["url"].split("?")[0]
    assert (back["body"] or None) == (want["body"] or None), (
        f"{label}: body did not survive rendering")


def test_a_body_full_of_quotes_needs_no_escaping_decision():
    """The 444-refusal class. The model supplies the literal payload; the
    renderer decides the spelling."""
    payload = """' UNION SELECT 1,'<script>alert("x")</script>',3-- """
    cmd = to_curl({"method": "POST", "url": "http://t:9090/s", "body": payload})
    assert _real_parser()(cmd)["body"] == payload


def test_body_uses_data_raw_not_dash_d():
    """`-d` strips newlines, and a leading `@` means "read this file" — a
    body starting with @ would silently become a file read."""
    cmd = to_curl({"method": "POST", "url": "http://t:9090/a", "body": "@/etc/passwd"})
    assert "--data-raw" in cmd and " -d " not in cmd
    assert _real_parser()(cmd)["body"] == "@/etc/passwd"


# ── the canary is data, not a shell variable ────────────────────────────────

def test_canary_token_is_substituted_before_rendering():
    plan = [{"id": "fire", "request": {"method": "POST", "url": "http://t:9090/p",
                                       "body": "http://t:9091/" + CANARY_TOKEN}}]
    script = to_script(plan, canary="POCzabc123")
    assert "POCzabc123" in script
    assert CANARY_TOKEN not in script
    assert "$CANARY" not in script, "no shell variable should survive into the command"


def test_substitute_is_recursive_and_leaves_other_text_alone():
    out = substitute({"a": [CANARY_TOKEN, "x"], "b": {"c": "p" + CANARY_TOKEN}}, "C1")
    assert out == {"a": ["C1", "x"], "b": {"c": "pC1"}}
    assert substitute("no token here", "C1") == "no token here"


def test_no_canary_leaves_the_plan_untouched():
    assert substitute(CANARY_TOKEN, None) == CANARY_TOKEN


# ── the target is read, not guessed ─────────────────────────────────────────

def test_target_is_the_first_step_not_the_callback_sink():
    """The probe bug, removed by construction: an SSRF plan carries the sink
    URL as a BODY, and the thing being attacked is the step's own url."""
    plan = [
        {"id": "fire", "request": {"method": "POST", "url": "http://t:9090/api/proxy",
                                   "body": "http://t:9091/" + CANARY_TOKEN}},
        {"id": "check", "wait_seconds": 2, "request": {"url": "http://t:9091/done"}},
    ]
    assert target_of(plan) == ("POST", "http://t:9090/api/proxy")


def test_steps_are_announced_so_output_says_which_one_ran():
    plan = [{"id": "login", "request": {"url": "http://t:9090/a"}},
            {"id": "exploit", "request": {"url": "http://t:9090/b"}}]
    script = to_script(plan)
    assert "--- STEP login ---" in script
    assert "--- STEP exploit ---" in script
    assert script.index("login") < script.index("exploit")


# ── rejections are addressed to the model ───────────────────────────────────

@pytest.mark.parametrize("bad,needle", [
    ({}, "url"),
    ({"url": "/api/login"}, "scheme"),
    ({"url": "http://t/a", "headers": "X: 1"}, "object"),
    ({"url": "http://t/a", "body": "x", "json": {"a": 1}}, "not both"),
])
def test_unrenderable_requests_say_what_to_fix(bad, needle):
    with pytest.raises(RequestSpecError) as e:
        normalise(bad)
    assert needle in str(e.value).lower() or needle in str(e.value)


def test_validate_plan_names_the_failing_step():
    with pytest.raises(RequestSpecError) as e:
        validate_plan([{"id": "ok", "request": {"url": "http://t/a"}},
                       {"id": "broken", "request": {"url": "/relative"}}])
    assert "broken" in str(e.value)


def test_timeout_is_bounded():
    assert normalise({"url": "http://t/a", "timeout": 99999})["timeout"] == 600
    assert normalise({"url": "http://t/a", "timeout": "nonsense"})["timeout"] == 30


# ── wiring: the plan must actually reach the probe ──────────────────────────

GRAPH = REPO / "app" / "rag-api" / "build_poc_graph.py"


def _ast(path):
    import ast
    return ast.parse(path.read_text(encoding="utf-8"))


def _func(tree, name):
    import ast
    for n in __import__("ast").walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name:
            return n
    return None


@pytest.mark.skipif(not GRAPH.exists(), reason="build_poc_graph not present")
def test_synth_renders_a_plan_when_one_is_present():
    import ast
    fn = _func(_ast(GRAPH), "node_synth")
    assert fn is not None
    called = {n.func.id for n in ast.walk(fn)
              if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
    assert "_ts" in called or "to_script" in called, \
        "node_synth must render a structured plan into the command"


@pytest.mark.skipif(not GRAPH.exists(), reason="build_poc_graph not present")
def test_a_plan_that_will_not_render_does_not_break_the_build():
    """A renderer fault must cost nothing: the model's own command stands and
    the reason is traced. Otherwise a bad plan burns an iteration."""
    import ast
    fn = _func(_ast(GRAPH), "node_synth")
    handlers = [n for n in ast.walk(fn) if isinstance(n, ast.ExceptHandler)]
    assert handlers, "plan rendering must be wrapped — it runs on every build"
    traced = {c.value for h in handlers for n in ast.walk(h)
              if isinstance(n, ast.Call) for c in n.args if isinstance(c, ast.Constant)}
    assert "synth_plan_rejected" in traced, "a dropped plan must say why in the trace"


@pytest.mark.skipif(not API.exists(), reason="rag-api source not present")
def test_the_probe_accepts_a_plan_and_prefers_it():
    import ast
    fn = _func(_ast(API), "_prerun_payload_probe")
    assert fn is not None
    assert any(a.arg == "plan" for a in fn.args.args + fn.args.kwonlyargs), \
        "the probe must accept the structured plan"
    src = ast.get_source_segment(API.read_text(encoding="utf-8"), fn) or ""
    # The declared target is consulted BEFORE the string inference.
    assert src.index("target_of") < src.index("_curl_target_url"), \
        "the probe must read the plan's declared target before inferring one"


@pytest.mark.skipif(not API.exists(), reason="rag-api source not present")
def test_the_plan_is_only_trusted_on_the_first_iteration():
    """Once refine rewrites the command by hand the plan no longer describes
    it. A stale declared target is worse than an inferred one."""
    import ast
    fn = _func(_ast(API), "_run_refine_poc")
    assert fn is not None
    src = ast.get_source_segment(API.read_text(encoding="utf-8"), fn) or ""
    call = src[src.index("_prerun_payload_probe("):]
    call = call[:call.index(")") + 1]
    assert "it == 1" in call, "the plan must not be reused after the first iteration"


# ── the synth contract ──────────────────────────────────────────────────────

@pytest.mark.skipif(not API.exists(), reason="rag-api source not present")
def test_plan_is_bound_before_the_return_reads_it():
    """`plan` is assigned only inside a branch that depends on what the model
    returned, and the return reads it unconditionally. That is the
    use-before-assignment shape that took `_summarize_build_trace` down on
    2026-10-20 (three suite failures, NameError on every trace summary).
    pyflakes does not flag conditional binding, so the initialiser is the
    guard and this is what holds it there."""
    import ast
    fn = _func(_ast(API), "_synthesize_cve_poc")
    assert fn is not None
    # An unconditional `plan = ...` at function-body level, before any return.
    top_level_init = None
    for i, node in enumerate(fn.body):
        if (isinstance(node, ast.Assign)
                and any(isinstance(t, ast.Name) and t.id == "plan" for t in node.targets)):
            top_level_init = i
            break
    assert top_level_init is not None, (
        "`plan` has no unconditional initialiser — it will be unbound whenever "
        "the model returns no plan")


@pytest.mark.skipif(not API.exists(), reason="rag-api source not present")
def test_the_structured_contract_is_the_default_and_chaining_is_the_fallback():
    """The old prompt actively taught the shape that breaks — "chain curl
    calls with ; and shell vars" — and that instruction produced the commands
    behind 444 shell_syntax refusals.

    Structural, on the if/else that selects the contract. A substring search
    would be satisfied by the COMMENT that quotes the old hint to explain why
    it moved, which is how the first version of this test passed for the
    wrong reason.
    """
    import ast
    fn = _func(_ast(API), "_synthesize_cve_poc")
    branch = None
    for node in ast.walk(fn):
        if (isinstance(node, ast.If)
                and any(isinstance(n, ast.Name) and n.id == "_structured"
                        for n in ast.walk(node.test))):
            branch = node
            break
    assert branch is not None, "no branch selects the prompt contract"

    def _strings(body):
        return " ".join(c.value for n in body for c in ast.walk(ast.Module(body=[n], type_ignores=[]))
                        if isinstance(c, ast.Constant) and isinstance(c.value, str))

    on, off = _strings(branch.body), _strings(branch.orelse)
    assert "PREFER `plan` over `command`" in on, "the default must ask for a plan"
    assert "{{CANARY}}" in on, "the default must name the canary token"
    assert "chain curl calls with ; and shell vars" not in on, (
        "the default contract still teaches shell chaining")
    assert "chain curl calls with ; and shell vars" in off, (
        "the legacy contract must be preserved verbatim behind the kill switch")


@pytest.mark.skipif(not API.exists(), reason="rag-api source not present")
def test_the_contract_change_has_a_kill_switch():
    """A prompt change alters what the model produces on EVERY build, so it
    has to be revertible without a rebuild — the LITELLM_ROUTER_ENABLED
    pattern."""
    import ast
    src = API.read_text(encoding="utf-8")
    seg = ast.get_source_segment(src, _func(_ast(API), "_synthesize_cve_poc")) or ""
    assert "BUILD_POC_STRUCTURED_PLAN" in seg


@pytest.mark.skipif(not API.exists(), reason="rag-api source not present")
def test_a_malformed_plan_falls_back_rather_than_failing_the_build():
    import ast
    src = API.read_text(encoding="utf-8")
    seg = ast.get_source_segment(src, _func(_ast(API), "_synthesize_cve_poc")) or ""
    assert "synth_plan_invalid" in seg, "an unrenderable plan must say so in the trace"
    i_plan = seg.index('obj.get("plan")')
    i_cmd = seg.index('obj.get("command")')
    assert i_plan < i_cmd, (
        "the plan must be read before the command — when the model sends "
        "both, the structured one is the one whose quoting we can guarantee")


# ── carrying a value between steps ──────────────────────────────────────────
#
# The one thing shell-chaining genuinely gave the model: a CSRF token fetched
# in one request and used in the next. Without it, the very first live plan
# this prompt produced wrote `csrf_token=REPLACE_WITH_CSRF` into the body —
# so every CSRF-gated exploit would have produced an unusable plan and the
# benchmark would have looked worse for the wrong reason.

EXTRACT_PLAN = [
    {"id": "fetch", "request": {"url": "http://t:9090/login.php"},
     "extract": {"csrf": {"grep_p": 'name="csrf_token"\\s+value="\\K[^"]+'}}},
    {"id": "use", "request": {"method": "POST", "url": "http://t:9090/login.php",
                              "body": "t={{csrf}}&q=' OR 1=1-- "}},
]


def test_a_capture_reference_expands_outside_the_quotes():
    """shlex.quote wraps a value in single quotes, where `$name` is literal.
    A capture has to step outside them, or the next request goes out with the
    parameter empty and the failure looks like the exploit."""
    script = to_script(EXTRACT_PLAN)
    # The capture leaves the single-quoted run and re-enters it:  't='"$csrf"'&...'
    assert '\'"$csrf"\'' in script, "the capture does not escape the quotes"
    # ...and the payload's own quote is still intact.
    assert "OR 1=1--" in script


def test_a_literal_dollar_in_a_payload_is_not_an_expansion():
    """A body containing the characters `$csrf` is DATA. Pattern-matching for
    `"$name"` after quoting would have turned it into a shell expansion."""
    body = "note=the var $csrf is literal"
    script = to_script([{"id": "x", "request": {
        "method": "POST", "url": "http://t:9090/a", "body": body}}])
    # Parsed back rather than matched as text: what matters is that the body
    # curl receives is byte-identical to the one the model supplied.
    parse = _real_parser()
    curl_line = [l for l in script.splitlines() if l.startswith("curl")][0]
    assert parse(curl_line)["body"] == body


def test_an_empty_capture_announces_itself():
    """A blank token produces a request that fails for a reason that looks
    like the exploit. The extraction has to say it failed."""
    assert "EXTRACT-FAILED: csrf" in to_script(EXTRACT_PLAN)


def test_extract_requires_a_pattern_and_a_usable_name():
    with pytest.raises(RequestSpecError) as e:
        to_script([{"id": "a", "request": {"url": "http://t/a"}, "extract": {"x": {}}}])
    assert "grep_p" in str(e.value)
    with pytest.raises(RequestSpecError) as e:
        to_script([{"id": "a", "request": {"url": "http://t/a"},
                    "extract": {"not a name": {"grep_p": "x"}}}])
    assert "identifier" in str(e.value)


def test_the_generated_script_is_valid_shell():
    """Generated shell that does not parse would be the original problem with
    extra steps. `bash -n` reads it without executing a word."""
    import shutil
    import subprocess
    if not shutil.which("bash"):
        pytest.skip("bash not available")
    script = to_script(EXTRACT_PLAN, canary="POCzTEST")
    r = subprocess.run(["bash", "-n", "-c", script], capture_output=True, text=True, timeout=10)
    assert r.returncode == 0, f"generated script does not parse: {r.stderr.strip()[:200]}"
