"""Every LLM call in exploit_runner/script_executor.py goes through llm_query.

Run on demand:

    pytest tests/test_script_executor_llm_routing.py -v

WHY THIS EXISTS
---------------
This module has three exploit-code generation paths. Two of them
(`ScriptExecutor.customize_script` and `ScriptExecutor.fix_script`) POST to
`LLM_URL` with `task="exploit_gen"`, which is what makes llm_query pick a
backend deployment. The third, module-level `txt_to_exploit()`, posted to
`{OLLAMA_URL}/api/generate` instead. There is no raw ollama daemon in this
deployment, so that path 404'd and can never have produced a single exploit --
silently, because the call sits inside `except Exception: logger.warning(...)`
and the function then falls through to its "manual" summary return.

Two separate things must hold, and each has burned this repo before:

1. No raw-ollama call. A direct `/api/generate` is a request to a service that
   does not exist here.
2. The routed call must carry `task` and must NOT force a concrete model.
   llm_query treats ANY non-empty `model` as an explicit caller choice that
   beats the task route, so `LLM_MODEL` (env, default "") must be passed as
   `LLM_MODEL or None` -- a bare `LLM_MODEL` would inject a caller model the
   moment the env var is set and 404 "DeploymentNotFound" on Azure.

Static (ast) rather than import-based: exploit_runner/ is not importable
outside its container (it imports `etl.scope_gate`, `httpx`, and sibling
modules by bare name), and the defect is a literal in the source.

SABOTAGE PROOF
--------------
* Point txt_to_exploit's httpx.post back at f"{OLLAMA_URL}/api/generate" and
  test_no_raw_ollama_generate_call + test_txt_to_exploit_routes_with_task fail.
* Change `"model": LLM_MODEL or None` to `"model": LLM_MODEL` and
  test_generation_calls_do_not_force_a_model fails (by call-site line number).
* Drop `"task": "exploit_gen"` from any of the three and
  test_all_generation_calls_declare_the_task fails by name.
"""
import ast
import os

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
EXECUTOR = os.path.join(REPO, "exploit_runner", "script_executor.py")


def _source():
    if not os.path.exists(EXECUTOR):
        pytest.skip("exploit_runner/script_executor.py not present")
    return open(EXECUTOR, encoding="utf-8").read()


def _tree():
    return ast.parse(_source())


def _func(tree, name):
    """Top-level function OR method with this name, anywhere in the module."""
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return node
    pytest.fail(f"{name}() not found in script_executor.py")


def _posts(node):
    """Every httpx `.post(...)` Call inside the given ast node."""
    out = []
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute) \
                and sub.func.attr == "post":
            out.append(sub)
    return out


def _json_kwarg(call):
    for kw in call.keywords:
        if kw.arg == "json":
            return kw.value
    return None


def _json_key(call, key):
    """The ast node for json={... key: <node> ...}, or None."""
    body = _json_kwarg(call)
    if not isinstance(body, ast.Dict):
        return None
    for k, v in zip(body.keys, body.values):
        if isinstance(k, ast.Constant) and k.value == key:
            return v
    return None


#: The three call sites that ask an LLM to write or repair exploit code.
GENERATION_FUNCS = ["txt_to_exploit", "customize_script", "fix_script"]


def test_no_raw_ollama_generate_call():
    """No path in this module talks to a raw ollama daemon."""
    # Unparsed rather than raw text: comments (including this guard's own
    # explanation in script_executor.py) must not count as a call site.
    src = ast.unparse(_tree())
    assert "/api/generate" not in src, (
        "script_executor.py still posts to a raw ollama /api/generate. "
        "There is no ollama deployment in this stack -- that path 404s. "
        "Route through LLM_URL (llm_query) with task='exploit_gen' instead."
    )
    assert "OLLAMA_URL" not in src, (
        "script_executor.py still defines/uses OLLAMA_URL. Every LLM call in "
        "this module must go through the llm_query router."
    )


def test_txt_to_exploit_routes_with_task():
    """txt_to_exploit posts to the llm_query URL, tagged task='exploit_gen'."""
    fn = _func(_tree(), "txt_to_exploit")
    posts = _posts(fn)
    assert posts, "txt_to_exploit no longer makes an LLM call at all"

    routed = []
    for call in posts:
        task = _json_key(call, "task")
        if isinstance(task, ast.Constant) and task.value == "exploit_gen":
            routed.append(call)
    assert routed, (
        "txt_to_exploit's LLM POST does not carry task='exploit_gen'. Without "
        "the task, llm_query cannot route the request to a live backend."
    )

    # ...and the URL comes from LLM_URL, not a hard-coded daemon address.
    for call in routed:
        url = call.args[0] if call.args else None
        assert isinstance(url, ast.Name) and url.id == "llm_url", (
            "txt_to_exploit's routed POST should target the `llm_url` resolved "
            "from os.environ['LLM_URL'], matching customize_script/fix_script."
        )
    assert "os.environ.get('LLM_URL'" in ast.unparse(fn), (
        "txt_to_exploit must read LLM_URL from the environment"
    )


@pytest.mark.parametrize("name", GENERATION_FUNCS)
def test_all_generation_calls_declare_the_task(name):
    """All three exploit-generation call sites tag the request with a task."""
    fn = _func(_tree(), name)
    tasks = [_json_key(c, "task") for c in _posts(fn)]
    tasks = [t for t in tasks if isinstance(t, ast.Constant)]
    assert any(t.value == "exploit_gen" for t in tasks), (
        f"{name}() posts to the LLM without task='exploit_gen'; llm_query then "
        f"falls back to a global default instead of the exploit_gen route."
    )


@pytest.mark.parametrize("name", GENERATION_FUNCS)
def test_generation_calls_do_not_force_a_model(name):
    """`model` must be `LLM_MODEL or None`, never a bare/forced model name.

    llm_query treats any non-empty model as a caller choice that overrides the
    task route -- a forced name 404s DeploymentNotFound on the Azure backend.
    """
    fn = _func(_tree(), name)
    for call in _posts(fn):
        model = _json_key(call, "model")
        if model is None:
            continue  # omitted entirely is fine: None is the routable value
        assert isinstance(model, ast.BoolOp) and isinstance(model.op, ast.Or), (
            f"{name}() (line {call.lineno}) sends a forced `model`. Use "
            f"`LLM_MODEL or None` so an unset env var leaves the model empty "
            f"and the task route decides."
        )
        last = model.values[-1]
        assert isinstance(last, ast.Constant) and last.value is None, (
            f"{name}() (line {call.lineno}) must fall back to None, not "
            f"{ast.dump(last)}"
        )
