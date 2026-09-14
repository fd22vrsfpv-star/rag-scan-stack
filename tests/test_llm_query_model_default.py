"""llm_query task routing must not be defeated by a defaulted `model`.

Run on demand:

    pytest tests/test_llm_query_model_default.py -v
    LLM_QUERY_URL=http://localhost:8002 pytest tests/test_llm_query_model_default.py

WHY THIS EXISTS
---------------
llm_query routes a request by TASK when the caller names a task and leaves the
model empty ("I don't care which model, use llm.route.<task>"). `_route_for`
treats ANY non-empty `model` as an explicit caller choice that WINS over the
task route. So if the `GenerateRequest`/`ChatRequest` pydantic model defaults
`model` to a concrete string (it used to default to DEFAULT_MODEL =
OLLAMA_MODEL), then a caller that omits `model` and sends only
`task="extract"` has that default silently injected -- and the request is sent
to an Ollama tag on the Azure backend, which 404s with DeploymentNotFound.
That is exactly what broke the extractor's "focus" user-account extraction.

The field default MUST be None so an omitted model stays empty and the task
route (or the global default) decides. The non-routed passthrough paths all use
`_normalize_model(req.model)` or `_caller_model(req.model) or AZURE_MODEL`, both
of which fall back to a concrete model when None -- so None here costs nothing.

Separately, the gpt-5 / o-series reasoning deployments reject `temperature` and
`top_p` overrides ("only the default (1) value is supported") AND `max_tokens`
(they need `max_completion_tokens`). `_azure_json_post` strips/swaps the named
param and retries, so a routed extract call carrying temperature=0.1 still
lands instead of 400ing.

SABOTAGE PROOF
--------------
* Change `GenerateRequest.model` back to `Field(default=DEFAULT_MODEL, ...)`
  and test_routing_models_do_not_default_the_model fails.
* Delete the temperature-strip branch in `_azure_json_post` and
  test_azure_post_strips_unsupported_sampling_params fails.
"""
import ast
import os
import re

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
LLM_QUERY = os.path.join(REPO, "llm_query", "llm_query.py")

#: The request models whose `model` field feeds _route_for. A concrete default
#: on any of these defeats task routing for callers that omit the model.
ROUTING_MODELS = {"GenerateRequest", "ChatRequest"}


def _source():
    if not os.path.exists(LLM_QUERY):
        pytest.skip("llm_query.py not present")
    return open(LLM_QUERY, encoding="utf-8").read()


def _model_field_default(tree, classname):
    """The default value node of the `model:` field on a pydantic class, or the
    string 'MISSING' if the class/field is absent."""
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == classname:
            for stmt in node.body:
                if (isinstance(stmt, ast.AnnAssign)
                        and isinstance(stmt.target, ast.Name)
                        and stmt.target.id == "model"):
                    return stmt.value
            return "MISSING"
    return "MISSING"


def _field_default_is_none(value) -> bool:
    """True when the annotation's default resolves to None -- either a bare
    `= None` or `Field(default=None, ...)`."""
    if value is None or value == "MISSING":
        return False
    # bare `model: Optional[str] = None`
    if isinstance(value, ast.Constant) and value.value is None:
        return True
    # `model: Optional[str] = Field(default=None, ...)`
    if isinstance(value, ast.Call) and isinstance(value.func, ast.Name) \
            and value.func.id == "Field":
        for kw in value.keywords:
            if kw.arg == "default":
                return isinstance(kw.value, ast.Constant) and kw.value.value is None
        # Field(None, ...) positional
        if value.args:
            return isinstance(value.args[0], ast.Constant) and value.args[0].value is None
    return False


def test_routing_models_do_not_default_the_model():
    tree = ast.parse(_source())
    bad = []
    for cls in sorted(ROUTING_MODELS):
        default = _model_field_default(tree, cls)
        if default == "MISSING":
            pytest.fail(f"{cls}.model field not found -- guard is stale")
        if not _field_default_is_none(default):
            bad.append(cls)
    assert not bad, (
        f"{bad}: the `model` field defaults to a concrete value, so a caller "
        f"that sends only a task (no model) has it injected and _route_for "
        f"treats it as an explicit choice that beats the task route -- the "
        f"request goes to the wrong model/backend (Azure 404 DeploymentNotFound). "
        f"Default `model` to None.")


def test_chat_handler_routes_by_task():
    """The chat handler must route by task like generate() -- it used to ignore
    `task` and go straight to the global-backend branch, so a non-streaming chat
    caller naming a task (web_payload_generator: exploit_gen) never reached its
    configured model."""
    src = _source()
    m = re.search(r"\ndef chat\(req: ChatRequest\):(.*?)\n(?:@router|def )", src, re.S)
    assert m, "chat(req: ChatRequest) handler not found -- guard is stale"
    body = m.group(1)
    assert "_route_for(" in body, (
        "chat() must call _route_for(req.task, req.model) so a task/provider:model "
        "chat request routes through the resolved provider, not the global backend.")


def test_azure_post_strips_unsupported_sampling_params():
    """gpt-5/o-series reject temperature/top_p overrides; the single Azure post
    chokepoint must strip them and retry, not surface the 400."""
    src = _source()
    # locate the _azure_json_post body
    m = re.search(r"def _azure_json_post\(.*?\n(.*?)\ndef ", src, re.S)
    body = m.group(1) if m else src
    assert "temperature" in body and "top_p" in body, (
        "_azure_json_post must handle temperature/top_p rejection from reasoning "
        "models -- strip the offending param and retry (see the max_tokens -> "
        "max_completion_tokens precedent in the same function).")
    assert re.search(r'k\s*!=\s*"temperature"', body), (
        "_azure_json_post must DROP temperature on a 400 unsupported_value, not "
        "just mention it.")


# ── Live (skips cleanly without the service) ─────────────────────────────────

def test_task_only_request_routes_live():
    base = os.environ.get("LLM_QUERY_URL")
    if not base:
        pytest.skip("LLM_QUERY_URL not set")
    requests = pytest.importorskip("requests")
    try:
        r = requests.post(f"{base.rstrip('/')}/api/generate",
                          json={"prompt": "Reply with the single word OK.",
                                "stream": False, "task": "extract",
                                "options": {"temperature": 0.1}},
                          timeout=60)
    except Exception as e:  # pragma: no cover
        pytest.skip(f"llm_query unreachable: {type(e).__name__}")
    # A task-only request must route -- not 404 (DeploymentNotFound: the default
    # model leaked onto the wrong backend) nor 400 (unsupported temperature).
    assert r.status_code == 200, (
        f"task-only /api/generate returned {r.status_code}: {r.text[:200]} -- "
        f"task routing is being defeated (model default leaked) or the reasoning "
        f"model rejected a sampling param that was not stripped.")
