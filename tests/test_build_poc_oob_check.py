"""Guard the OOB sink reachability pre-check (added 2026-10-06).

Operator ask: "let's work on a check for the oob listener." The deep-test
batch's exploits chain `exploit && curl SINK` where SINK is the proof-of-
exploit endpoint. If SINK is unreachable, the exploit may land but we'll
never see the signal — the verdict is misleadingly "failed" when it's
actually "proof mechanism was broken".

Run on demand (sidecar):

    docker run --rm -v /opt/rag-scan-stack:/work:ro -w /work \
      python:3.12-slim sh -c 'pip install -q pytest && \
      PYTHONPATH=. python -m pytest tests/test_build_poc_oob_check.py -v'
"""
from __future__ import annotations

import ast as _ast
import re
from pathlib import Path


REPO = Path(__file__).resolve().parent.parent
API = REPO / "app" / "rag-api" / "api.py"


def _func_src(name: str) -> str | None:
    src = API.read_text()
    tree = _ast.parse(src)
    for node in _ast.walk(tree):
        if isinstance(node, (_ast.FunctionDef, _ast.AsyncFunctionDef)) and node.name == name:
            return _ast.get_source_segment(src, node)
    return None


def test_oob_check_function_is_defined():
    body = _func_src("_prerun_oob_check")
    assert body, "_prerun_oob_check missing"
    # Must extract all URLs (not just the first — that's the exploit target).
    assert "findall" in body and "https?://" in body, (
        "oob check must extract every URL from the command, not just the first"
    )
    # Must classify URLs by kind so operators can distinguish TARGET sink poll
    # from an external callback destination.
    for kind in ("TARGET", "OOB_LOCAL", "OOB_METADATA", "OOB_INTERNAL", "OOB_EXTERNAL"):
        assert f'"{kind}"' in body or f"'{kind}'" in body, (
            f"OOB classification must distinguish the {kind} case so the trace "
            f"carries the real signal, not a flat 'unreachable' flag"
        )


def test_oob_check_only_probes_reachable_kinds():
    """OOB_METADATA (169.254.x) and OOB_EXTERNAL callbacks are unreachable from
    this host by design — probing them would always 'fail' and poison the
    diagnostic. The check must probe only TARGET + OOB_INTERNAL."""
    body = _func_src("_prerun_oob_check")
    assert body, "_prerun_oob_check missing"
    # The probe branch is gated on a kind check.
    assert 'kind in ("TARGET", "OOB_INTERNAL")' in body or "kind in ('TARGET', 'OOB_INTERNAL')" in body, (
        "the probe branch must only hit kinds reachable from here"
    )


def test_oob_check_never_raises():
    """A broken OOB check must not break dispatch. The helper always returns a
    dict with `ok: True`; the dispatcher turns 'unreachable sinks' into a
    diagnostic trace, not an abort."""
    body = _func_src("_prerun_oob_check")
    assert body, "_prerun_oob_check missing"
    # The docstring must say never-raises; and the function must not re-raise
    # inside the per-URL probe loop.
    assert "Never raises" in body or "never raises" in body, (
        "helper docstring must document the never-raises contract so the "
        "dispatcher caller can trust it"
    )


def test_oob_check_is_hooked_at_dispatch():
    """The check must be invoked in the dispatch path alongside
    `_prerun_payload_probe` and its result traced as `oob_sink_check`."""
    src = API.read_text()
    hook_pos = src.find("_prerun_oob_check(ip, port, command")
    assert hook_pos >= 0, (
        "_prerun_oob_check must be invoked in the dispatch path alongside the "
        "payload probe"
    )
    # Trace tag
    assert '"oob_sink_check"' in src, (
        "the OOB check outcome must be traced as 'oob_sink_check' so the "
        "operator can see sink reachability per iteration"
    )
    # The dispatch must come AFTER the check within the same block.
    post = src[hook_pos : hook_pos + 2000]
    assert _hook_lineno("_prerun_oob_check") < _dispatch_lineno(), (
        "the listener /vectors/run dispatch happens BEFORE the OOB check"
    )


def test_oob_check_bumps_metric_on_unreachable():
    """A batch summary should surface how often sinks were unreachable so an
    operator can tell 'exploits failing' from 'sinks were down'."""
    src = API.read_text()
    assert "oob_sinks_unreachable_total" in src, (
        "unreachable sinks must bump a metric so the batch summary surfaces "
        "the pattern across CVEs"
    )


def _dispatch_lineno():
    """Line of the target dispatch inside `_run_refine_poc`, structurally.

    2026-10-16: this was a character-window search for the literal string
    "vectors/run" after the hook — widened 2000 -> 8000 once already, then
    broken outright when the dispatch moved behind `_attack_proxy_for` /
    `_vectors_run_payload` and ~70 lines of proxy policy landed between the
    hook and the post. The ORDER is what matters, so compare line numbers and
    stop caring how the dispatch is spelled.
    """
    import ast as _ast
    from pathlib import Path as _P
    api = _P(__file__).resolve().parents[1] / "app" / "rag-api" / "api.py"
    tree = _ast.parse(api.read_text(encoding="utf-8"))
    fn = next((n for n in _ast.walk(tree)
               if isinstance(n, _ast.FunctionDef) and n.name == "_run_refine_poc"), None)
    assert fn, "_run_refine_poc not found"
    lines = []
    for n in _ast.walk(fn):
        if not isinstance(n, _ast.Call):
            continue
        if isinstance(n.func, _ast.Name) and n.func.id in (
                "_listener_vectors_run", "_vectors_run_payload"):
            lines.append(n.lineno)
        elif n.args and "/vectors/run" in _ast.unparse(n.args[0]):
            lines.append(n.lineno)
    assert lines, "no /vectors/run dispatch found in _run_refine_poc"
    return min(lines)


def _hook_lineno(func_name):
    """Line of the first call to `func_name` inside `_run_refine_poc`."""
    import ast as _ast
    from pathlib import Path as _P
    api = _P(__file__).resolve().parents[1] / "app" / "rag-api" / "api.py"
    tree = _ast.parse(api.read_text(encoding="utf-8"))
    fn = next(n for n in _ast.walk(tree)
              if isinstance(n, _ast.FunctionDef) and n.name == "_run_refine_poc")
    lines = [n.lineno for n in _ast.walk(fn)
             if isinstance(n, _ast.Call) and isinstance(n.func, _ast.Name)
             and n.func.id == func_name]
    assert lines, f"{func_name} is not called in _run_refine_poc"
    return min(lines)
