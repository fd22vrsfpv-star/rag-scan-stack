"""2026-10-10: the pre-run block checks that the programs a PoC command calls
are installed on the runner — beside the endpoint probe and the OOB sink check.

Operator: "we need to run a precheck to make sure commands are installed
before trying them to run local … that should be part of a precheck, just like
checking network connectivity." CVE-2024-22120 (first build after the
2026-10-09 rebuild) burned iteration 2 on `/bin/sh: 1: bc: not found` — the
command never reached the target and the refine loop learned nothing.

    docker run --rm -v /opt/rag-scan-stack:/work:ro -w /work python:3.12-slim \
      sh -c 'pip install -q pytest && PYTHONPATH=. python -m pytest tests/test_build_poc_prerun_tool_check.py -v'
"""
from __future__ import annotations

import ast as _ast
import logging
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
API = REPO / "app" / "rag-api" / "api.py"
FIXTURE = REPO / "tests" / "fixtures" / "poc_command_CVE-2024-22120_bc.txt"


def _func_src(name: str, path=API) -> str | None:
    src = path.read_text()
    tree = _ast.parse(src)
    for node in _ast.walk(tree):
        if isinstance(node, (_ast.FunctionDef, _ast.AsyncFunctionDef)) and node.name == name:
            return _ast.get_source_segment(src, node)
    return None


def _const_src(name: str) -> str:
    src = API.read_text()
    tree = _ast.parse(src)
    for node in tree.body:
        if isinstance(node, _ast.Assign) and any(isinstance(t, _ast.Name) and t.id == name for t in node.targets):
            return _ast.get_source_segment(src, node)
    raise AssertionError(f"module constant {name} not found")


@pytest.fixture(scope="module")
def ns():
    """_command_binaries + _prerun_tool_check with the runner probe stubbed."""
    n = {"logging": logging}
    for c in ("_SHELL_KEYWORDS", "_SHELL_BUILTINS", "_CMD_WRAPPERS", "_COMMON_RUNNER_TOOLS"):
        exec(_const_src(c), n)
    exec(_func_src("_command_binaries"), n)
    exec(_func_src("_prerun_tool_check"), n)
    return n


def test_real_22120_command_names_bc_and_nothing_bogus(ns):
    cmd = FIXTURE.read_text()
    assert "bc" in cmd                                   # the fixture is the real failing command
    bins = ns["_command_binaries"](cmd)
    assert "bc" in bins
    for must in ("curl", "grep", "awk", "head", "mktemp"):
        assert must in bins, must
    # nothing from inside quotes / variables / redirections / URLs
    for bogus in ("null", "sid", "zabbix", "zbx_session", "http", "Admin", "dev", "print", "K"):
        assert bogus not in bins, bogus


@pytest.mark.parametrize("cmd,expect", [
    ("curl -s -d 'a|b;c && d' http://h/", ["curl"]),                       # separators inside quotes
    ("python3 -c 'import os; os.system(\"id\")' | jq .", ["python3", "jq"]),
    ("sudo nmap -p80 10.0.0.1 && /usr/bin/curl -s x", ["nmap", "curl"]),  # wrapper + path
    ("FOO=1 BAR=$(mktemp) bar -x", ["mktemp", "bar"]),                      # env prefix, substitution
    ("cat <<EOF\nbc\nEOF", ["cat"]),                                        # heredoc body dropped
    ("( curl x >/dev/null 2>&1 ) ; sleep 2", ["curl", "sleep"]),            # redirections, subshell
    ("if [ -z \"$S\" ]; then echo no; exit 1; fi; curl y", ["curl"]),       # keywords + builtins
    ("echo $((1+2)); printf x", []),                                        # builtins only
    ("timeout 5 nc -z h 80 || true", ["nc"]),
])
def test_parser_cases(ns, cmd, expect):
    assert ns["_command_binaries"](cmd) == expect


def test_prerun_tool_check_short_circuits_only_on_a_confirmed_missing_program(ns):
    calls = []

    def fake_runner(names, ip, port, timeout=15):
        calls.append(list(names))
        return {n: {"bc": False, "curl": True, "python3": True, "awk": True}.get(n) for n in names}

    ns["_runner_has_binaries"] = fake_runner
    r = ns["_prerun_tool_check"]("10.0.0.5", 8080, "curl -s h | bc")
    assert r["ok"] is False and r["missing"] == ["bc"] and r["binaries"] == ["curl", "bc"]
    assert "bc not installed" in r["reason"]
    assert "curl" in r["available_alternatives"] and "bc" not in r["available_alternatives"]
    # the common toolset rides along in the same probe so the message can name alternatives
    assert "python3" in calls[0] and "curl" in calls[0]

    # unanswered probe → unchecked, NOT missing: unreachable is not absent
    ns["_runner_has_binaries"] = lambda names, ip, port, timeout=15: {n: None for n in names}
    r2 = ns["_prerun_tool_check"]("10.0.0.5", 8080, "curl -s h | bc")
    assert r2["ok"] is True and r2["missing"] == [] and r2["unchecked"] == ["curl", "bc"]
    assert "run proceeds" in r2["reason"]

    # nothing external → skipped, no probe
    ns["_runner_has_binaries"] = lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not probe"))
    r3 = ns["_prerun_tool_check"]("10.0.0.5", 8080, "echo hi")
    assert r3["skipped"] and r3["ok"]


def test_loop_runs_the_tool_check_in_the_prerun_block_and_skips_the_listener():
    loop = _func_src("_run_refine_poc")
    assert loop
    i_probe = loop.index("_prerun_payload_probe(ip, port, command")
    i_oob = loop.index("_prerun_oob_check(ip, port, command")
    i_tool = loop.index("_prerun_tool_check(ip, port, command")
    i_trace = loop.index('"prerun_tool_check"')
    i_short = loop.index("PRERUN_TOOL_MISSING")
    i_post = loop.index('json={"command": command, "target": str(ip), "port": port, "timeout": _vt}')
    # same pre-run block, ordered: probe → oob → tools → (short-circuit | listener call)
    assert i_probe < i_oob < i_tool < i_trace < i_short < i_post
    assert "ec = 45" in loop and "skipped_runs_prerun_tool_missing" in loop
    assert "PRERUN_TOOL_AVAILABLE" in loop
    # the endpoint-probe short-circuit is now the elif of the tool short-circuit
    assert 'elif _probe.get("ok") is False:' in loop
    assert "if _probe.get(\"ok\") is False:" not in loop.replace('elif _probe.get("ok") is False:', "")


def test_runner_probe_is_cached_and_never_raises():
    src = _func_src("_runner_has_binaries")
    assert src and "_RUNNER_BIN_CACHE" in src and "_RUNNER_BIN_CACHE_TTL" in src
    assert '"/vectors/run"' in src.replace("'", '"') or "/vectors/run" in src
    assert "command -v" in src and "except Exception" in src
    assert '"prerun_tool_check"' in _const_src("_KEY_TRACE_PHASES")
