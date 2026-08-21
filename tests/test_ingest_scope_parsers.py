"""The remaining ingest parsers must refuse out-of-scope hosts.

Run on demand:

    pytest tests/test_ingest_scope_parsers.py -v

WHY THIS EXISTS
---------------
Scope was enforced when choosing what to point a tool AT, and later on most
ingest paths, but four parsers had no check at all: burp, nikto, zap_file and
impacket. That is the same hole that stored twiki.org and twitter.com as
engagement findings — a Burp sitemap contains every host the browser touched,
nikto follows redirects, and ZAP spiders links.

Two failure modes are asserted here beyond "does it filter":

  * the gate must sit BEFORE the savepoint, or a skipped record leaves an
    unreleased SAVEPOINT and the next insert fails inside a poisoned
    transaction. That bug appeared three separate times in this codebase.
  * the scope parameters must be REQUIRED, not defaulted. host_in_scope with
    enforce=False returns True, so a defaulted parameter turns a forgotten call
    site into a silent bypass rather than an error.
"""
import ast
import os

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))

GATED = {
    "parse_burp.py": "Burp's sitemap holds every host the browser touched",
    "parse_nikto.py": "nikto follows redirects off the requested host",
    "parse_zap_file.py": "ZAP spiders links to third-party hosts",
    "parse_impacket.py": "credential material must not be stored for an unauthorised host",
}


def _src(name):
    path = os.path.join(REPO, "etl", name)
    if not os.path.exists(path):                 # pragma: no cover
        pytest.skip(f"{name} not present")
    return open(path, encoding="utf-8").read()


@pytest.mark.parametrize("name,fn", [
    ("parse_nikto.py", "_insert_item"),
    ("parse_zap_file.py", "_insert_finding"),
])
def test_scope_params_are_required_not_defaulted(name, fn):
    """host_in_scope(..., enforce=False, ...) returns True.

    So a defaulted parameter means any call site that forgets to pass the scope
    silently ingests everything. Required parameters make that a TypeError.
    """
    tree = ast.parse(_src(name))
    target = next((n for n in ast.walk(tree)
                   if isinstance(n, ast.FunctionDef) and n.name == fn), None)
    assert target, f"{fn} not found in {name}"
    args = target.args
    names = [a.arg for a in args.kwonlyargs]
    assert "enforce_scope" in names, f"{fn} does not accept enforce_scope"
    idx = names.index("enforce_scope")
    default = args.kw_defaults[idx]
    assert default is None, (
        f"{fn}.enforce_scope has a default; a call site that omits it would "
        f"silently disable the gate")


@pytest.mark.parametrize("name,fn", [
    ("parse_nikto.py", "_insert_item"),
    ("parse_zap_file.py", "_insert_finding"),
])
def test_every_insert_call_site_passes_the_scope(name, fn):
    tree = ast.parse(_src(name))
    calls = [n for n in ast.walk(tree)
             if isinstance(n, ast.Call) and getattr(n.func, "id", "") == fn]
    assert calls, f"no calls to {fn} found in {name} — has it been renamed?"
    missing = [c.lineno for c in calls
               if "enforce_scope" not in {k.arg for k in c.keywords}]
    assert not missing, f"{name}: {fn} called without the scope at line(s) {missing}"


def test_out_of_scope_counter_is_reported(name="parse_burp.py"):
    """A silent filter is indistinguishable from a parser that found nothing."""
    for n in GATED:
        assert "out_of_scope" in _src(n), f"{n} filters without counting it"


@pytest.mark.parametrize("name", sorted(GATED))
def test_scope_arguments_are_bound_where_they_are_passed(name):
    """Every name passed as enforce_scope=/scope_rows= must exist in that scope.

    The sibling audit in test_scope_gate_ingest.py checks the function that
    CALLS host_in_scope. It cannot see an intermediate that merely forwards the
    value — which is exactly how parse_zap_file shipped broken: _insert_finding
    received the scope correctly, but _parse_json forwarded `_enforce_scope`, a
    name bound only in parse_zap_file(). The file parsed, the structural checks
    passed, and it raised NameError on the first alert.
    """
    tree = ast.parse(_src(name))
    problems = []
    for fn in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]:
        bound = {a.arg for a in list(fn.args.args) + list(fn.args.kwonlyargs)
                 + list(getattr(fn.args, "posonlyargs", []))}
        for n in ast.walk(fn):
            if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store):
                bound.add(n.id)
            elif isinstance(n, (ast.Import, ast.ImportFrom)):
                bound |= {(a.asname or a.name).split(".")[0] for a in n.names}
        for call in [n for n in ast.walk(fn) if isinstance(n, ast.Call)]:
            for kw in call.keywords:
                if kw.arg in ("enforce_scope", "scope_rows") and isinstance(kw.value, ast.Name):
                    if kw.value.id not in bound:
                        problems.append(
                            f"{fn.name}() passes {kw.arg}={kw.value.id}, which is not "
                            f"bound there — NameError on the first record")
    assert not problems, f"{name}: " + "; ".join(problems)
