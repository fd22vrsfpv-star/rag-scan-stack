"""Invariants every scan-initiating code path must hold.

Run on demand:

    pytest tests/test_dispatch_invariants.py -v

Two rules that CLAUDE.md states and that nothing previously enforced:

  1. Anything that sends traffic to a host passes the scope gate.
  2. Anything that initiates a scan is bounded by MAX_CONCURRENT_SCANS.

Both were violated in ways prose could not prevent. Dispatch had no scope check
at all, so 14 recommendations targeting third-party Cloudflare addresses sat in
the database with several already executed. And the recommender ignored the
engagement scan limit entirely, so one call per open port per scan — each of
which also auto-executed tools — saturated the service until dispatches timed
out and were recorded as failures.

HOW THIS TEST WORKS
-------------------
It is a RATCHET, not a pass/fail audit. Modules that initiate traffic are
discovered from source, then checked against a known-debt list. Existing gaps
are listed explicitly with a reason; a NEW ungated dispatcher fails the test by
name. That keeps the suite green (so a failure is a real signal) while making
the remaining debt impossible to lose track of.

To close an item: add the gate, then delete its entry from the list below. To
add a new dispatcher: add the gate. Do not extend the list without a reason —
that is the whole point of it being visible.
"""
import ast
import os
import re

import pytest

REPO = os.path.join(os.path.dirname(__file__), "..")

# Source markers that mean "this module can cause traffic to reach a target".
_DISPATCH_MARKERS = (
    "/tools/execute", "execute-recommended", "/jobs/", "subprocess.Popen",
    "subprocess.run", "asyncio.create_subprocess",
)
_SCOPE_MARKERS = ("_host_in_scope", "is_in_scope", "scope_gate", "host_in_scope")
_LIMIT_MARKERS = ("MAX_CONCURRENT_SCANS",)

# Directories worth scanning. Tests, migrations and the frontend are excluded.
_ROOTS = (
    "dashboard/bff", "scan_recommender", "nmap_scanner", "pd_runner",
    "web_scanner", "osint_runner", "kali_listener", "autogen_agents",
    "app/rag-api", "exploit_runner", "playwright_scanner", "brutus_runner",
)

# ── Known debt ────────────────────────────────────────────────────────────
#
# Every entry is a module that can initiate traffic without the stated gate.
# Each carries WHY it is tolerated for now. Shrink this list; do not grow it.

SCOPE_DEBT = {
    "app/rag-api/api.py":
        "job-creation endpoints fan out to the scanner services",
    "app/rag-api/health_router.py":
        "sends traffic to a supplied target without a scope check",
    "autogen_agents/autogen_service.py":
        "sends traffic to a supplied target without a scope check",
    "autogen_agents/mcp_server.py":
        "sends traffic to a supplied target without a scope check",
    "autogen_agents/scan_tools.py":
        "sends traffic to a supplied target without a scope check",
    "brutus_runner/brutus_runner.py":
        "sends traffic to a supplied target without a scope check",
    "dashboard/bff/polling.py":
        "re-dispatches queued jobs and never re-checks the scope they were created under",
    "dashboard/bff/routers/nodes.py":
        "remote-node execution path",
    "dashboard/bff/services/pipeline_orchestrator.py":
        "drives multi-stage scans; the gate belongs at stage dispatch",
    "exploit_runner/script_executor.py":
        "sends traffic to a supplied target without a scope check",
    "nmap_scanner/cred_checker.py":
        "sends traffic to a supplied target without a scope check",
    "osint_runner/service_enum_cli.py":
        "sends traffic to a supplied target without a scope check",
    "pd_runner/pd_runner.py":
        "sends traffic to a supplied target without a scope check",
    "playwright_scanner/metadata_extractor.py":
        "sends traffic to a supplied target without a scope check",
    "playwright_scanner/playwright_scanner.py":
        "sends traffic to a supplied target without a scope check",
    "scan_recommender/exploits_rag.py":
        "sends traffic to a supplied target without a scope check",
    "scan_recommender/scan_recommender.py":
        "auto-execute dispatches tools straight from recommendations",
    "web_scanner/scan_pipeline.py":
        "sends traffic to a supplied target without a scope check",
    "web_scanner/web_scan.py":
        "sends traffic to a supplied target without a scope check",
}

LIMIT_DEBT = {
    "app/rag-api/api.py":
        "job-creation endpoints fan out to the scanner services",
    "app/rag-api/health_router.py":
        "initiates scans without consulting the shared limit",
    "autogen_agents/autogen_service.py":
        "initiates scans without consulting the shared limit",
    "autogen_agents/mcp_server.py":
        "initiates scans without consulting the shared limit",
    "autogen_agents/scan_tools.py":
        "initiates scans without consulting the shared limit",
    "brutus_runner/brutus_runner.py":
        "initiates scans without consulting the shared limit",
    "dashboard/bff/routers/assets.py":
        "main recommendation dispatcher; batch size is bounded only by how many ids the caller passes",
    "dashboard/bff/services/pipeline_orchestrator.py":
        "drives multi-stage scans; the gate belongs at stage dispatch",
    "dashboard/bff/services/tool_executor.py":
        "runs tools for the pipeline; needs the same gate as routers/assets.py",
    "exploit_runner/script_executor.py":
        "initiates scans without consulting the shared limit",
    "kali_listener/listener_service.py":
        "executes whatever it is handed — the LAST line of defence, and the best place to refuse an out-of-scope target even when a caller insists",
    "nmap_scanner/cred_checker.py":
        "initiates scans without consulting the shared limit",
    "osint_runner/osint_runner.py":
        "initiates scans without consulting the shared limit",
    "osint_runner/service_enum_cli.py":
        "initiates scans without consulting the shared limit",
    "pd_runner/pd_runner.py":
        "initiates scans without consulting the shared limit",
    "playwright_scanner/metadata_extractor.py":
        "initiates scans without consulting the shared limit",
    "playwright_scanner/playwright_scanner.py":
        "initiates scans without consulting the shared limit",
    "scan_recommender/exploits_rag.py":
        "initiates scans without consulting the shared limit",
    "web_scanner/scan_pipeline.py":
        "initiates scans without consulting the shared limit",
    "web_scanner/web_scan.py":
        "initiates scans without consulting the shared limit",
}


def _python_files():
    for root in _ROOTS:
        base = os.path.join(REPO, root)
        if not os.path.isdir(base):
            continue
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames[:] = [d for d in dirnames
                           if d not in {"__pycache__", "node_modules", ".git", "tests"}]
            for fn in filenames:
                if fn.endswith(".py"):
                    full = os.path.join(dirpath, fn)
                    yield os.path.relpath(full, REPO).replace(os.sep, "/"), full


def _initiates_traffic(src: str) -> bool:
    """True if the module appears to send traffic at a target.

    Comments and docstrings are stripped first: several modules DISCUSS
    /tools/execute in prose, and counting those would fill the debt list with
    files that dispatch nothing.
    """
    code = _strip_comments(src)
    return any(m in code for m in _DISPATCH_MARKERS)


def _strip_comments(src: str) -> str:
    out = []
    for line in src.splitlines():
        stripped = line.lstrip()
        if stripped.startswith("#"):
            continue
        out.append(re.sub(r"\s+#.*$", "", line))
    code = "\n".join(out)
    # Drop docstrings, which is where most of the prose lives.
    try:
        tree = ast.parse(src)
        spans = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                doc = ast.get_docstring(node, clean=False)
                if doc:
                    spans.append(doc)
        for doc in spans:
            code = code.replace(doc, "")
    except SyntaxError:
        pass
    return code


def _dispatchers():
    found = {}
    for rel, full in _python_files():
        try:
            src = open(full, encoding="utf-8", errors="replace").read()
        except OSError:                          # pragma: no cover
            continue
        if _initiates_traffic(src):
            found[rel] = _strip_comments(src)
    return found


@pytest.fixture(scope="module")
def dispatchers():
    d = _dispatchers()
    if not d:                                    # pragma: no cover
        pytest.skip("no dispatching modules found — repo layout changed?")
    return d


def test_discovery_finds_the_known_dispatchers(dispatchers):
    """Sanity check on the detector itself.

    If this stops finding the main dispatcher, the two invariant tests below
    would pass vacuously — which is the failure mode that makes a guard
    worthless.
    """
    assert "dashboard/bff/routers/assets.py" in dispatchers, \
        "detector no longer sees the main dispatcher; the guards below are vacuous"


def test_no_new_ungated_dispatchers(dispatchers):
    """Every traffic-initiating module passes the scope gate, or is known debt."""
    ungated = {rel for rel, code in dispatchers.items()
               if not any(m in code for m in _SCOPE_MARKERS)}
    new = sorted(ungated - set(SCOPE_DEBT))
    assert not new, (
        "these modules can send traffic to a host without a scope check:\n  "
        + "\n  ".join(new)
        + "\n\nAdd the scope gate (see dashboard/bff/routers/assets.py::_host_in_scope). "
          "Do NOT add them to SCOPE_DEBT without a reason — an out-of-scope scan is "
          "unauthorised traffic, not a style issue.")


def test_no_new_unbounded_scan_initiators(dispatchers):
    """Every scan initiator respects the engagement limit, or is known debt."""
    unbounded = {rel for rel, code in dispatchers.items()
                 if not any(m in code for m in _LIMIT_MARKERS)}
    new = sorted(unbounded - set(LIMIT_DEBT))
    assert not new, (
        "these modules initiate scans without consulting MAX_CONCURRENT_SCANS:\n  "
        + "\n  ".join(new)
        + "\n\nBound them by the engagement scan limit rather than a private number "
          "(see scan_recommender.py::SCAN_LIMIT).")


def test_debt_lists_do_not_contain_resolved_entries(dispatchers):
    """Once a module gains its gate, its debt entry must be removed.

    Without this the lists rot into permanent exemptions and the ratchet stops
    ratcheting.
    """
    fixed_scope = [rel for rel in SCOPE_DEBT
                   if rel in dispatchers
                   and any(m in dispatchers[rel] for m in _SCOPE_MARKERS)]
    fixed_limit = [rel for rel in LIMIT_DEBT
                   if rel in dispatchers
                   and any(m in dispatchers[rel] for m in _LIMIT_MARKERS)]
    assert not fixed_scope, f"now gated — remove from SCOPE_DEBT: {fixed_scope}"
    assert not fixed_limit, f"now bounded — remove from LIMIT_DEBT: {fixed_limit}"


def test_debt_entries_reference_real_files():
    """A stale path in the debt list silently exempts nothing (or worse, hides a
    renamed module that lost its gate)."""
    for rel in list(SCOPE_DEBT) + list(LIMIT_DEBT):
        assert os.path.exists(os.path.join(REPO, rel)), f"debt entry no longer exists: {rel}"


def test_every_debt_entry_has_a_reason():
    for rel, why in list(SCOPE_DEBT.items()) + list(LIMIT_DEBT.items()):
        assert why and len(why) > 15, f"{rel} needs a real reason, got {why!r}"
