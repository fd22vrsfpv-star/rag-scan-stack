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
# Names that constitute "this module consults the scope". Deliberately broad:
# a detector that misses a real gate produces a FALSE debt entry, which is worse
# than no list — it hides the genuine gaps in noise. routers/scans.py was
# flagged for weeks of this list's life despite calling _enforce_scan_scope()
# before every launch.
_SCOPE_MARKERS = (
    "_host_in_scope", "is_in_scope", "scope_gate", "host_in_scope",
    "scope_guard", "_enforce_scan_scope", "enforce_scope", "scope_rows",
)
# NOT a marker: the bare table name "scope_targets". Modules query it for
# reasons that are not authorisation — DDL, health checks, CIDR grouping, and
# the in_scope column the recommendations UI displays. Counting those cleared
# three modules that dispatch with no gate at all.
# A module is bounded either by reading the limit itself, or by routing its
# execution through the shared runner in common/tool_job.py, which holds a
# semaphore sized by MAX_CONCURRENT_SCANS. Naming only the env var reported
# pd_runner and osint_runner as unbounded immediately after they were bounded —
# the same too-narrow-marker mistake the scope list made with scans.py.
# get_max_concurrent is the BFF's accessor: it literally returns
# MAX_CONCURRENT_SCANS and is the only correct way to read it at runtime
# there, because set_max_concurrent() rebinds the module global. Without it
# as a marker, dashboard/bff/routers/assets.py — the REFERENCE dispatcher —
# matched only on a log-message string that happens to name the env var,
# which is barely stronger than the comments _strip_comments() removes.
_LIMIT_MARKERS = ("MAX_CONCURRENT_SCANS", "run_tool_job", "scan_slot",
                  "get_max_concurrent")

# Directories worth scanning. Tests, migrations and the frontend are excluded.
_ROOTS = (
    "dashboard/bff", "scan_recommender", "nmap_scanner", "pd_runner",
    "web_scanner", "osint_runner", "kali_listener", "autogen_agents",
    "app/rag-api", "exploit_runner", "playwright_scanner", "brutus_runner",
    # node_manager was MISSING from this tuple, so the entire remote-node path
    # — SSH to a box and run scanners there, where nothing in the stack sees the
    # traffic — never appeared in either debt list. A blind spot in the audit is
    # worse than a debt entry, because the debt entry is at least visible.
    "node_manager",
)

# ── Known debt ────────────────────────────────────────────────────────────
#
# Every entry is a module that can initiate traffic without the stated gate.
# Each carries WHY it is tolerated for now. Shrink this list; do not grow it.

SCOPE_DEBT = {
}

# Flagged by the detector, but these do NOT send traffic to an engagement
# target. They are separated from SCOPE_DEBT deliberately: leaving them there
# labelled "sends traffic to a supplied target without a scope check" states
# something untrue about the code, and it inflates the debt count so the
# entries that DO need a gate are harder to see.
#
# Adding a scope gate to the first two would be actively harmful, not merely
# unnecessary — the gate fails closed, and neither destination is ever in an
# engagement scope, so every call would be refused.
LIMIT_NOT_APPLICABLE = {
    "autogen_agents/autogen_service.py":
        "does not initiate scans itself — it orchestrates and reports. The slot "
        "is taken in scan_tools.py, where the dispatch actually happens; taking "
        "one here too would double-count a single scan.",
    "autogen_agents/mcp_server.py":
        "does not initiate scans — it forwards an MCP tool call to the "
        "autogen-agents API. The slot is held downstream in scan_tools.py.",
    "osint_runner/service_enum_cli.py":
        "runs on a REMOTE NODE, uploaded there by node_manager, with neither "
        "common/ nor a database — there is no shared semaphore to consult. The "
        "slot is held upstream: node_manager.remote_scan wraps the whole "
        "dispatch, so the ceiling is applied where the work is admitted.",
    "app/rag-api/health_router.py":
        "does not initiate scans — it polls our own containers' /health.",
    "scan_recommender/exploits_rag.py":
        "does not initiate scans — LLM calls plus a local searchsploit/git pull.",
    "playwright_scanner/metadata_extractor.py":
        "runs INSIDE a playwright scan that already holds a slot. Taking a second "
        "one would double-count a single scan and can deadlock the pool at the "
        "ceiling. Its scope gate IS present, per URL.",
    "node_manager/ssh_manager.py":
        "SSH transport, not a scan initiator; remote_scan holds the slot around "
        "the whole dispatch, so bounding here too would double-count one scan.",
}

GATE_NOT_APPLICABLE = {
    "autogen_agents/autogen_service.py":
        "orchestration front door. Every .post goes to the configured Azure LLM "
        "endpoint (a health-check ping), to {service_url}/jobs/{id}/restart on "
        "OUR OWN scanner services by job id, or to rag-api "
        "(/scans/update-status, /webhooks/emit). No operator-supplied host. The "
        "scanning it drives goes through scan_tools.py, which IS gated.",
    "autogen_agents/mcp_server.py":
        "MCP front door. Its posts go to {LOG_API_URL}/logs/ingest and "
        "{LOG_API_URL}/pentest — the autogen-agents API itself — and the "
        "argument it forwards is a free-text `target_description`, not a host. "
        "The work lands in autogen_service and then scan_tools.py, gated there.",
    "app/rag-api/health_router.py":
        "checks OUR OWN containers. `url` is built from the hardcoded "
        "service_ports/docker_service_names maps and the name is whitelisted "
        "(unknown -> 400), so the destination is never operator-supplied. Our "
        "own services are correctly absent from any engagement scope, so a "
        "gate here would refuse every health check.",
    "scan_recommender/exploits_rag.py":
        "its requests.post calls go to _azure_embed_url()/_azure_chat_url() — "
        "the configured LLM endpoint — and its subprocess calls are `git pull` "
        "on the local exploitdb checkout and `searchsploit`. Nothing here "
        "contacts a scan target.",
    "node_manager/ssh_manager.py":
        "SSH transport. Its `host` argument is the NODE, not the scan target, "
        "so gating on it would check the wrong value and give false "
        "confidence. The target-level gate is upstream in "
        "node_manager.remote_scan.",
    "osint_runner/service_enum_cli.py":
        "NOT shipped in the osint-runner image; node_manager uploads it to a "
        "remote node and runs it there with no etl/ and no database, so an "
        "etl-based gate would fail closed and kill email/dns/service enum. "
        "Gated upstream in node_manager.remote_scan instead.",
}

LIMIT_DEBT = {
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
    new = sorted(ungated - set(SCOPE_DEBT) - set(GATE_NOT_APPLICABLE))
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
    new = sorted(unbounded - set(LIMIT_DEBT) - set(LIMIT_NOT_APPLICABLE))
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
    for rel in (list(SCOPE_DEBT) + list(LIMIT_DEBT)
                + list(GATE_NOT_APPLICABLE) + list(LIMIT_NOT_APPLICABLE)):
        assert os.path.exists(os.path.join(REPO, rel)), f"debt entry no longer exists: {rel}"


def test_not_applicable_entries_carry_evidence_not_a_shrug():
    """The two NOT_APPLICABLE lists must not become SCOPE_DEBT by another name.

    A debt entry says "this needs a gate and does not have one". A
    not-applicable entry claims something stronger — that there is no target to
    gate, or that the gate is genuinely elsewhere — and that claim has to be
    checkable by a reader. So the reason must be substantive and must NOT reuse
    the generic debt phrasing, which would turn the list into a way to make a
    real violation disappear.
    """
    generic = ("sends traffic to a supplied target without a scope check",
               "initiates scans without consulting the shared limit")
    for name, table in (("GATE_NOT_APPLICABLE", GATE_NOT_APPLICABLE),
                        ("LIMIT_NOT_APPLICABLE", LIMIT_NOT_APPLICABLE)):
        for rel, why in table.items():
            assert why.strip() not in generic, (
                f"{name}[{rel}] reuses the generic debt reason — that is a "
                "violation being reclassified, not an exemption")
            assert len(why) > 60, (
                f"{name}[{rel}] needs the evidence, not a shrug: got {why!r}")
            # It has to say either what it talks to instead, or where the real
            # gate/slot is.
            # Each keyword marks a claim a reader can CHECK: what it talks to
            # instead, or where the real gate/slot lives. "downstream" is as
            # specific as "upstream" — an orchestration front door whose work
            # lands in a gated module is exempt for a verifiable reason, and the
            # original list simply had not met that shape yet.
            assert any(k in why.lower() for k in (
                "own container", "llm", "upstream", "downstream", "transport",
                "already holds", "does not initiate", "local", "hardcoded",
                "never operator", "api itself")), (
                f"{name}[{rel}] does not say why it is exempt: {why!r}")


def test_a_module_cannot_be_in_both_a_debt_and_an_exemption_list():
    """Otherwise the same file reads as both "needs a gate" and "does not"."""
    both_scope = set(SCOPE_DEBT) & set(GATE_NOT_APPLICABLE)
    both_limit = set(LIMIT_DEBT) & set(LIMIT_NOT_APPLICABLE)
    assert not both_scope, f"in SCOPE_DEBT and GATE_NOT_APPLICABLE: {both_scope}"
    assert not both_limit, f"in LIMIT_DEBT and LIMIT_NOT_APPLICABLE: {both_limit}"


def test_every_debt_entry_has_a_reason():
    for rel, why in (list(SCOPE_DEBT.items()) + list(LIMIT_DEBT.items())
                     + list(GATE_NOT_APPLICABLE.items())
                     + list(LIMIT_NOT_APPLICABLE.items())):
        assert why and len(why) > 15, f"{rel} needs a real reason, got {why!r}"


# ── Exploit execution requires an explicit operator decision ──────────────

def test_exploit_execution_is_opt_in_and_defaults_off():
    """approve_exploits must default to False.

    /api/scan-recommendations/run is called by the recon agent
    (services/recon_agent.py) and by agent-session finalisation
    (autogen_service.py). Neither is a human deciding to exploit a host, and
    neither sets this flag — so the default is what stops an agent
    auto-exploiting. A caller that does not know the flag exists cannot.
    """
    src = open(os.path.join(REPO, "dashboard", "bff", "routers", "assets.py")).read()
    m = re.search(r"approve_exploits: bool = (\w+)", src)
    assert m, "approve_exploits field not found on the run request"
    assert m.group(1) == "False", (
        f"approve_exploits defaults to {m.group(1)} — an automated caller would "
        f"auto-exploit without asking")


def test_direct_exploit_path_is_gated_on_the_flag():
    """The direct-execution branch must test the flag, not just the scanner."""
    src = open(os.path.join(REPO, "dashboard", "bff", "routers", "assets.py")).read()
    assert 'elif scanner == "metasploit" and body.approve_exploits:' in src, (
        "the direct metasploit branch is not gated on approve_exploits")
    # And the approval-queue branch must still exist for everything else.
    assert 'elif scanner == "metasploit":' in src, (
        "the approval-queue fallback is gone — automated callers would have no path")


def test_msf_proxy_refuses_rather_than_connecting_direct():
    """An unusable proxy must fail the run, not silently bypass it.

    The operator selected a proxy profile; running the module direct would put
    traffic on a path they did not choose, which is worse than not running.
    """
    src = open(os.path.join(REPO, "exploit_runner", "exploit_runner.py")).read()
    assert "refusing to run the module unproxied" in src, (
        "a proxy that cannot be expressed as an MSF Proxies value must refuse")

# ── the gates added when this list was shrunk ────────────────────────────────

@pytest.mark.unit
def test_async_scan_slot_exists_and_does_not_block_the_loop():
    """kali-listener and node-manager execute with `await create_subprocess_*`.

    Holding the THREADING semaphore there would block the event loop for up to
    SLOT_WAIT_TIMEOUT (1800s), stalling every other request including the health
    check that keeps the container marked healthy. So the async variant is not a
    convenience — a sync slot in an async executor is a self-inflicted outage.
    """
    import asyncio
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "_tj", os.path.join(REPO, "common", "tool_job.py"))
    tj = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tj)

    assert hasattr(tj, "async_scan_slot"), "async_scan_slot missing"
    assert hasattr(tj, "active_async_slot_count")

    async def exercise():
        tj._async_slots = asyncio.Semaphore(2)
        peak = cur = 0
        async def worker():
            nonlocal peak, cur
            async with tj.async_scan_slot("j"):
                cur += 1
                peak = max(peak, cur)
                await asyncio.sleep(0.01)
                cur -= 1
        await asyncio.gather(*(worker() for _ in range(6)))
        return peak
    assert asyncio.run(exercise()) == 2, "async slot did not bound concurrency"

    async def times_out():
        tj._async_slots = asyncio.Semaphore(1)
        async with tj.async_scan_slot("holder"):
            try:
                async with tj.async_scan_slot("waiter", timeout=0.05):
                    return False
            except TimeoutError:
                return True
    assert asyncio.run(times_out()), "a full pool must raise, not hang"


@pytest.mark.unit
def test_enforce_target_scope_fails_closed():
    """"Cannot check" must never look like "is authorised" to a tool about to
    send packets. Verified without a database, which is the failure mode."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "_sg", os.path.join(REPO, "etl", "scope_gate.py"))
    sg = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sg)

    assert hasattr(sg, "enforce_target_scope")
    sg._ENFORCE_CACHE.update({"rows": None, "at": 0.0})
    refusal = sg.enforce_target_scope("10.0.0.1", dsn="")
    assert refusal and "refusing" in refusal.lower(), (
        f"missing DSN must refuse, got {refusal!r}")


@pytest.mark.unit
def test_closed_entries_actually_carry_a_gate():
    """A debt entry removed from the list must have gained a real gate.

    The lists are checked by source marker, so deleting an entry without adding
    enforcement would quietly pass. These assert the enforcement itself.
    """
    cred = open(os.path.join(REPO, "nmap_scanner", "cred_checker.py"),
                encoding="utf-8").read()
    assert "enforce_target_scope" in cred and "_scope_refusal(target)" in cred, \
        "cred_checker was removed from SCOPE_DEBT but does not call the gate"
    assert cred.count("_scope_refusal(target)") >= 2, \
        "both hydra and nmap credential paths must be gated"

    listener = open(os.path.join(REPO, "kali_listener", "listener_service.py"),
                    encoding="utf-8").read()
    assert "async_scan_slot" in listener, \
        "kali_listener was removed from LIMIT_DEBT but holds no scan slot"
    assert "_SLOTS_AVAILABLE" in listener and "refusing to execute" in listener, \
        "a missing slot module must refuse, not run unbounded"

    nm = open(os.path.join(REPO, "node_manager", "node_manager.py"),
              encoding="utf-8").read()
    assert "_remote_scope_refusal" in nm and "async_scan_slot" in nm, \
        "node_manager.remote_scan must gate scope AND hold a slot"


@pytest.mark.unit
def test_the_remote_node_path_is_audited():
    """node_manager was absent from _ROOTS, so the entire remote path — SSH to a
    box and run scanners there, where nothing in the stack sees the traffic —
    never appeared in either debt list. A blind spot is worse than a debt entry."""
    assert "node_manager" in _ROOTS


@pytest.mark.unit
def test_uploaded_remote_script_is_not_falsely_gated():
    """osint_runner/service_enum_cli.py must NOT carry an etl-based gate.

    It is not shipped in the osint-runner image; node_manager uploads it to a
    remote node and runs it with python3, where etl/ and the database do not
    exist. An etl-based gate there fails closed and kills email/dns/service
    enum outright — a gate in the wrong layer is an outage, not a safeguard.
    """
    path = os.path.join(REPO, "osint_runner", "service_enum_cli.py")
    src = open(path, encoding="utf-8").read()

    # Check CODE, not prose: the docstring explains why the gate is absent and
    # names the function, so a bare substring search flags its own explanation.
    # Same trap the SQL guard hit when a comment mentioning dp.get("method")
    # read as a column reference.
    tree = ast.parse(src)
    imported, called = [], []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and (node.module or "").startswith("etl"):
            imported.extend(a.name for a in node.names)
        if isinstance(node, ast.Call):
            fn = node.func
            name = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", "")
            if name in ("enforce_target_scope", "_scope_refusal"):
                called.append(name)
    assert not imported, (
        f"service_enum_cli imports from etl ({imported}) — it runs on a remote "
        "node where etl does not exist, so this would refuse every enumeration")
    assert not called, f"service_enum_cli calls the etl gate ({called})"
