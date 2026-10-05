"""Guard: asnmap is wired as a first-class recon tool, end to end.

The ASN scope-pivot reads `asnmap` findings from recon_findings, but nothing
collected them: the BFF had no `/api/scans/asnmap` dispatch and the recon
agent never ran asnmap. These structural checks pin the wiring that closes
that loop so it cannot silently regress.

All checks read SOURCE with `ast` (no import, works on a bare checkout) and
assert on parsed structure, never on code-fragment substrings.

Sabotage-proven:
  * Remove the 'asnmap' key from SCAN_ROUTES → test_bff_dispatches_asnmap fails.
  * Remove 'asnmap' from STAGE_TO_SCAN → test_recon_agent_runs_asnmap fails.
  * Remove the `scan_type != "asnmap"` gate exemption →
    test_asnmap_stage_is_ungated fails.
  * Drop 'asnmap' from THIRD_PARTY_PASSIVE_TYPES → test_asnmap_is_passive fails.
"""
import ast
import os

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCANS = os.path.join(REPO, "dashboard", "bff", "routers", "scans.py")
RECON = os.path.join(REPO, "dashboard", "bff", "services", "recon_agent.py")
OSINT = os.path.join(REPO, "osint_runner", "osint_runner.py")


def _module(path):
    if not os.path.exists(path):
        pytest.skip(f"{os.path.basename(path)} not present")
    return ast.parse(open(path, encoding="utf-8").read())


def _find_assign(tree, name):
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if getattr(t, "id", None) == name:
                    return node.value
        elif isinstance(node, ast.AnnAssign):
            # e.g. `SCAN_TARGET_TYPES: dict[str, set[str]] = {...}`
            if getattr(node.target, "id", None) == name and node.value is not None:
                return node.value
    return None


def _const(node):
    """Evaluate a literal node to a Python value, handling negative ints
    (ast parses `-1` as UnaryOp(USub, Constant(1)), not Constant(-1))."""
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
        inner = _const(node.operand)
        return -inner if isinstance(inner, (int, float)) else None
    return None


def _dict_keys_values(dict_node):
    """Return a list of (key, value_node) for a Dict literal, keys evaluated
    to Python values where possible."""
    return [( _const(k), v ) for k, v in zip(dict_node.keys, dict_node.values)]


def _int_elements(node):
    """Ints in a set/list literal, negatives included."""
    out = set()
    for e in getattr(node, "elts", []):
        v = _const(e)
        if isinstance(v, int):
            out.add(v)
    return out


# ─── BFF dispatch ───────────────────────────────────────────────────────────

def test_bff_dispatches_asnmap():
    """SCAN_ROUTES['asnmap'] routes to the osint runner's /jobs/asnmap."""
    tree = _module(SCANS)
    svc = _find_assign(tree, "SCAN_ROUTES")
    assert isinstance(svc, ast.Dict), "SCAN_ROUTES is not a dict literal"
    entry = None
    for key, val in _dict_keys_values(svc):
        if key == "asnmap":
            entry = val
            break
    assert entry is not None, "SCAN_ROUTES has no 'asnmap' entry"
    assert isinstance(entry, ast.Tuple) and len(entry.elts) >= 2
    service = entry.elts[0].value
    path = entry.elts[1].value
    assert service == "osint_runner_url", f"asnmap routed to {service!r}, not the osint runner"
    assert path == "/jobs/asnmap", f"asnmap path is {path!r}, not /jobs/asnmap"


def test_asnmap_is_passive():
    """asnmap discloses the target to a 3rd party but never touches it, so it
    is classified passive (gets the consent prompt, not a flat 403)."""
    tree = _module(SCANS)
    passive = _find_assign(tree, "THIRD_PARTY_PASSIVE_TYPES")
    assert passive is not None, "THIRD_PARTY_PASSIVE_TYPES missing"
    vals = {e.value for e in ast.walk(passive)
            if isinstance(e, ast.Constant) and isinstance(e.value, str)}
    assert "asnmap" in vals, "asnmap not classified passive in the BFF"


# ─── recon agent ────────────────────────────────────────────────────────────

def test_recon_agent_runs_asnmap():
    """The autonomous recon agent includes asnmap in its stage plan, as a
    SEED stage (always runs, even in kb-driven mode), for domain + ip."""
    tree = _module(RECON)
    stages = _find_assign(tree, "STAGE_TO_SCAN")
    assert isinstance(stages, ast.Dict)
    asn_stage = None
    for key, val in _dict_keys_values(stages):
        if isinstance(val, ast.Constant) and val.value == "asnmap":
            asn_stage = key
    assert asn_stage is not None, "STAGE_TO_SCAN has no asnmap stage — the agent never collects ASN data"

    seed = _find_assign(tree, "SEED_STAGES")
    seed_vals = _int_elements(seed)
    assert asn_stage in seed_vals, "asnmap stage is not a SEED stage, so kb-driven mode skips it"

    stt = _find_assign(tree, "SCAN_TARGET_TYPES")
    stt_keys = {k for k, _ in _dict_keys_values(stt) if k is not None}
    assert "asnmap" in stt_keys, "asnmap missing from SCAN_TARGET_TYPES"


def test_asnmap_stage_is_ungated():
    """asnmap must not wait on a prior stage — the gate carries an explicit
    `scan_type != "asnmap"` exemption so the break-on-waiting-stage can never
    starve it."""
    tree = _module(RECON)
    found = False
    for node in ast.walk(tree):
        if isinstance(node, ast.Compare) and isinstance(node.ops[0], ast.NotEq):
            right = node.comparators[0]
            if isinstance(right, ast.Constant) and right.value == "asnmap":
                found = True
                break
    assert found, 'no `scan_type != "asnmap"` gate exemption — asnmap can be starved by an earlier waiting stage'


# ─── osint runner job ───────────────────────────────────────────────────────

def _func(tree, name):
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    return None


def test_asnmap_job_has_cymru_fallback():
    """The /jobs/asnmap worker falls back to the free Team Cymru lookup.

    asnmap (ProjectDiscovery) needs a PDCP API key and prompts interactively,
    so in a non-tty container the binary alone yields nothing. _run_asnmap_job
    must call _cymru_asn_lookup so ASN data is actually produced without a key."""
    tree = _module(OSINT)
    fn = _func(tree, "_run_asnmap_job")
    assert fn is not None, "_run_asnmap_job worker is gone — /jobs/asnmap lost its Cymru path"
    called = {n.func.id for n in ast.walk(fn)
              if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
    assert "_cymru_asn_lookup" in called, "_run_asnmap_job never calls the Team Cymru fallback"
    assert "_ingest_results" in called, "_run_asnmap_job never ingests its results"


def test_asnmap_binary_uses_correct_flag():
    """asnmap takes `-f` for a file of targets; the old `-l` is not a real flag
    (v1.1 exits 2: 'flag provided but not defined: -l'), so every asnmap
    invocation must use -f, never -l."""
    tree = _module(OSINT)
    for node in ast.walk(tree):
        if isinstance(node, ast.List) and node.elts:
            first = node.elts[0]
            if isinstance(first, ast.Constant) and first.value == "asnmap":
                flags = [e.value for e in node.elts[1:]
                         if isinstance(e, ast.Constant)]
                assert "-l" not in flags, f"asnmap invoked with the invalid -l flag: {flags}"
                assert "-f" in flags, f"asnmap invocation missing -f file flag: {flags}"


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
