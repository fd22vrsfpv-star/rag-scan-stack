"""Executing tests for common/dispatch_validation.

Two jobs:
  1. Unit-test validate_dispatch's contract (empty -> refuse; single -> fan out
     one-per-target; multi -> one group).
  2. Agreement: pin TOOL_SPECS to the node_manager remote templates. A template
     that places its target via a singular placeholder ({domain}/{target}) and
     is not run _per_target is a SINGLE-arity tool; if TOOL_SPECS disagrees, a
     multi-target dispatch will crash at runtime the way service-enum did.

Sabotage proof: flip service-enum's spec to "multi" (or drop it) and
test_singular_placeholder_templates_are_single fails; hand two targets to a
single tool and assert the fan-out — break the fan-out and test_single_* fails.
"""
import os
import re
import sys

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "common"))

dv = pytest.importorskip("dispatch_validation")


# ── Unit: the core contract ────────────────────────────────────────────────

def test_empty_targets_refused():
    for empty in (None, "", "   ", [], ["", "  "]):
        res = dv.validate_dispatch("amass", empty)
        assert res.ok is False
        assert "no targets" in res.reason


def test_single_arity_fans_out_one_per_target():
    res = dv.validate_dispatch("service-enum", ["convio.net", "blackbaud.com"])
    assert res.ok is True
    assert res.fanout == [["convio.net"], ["blackbaud.com"]]


def test_single_arity_one_target_is_one_run():
    res = dv.validate_dispatch("service-enum", ["convio.net"])
    assert res.ok is True
    assert res.fanout == [["convio.net"]]


def test_multi_arity_single_group():
    res = dv.validate_dispatch("amass", ["convio.net", "blackbaud.com"])
    assert res.ok is True
    assert res.fanout == [["convio.net", "blackbaud.com"]]


def test_unknown_tool_is_permissive_multi():
    res = dv.validate_dispatch("some-new-scanner", ["a.com", "b.com"])
    assert res.ok is True
    assert res.fanout == [["a.com", "b.com"]]


def test_comma_and_newline_splitting():
    res = dv.validate_dispatch("service-enum", "convio.net, blackbaud.com")
    assert res.fanout == [["convio.net"], ["blackbaud.com"]]


def test_plan_fanout_empty_on_refusal():
    assert dv.plan_fanout("amass", []) == []


# ── Agreement: TOOL_SPECS vs the actual remote templates ───────────────────

def _known_scan_templates():
    """(scan_type, cmd_string, is_per_target) parsed from node_manager templates.

    Regex, not import — node_manager pulls heavy deps. Good enough: we only need
    to see which template strings carry a {domain}/{target} placeholder.
    """
    path = os.path.join(REPO, "node_manager", "node_manager.py")
    if not os.path.exists(path):
        pytest.skip("node_manager.py not present")
    src = open(path, encoding="utf-8").read()
    # Grab each `"name": { ... "cmd": [ ... ] ... }` block loosely by scanning
    # lines: a scan key introduces a block, "cmd": [...] gives its command.
    out = []
    # Find template dict entries of the form:  "service-enum": {
    for m in re.finditer(r'"([a-z0-9-]+)":\s*\{', src):
        name = m.group(1)
        tail = src[m.end():m.end() + 600]
        cmd_m = re.search(r'"cmd":\s*\[(.*?)\]', tail, re.S)
        if not cmd_m:
            continue
        cmd_str = cmd_m.group(1)
        per_target = '"_per_target"' in tail and 'True' in tail.split('"_per_target"')[1][:20]
        out.append((name, cmd_str, per_target))
    return out


def test_singular_placeholder_templates_are_single():
    """Any non-_per_target template using {domain} or {target} must be SINGLE."""
    offenders = []
    for name, cmd_str, per_target in _known_scan_templates():
        if per_target:
            continue
        singular = ("{domain}" in cmd_str or "{target}" in cmd_str)
        plural = "{targets}" in cmd_str
        if singular and not plural:
            if dv.spec_for(name).arity != "single":
                offenders.append(name)
    assert not offenders, (
        "these node_manager templates place a single target via a placeholder "
        f"but are not arity='single' in TOOL_SPECS (multi-target dispatch will "
        f"crash like service-enum did): {offenders}"
    )
