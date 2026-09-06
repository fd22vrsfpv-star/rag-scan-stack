"""Tools the WSTG lane runs must be allowlisted by kali-listener.

WHY THIS EXISTS
---------------
`knowledge/wstg_map.yaml` turns a finding into a security test, and every safe
test is executed through `kali-listener /tools/execute`. That endpoint checks the
tool against `get_allowed_tools()` AFTER the scope gate, and rejects anything
outside it with 400.

`sslscan` was named by two WSTG entries (the CRYP weak-transport family) and was
installed in no container at all, so that whole family could never produce a
result — while still being counted as "covered" by the coverage report. Three
more (`ncrack`, `ffuf`, `feroxbuster`) were declared in
`knowledge/service_tools.yaml` and likewise absent.

Both failures look identical to the operator: a scan that ran and found nothing.

SCOPE OF THIS GUARD: the WSTG map only. `service_tools.yaml` is a broad catalogue
of ~85 tools a tester might use, most legitimately absent and filtered at runtime
by `knowledge/tool_catalogs.json`; asserting on all of it here would be wrong.
The live "is it actually installed" check is `scripts/post-install-check.sh`.

Sabotage check: remove "sslscan" from _FALLBACK_ALLOWED_TOOLS -> RED.
"""
import os
import re

import pytest

yaml = pytest.importorskip("yaml")

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
WSTG_MAP = os.path.join(REPO, "knowledge", "wstg_map.yaml")
LISTENER = os.path.join(REPO, "kali_listener", "listener_service.py")
KALI_DOCKERFILE = os.path.join(REPO, "kali_listener", "Dockerfile")

#: Named as a command's first word but not dispatched to the listener as a tool.
NOT_DISPATCHED = {
    "manual_followup",   # placeholder, never executed
    "webshell",          # structured dispatch, carries no shell command
}

#: Executed by a different service, so the listener allowlist does not apply.
SERVED_ELSEWHERE = {"nuclei", "zap", "wafw00f", "nikto", "gowitness", "katana",
                    "httpx", "naabu", "masscan", "subfinder", "dnsx"}

#: Pinned regression: these were declared-but-absent and are now installed.
#: Removing one from the Dockerfile without removing its commands re-breaks the
#: exact failure this module exists for.
REQUIRED_IN_KALI_IMAGE = ("sslscan", "ncrack", "ffuf", "feroxbuster")


def _first_word(cmd):
    cmd = (cmd or "").strip()
    return os.path.basename(cmd.split()[0]) if cmd else ""


def _wstg_tools():
    if not os.path.exists(WSTG_MAP):
        pytest.skip("wstg_map.yaml not present")
    with open(WSTG_MAP, encoding="utf-8") as fh:
        entries = (yaml.safe_load(fh) or {}).get("entries") or []
    tools = {}
    for e in entries:
        binary = _first_word(e.get("command"))
        if binary:
            tools.setdefault(binary, []).append(e.get("id"))
    assert tools, "no WSTG commands parsed — this guard would pass vacuously"
    return tools


def _allowlist():
    if not os.path.exists(LISTENER):
        pytest.skip("listener_service.py not present")
    with open(LISTENER, encoding="utf-8") as fh:
        src = fh.read()
    m = re.search(r"_FALLBACK_ALLOWED_TOOLS\s*=\s*\{(.*?)\n\}", src, re.S)
    assert m, "_FALLBACK_ALLOWED_TOOLS not found — guard would pass vacuously"
    allowed = set(re.findall(r'"([^"]+)"', m.group(1)))
    assert len(allowed) > 20, f"only {len(allowed)} tools parsed — guard too weak"
    return allowed


def test_every_wstg_tool_is_allowlisted():
    allowed = _allowlist()
    gaps = {
        tool: ids for tool, ids in _wstg_tools().items()
        if tool not in NOT_DISPATCHED and tool not in SERVED_ELSEWHERE
        and tool not in allowed
    }
    assert not gaps, (
        "these WSTG tests name a tool the listener will reject with 400 "
        f"(not in the allowlist), after it has already passed the scope gate: {gaps}"
    )


@pytest.mark.parametrize("tool", REQUIRED_IN_KALI_IMAGE)
def test_previously_missing_tools_are_installed(tool):
    """Installed AND allowlisted — a tool needs both to ever run."""
    if not os.path.exists(KALI_DOCKERFILE):
        pytest.skip("kali_listener/Dockerfile not present")
    with open(KALI_DOCKERFILE, encoding="utf-8") as fh:
        # Strip comments: this module NAMES these tools in prose above, and the
        # Dockerfile explains them in a comment too. Only real install lines count.
        body = "\n".join(l.split("#", 1)[0] for l in fh.read().splitlines())
    assert re.search(rf"^\s*{re.escape(tool)}\s*\\?\s*$", body, re.M), (
        f"{tool} is no longer installed by kali_listener/Dockerfile — every "
        f"recommendation naming it will fail with 'not found'"
    )
    assert tool in _allowlist(), (
        f"{tool} is installed but not in _FALLBACK_ALLOWED_TOOLS, so "
        f"/tools/execute rejects it with 400"
    )
