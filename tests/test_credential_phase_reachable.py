"""Credential discovery is reachable — but only where it was authorised.

Run on demand:

    pytest tests/test_credential_phase_reachable.py -v

WHY THIS EXISTS
---------------
A full pentest run against a host with **ftp(21), ssh(22), telnet(23),
ftp(2121) and vnc(5900) open** produced **zero** credential findings and ran no
credential scan. That reads as "nothing to find". The truth was "never looked".

`SCAN_TOOLS_DISPATCH` excludes `start_credential_check` and `start_brutus` with
the comment that they "stay behind the human-approved exploit phase" — but
`EXPLOIT_PLAN_TOOLS` never contained them either. No phase of the pipeline could
reach them at all, so the intent in that comment was never implemented and
credential discovery simply never happened on any run.

Two halves to the fix, and it needed both:

  1. **Reachable.** `SCAN_TOOLS_CREDENTIAL` is added to the scan phase's toolset
     when the engagement has operator pre-approval — the same authorisation that
     skips the exploit interrupt. Without pre-approval they stay out, exactly as
     before.
  2. **Known about.** The scan task now says the tools exist and when to use
     them. A tool the agent is never told about does not get chosen, which is
     the likeliest reason `start_credential_check` sat unused even in the runs
     where something could in principle have called it.

WHAT KEEPS IT HONEST
--------------------
  * Gated on the SAME per-engagement pre-approval as the exploit gate, so an
    engagement nobody approved gets no credential testing.
  * Only when `auto_execute` is on — with it off the phase has no dispatch tools
    at all, and that contract is unchanged.
  * The tool bodies keep their own scope gate and concurrency bound; this
    changes what the agent may CHOOSE, never what a tool is allowed to do.

SABOTAGE PROOF
--------------
Put the credential names into SCAN_TOOLS_DISPATCH and
`test_credentials_are_not_in_the_default_dispatch_set` fails — they would then
run on every engagement, approved or not. Remove the pre-approval check and
`test_credential_tools_require_preapproval` fails.
"""
import ast
import os
import re

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
ENGINE = os.path.join(REPO, "autogen_agents", "langgraph_engine.py")
REGISTRY = os.path.join(REPO, "autogen_agents", "tool_registry.py")


def _read(path):
    if not os.path.exists(path):
        pytest.skip(f"{path} not present")
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def _func(src, name):
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return ast.get_source_segment(src, node) or ""
    return ""


def _set_literal(src, name):
    """The names in a module-level `NAME = {...}` string set."""
    m = re.search(rf"^{name}\s*=\s*\{{(.*?)\}}", src, re.S | re.M)
    assert m, f"{name} not found"
    return set(re.findall(r'"([^"]+)"', m.group(1)))


# ── Reachable at all ───────────────────────────────────────────────────────

def test_credential_tools_are_declared():
    names = _set_literal(_read(ENGINE), "SCAN_TOOLS_CREDENTIAL")
    assert names == {"start_credential_check", "start_brutus"}, (
        f"SCAN_TOOLS_CREDENTIAL is {names} — credential discovery is "
        "unreachable by the pipeline again")


def test_credential_tools_exist_in_the_registry():
    """A name the registry does not define is silently dropped from the toolset,
    which looks exactly like the bug this fixes."""
    reg = _read(REGISTRY)
    for tool in ("start_credential_check", "start_brutus"):
        assert f'name="{tool}"' in reg, f"{tool} is not a registered tool"


def test_scan_phase_can_gain_them():
    fn = _func(_read(ENGINE), "scan")
    assert "SCAN_TOOLS_CREDENTIAL" in fn, (
        "the scan phase can no longer gain the credential tools, so no phase "
        "can reach them — a host with ftp/ssh/telnet open gets zero credential "
        "findings and it looks like there was nothing to find")


# ── But only where authorised ──────────────────────────────────────────────

def test_credentials_are_not_in_the_default_dispatch_set():
    src = _read(ENGINE)
    dispatch = _set_literal(src, "SCAN_TOOLS_DISPATCH")
    creds = _set_literal(src, "SCAN_TOOLS_CREDENTIAL")
    assert not (dispatch & creds), (
        f"credential tools {dispatch & creds} are in the default dispatch set — "
        "they would run on every engagement, including ones nobody approved")


def test_credential_tools_require_preapproval():
    fn = _func(_read(ENGINE), "scan")
    assert "_engagement_preapproval" in fn, (
        "the credential tools are no longer gated on engagement pre-approval")
    # The gate must come before the toolset is widened.
    assert fn.index("_engagement_preapproval") < fn.index("SCAN_TOOLS_CREDENTIAL"), (
        "the toolset is widened before the authorisation is checked")


def test_credential_tools_require_auto_execute():
    """auto_execute off means no dispatch tools at all. That contract stands."""
    fn = _func(_read(ENGINE), "scan")
    i = fn.index("creds_enabled = False")
    guard = fn[i:fn.index("SCAN_TOOLS_CREDENTIAL")]
    assert "if auto:" in guard, (
        "credential tools can be added with auto_execute OFF, which breaks the "
        "rule that the toolset — not the prompt — enforces that contract")


# ── And the agent is told they exist ───────────────────────────────────────

def test_the_agent_is_told_the_tools_exist():
    """A tool nobody mentions does not get chosen."""
    fn = _func(_read(ENGINE), "scan")
    assert "cred_note" in fn, "the credential prompt note is gone"
    assert "start_credential_check" in fn, (
        "the task no longer names the tool, so the agent has to guess it exists")
    for svc in ("ftp", "ssh", "telnet", "vnc"):
        assert svc in fn, (
            f"the prompt no longer names {svc} as a credential-testing trigger")


def test_the_note_only_appears_when_the_tools_do():
    fn = _func(_read(ENGINE), "scan")
    assert 'if creds_enabled else ""' in fn, (
        "the credential note is added unconditionally — a run without the tools "
        "would be told to use tools it does not have, which is how an agent "
        "burns steps on calls that cannot resolve")
