"""The runtime command check must be safe, and must not be able to lie.

Run on demand:

    pytest tests/test_tool_command_check.py -v

WHY THIS EXISTS
---------------
`scripts/check_tool_commands.py` runs real tool commands to confirm their options
and call path — something no static check can do. gobuster had failed 20 of 20
runs on a wordlist path absent from the image, and pytest could not have caught
it; only running gobuster could.

That makes the checker itself a thing to be careful about, in two directions:

  * **It must not become a dispatch surface.** It runs subprocesses. If a
    caller-supplied host could reach it, it would be a way to send traffic that
    never passes the scope gate. The probe target is therefore hardcoded
    loopback, a command with no `{target}` to redirect is reported rather than
    run, and anything whose substituted form still names another host is refused.
  * **It must not report success it did not observe.** `connection refused` is
    the success signal, so a lenient classifier would call everything OK. Bad
    options are checked FIRST, because a tool that rejects its own flags never
    reaches the filesystem or the network and would otherwise be misattributed.

Measured on this deployment: 243 commands, 178 ok, 10 bad_option (all httpx),
1 missing_path, 52 no_binary, 2 correctly refused as unsafe to probe.
"""
import json
import os
import re
import stat
import subprocess

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
SCRIPT = os.path.join(REPO, "scripts", "check_tool_commands.py")
LISTENER = os.path.join(REPO, "kali_listener", "listener_service.py")
MARKDOWN = os.path.join(REPO, "knowledge", "commands", "tool_invocations.md")


def _psql(sql):
    try:
        out = subprocess.run(
            ["docker", "exec", "rag-postgres", "psql", "-U", "app", "-d", "scans",
             "-v", "ON_ERROR_STOP=1", "-tAc", sql],
            capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.SubprocessError):
        return None
    return out.stdout.strip() if out.returncode == 0 else None


# ── the checker must be safe ────────────────────────────────────────────────

@pytest.mark.unit
def test_the_script_exists_and_runs_standalone():
    assert os.path.exists(SCRIPT), "the runtime command check is gone"
    assert os.stat(SCRIPT).st_mode & stat.S_IXUSR, "not executable"


@pytest.mark.unit
def test_the_probe_target_is_hardcoded_loopback():
    """A caller-supplied host would make this a way to send unscoped traffic."""
    src = open(LISTENER, encoding="utf-8").read()
    assert '_PROBE_HOST = "127.0.0.1"' in src, \
        "the probe host is no longer hardcoded loopback"
    # Read to the line that is exactly `}`: splitting on the first "}" lands
    # inside the "{target}" key itself and yields two characters of the block.
    lines = src.split("_PROBE_SUBS = {", 1)[1].splitlines()
    blk = []
    for line in lines:
        if line.strip() == "}":
            break
        blk.append(line)
    blk = "\n".join(blk)
    assert "_PROBE_HOST" in blk, \
        f"the probe substitution no longer uses the hardcoded host: {blk!r}"
    assert "request." not in blk, \
        "the probe substitution now takes a value from the request"


@pytest.mark.unit
def test_the_checker_never_dispatches_through_the_scope_gated_path():
    """If it called /tools/execute it could launder a command past the gate."""
    src = open(LISTENER, encoding="utf-8").read()
    fn = src.split("async def verify_tool_commands(", 1)[1].split("\n@app.", 1)[0]
    assert "/tools/execute" not in fn, \
        "verify now routes through the dispatch path; that is a scope bypass"
    assert "create_subprocess_shell" in fn, "the probe no longer runs locally"


@pytest.mark.unit
def test_a_command_it_cannot_redirect_is_reported_not_run():
    src = open(LISTENER, encoding="utf-8").read()
    fn = src.split("async def verify_tool_commands(", 1)[1].split("\n@app.", 1)[0]
    assert 'if "{target}" not in cmd:' in fn, \
        "a command with no target is no longer skipped — probing it may hit "\
        "something real"
    assert "unverifiable" in fn
    # and after substitution it must still refuse a non-loopback host
    assert "probe would contact" in fn, \
        "the post-substitution host check is gone"


@pytest.mark.unit
def test_bad_options_are_classified_before_paths_and_network():
    """A tool that rejects its flags never reaches the disk or the wire.

    Checking network markers first would call `Incorrect Usage ... refused` an
    OK, which is exactly the false pass this check exists to prevent.
    """
    src = open(LISTENER, encoding="utf-8").read()
    fn = src.split("def _classify_probe(", 1)[1].split("\n@app.", 1)[0]
    i_opt = fn.index("_BAD_OPTION_MARKERS")
    i_path = fn.index("_MISSING_PATH_MARKERS")
    i_net = fn.index("_REACHED_NETWORK_MARKERS")
    assert i_opt < i_path < i_net, \
        "classification order changed; bad options must be checked first"


@pytest.mark.unit
def test_no_binary_is_not_claimed_to_be_a_defect_everywhere():
    """httpx/katana/naabu/tlsx live in pd-runner, not kali-listener.

    Reporting those as broken everywhere would be wrong, and the report has to
    say so or a reader will 'fix' a tool that is simply hosted elsewhere.
    """
    src = open(SCRIPT, encoding="utf-8").read()
    assert "pd-runner" in src, \
        "the per-image caveat is gone; no_binary will be read as missing everywhere"
    assert "PER IMAGE" in src.upper()


@pytest.mark.unit
def test_the_markdown_goes_where_the_rag_can_ingest_it():
    src = open(SCRIPT, encoding="utf-8").read()
    assert os.path.join("knowledge", "commands") in src or \
        '"knowledge", "commands"' in src, "the default output moved"
    assert "playbooks/ingest" in src, \
        "the record no longer says how the markdown reaches the RAG"


# ── executed ────────────────────────────────────────────────────────────────

def test_the_verify_endpoint_classifies_the_four_known_cases():
    """One good command and three broken ones, through the real endpoint."""
    payload = json.dumps({"timeout": 12, "commands": [
        {"tool": "gobuster", "command":
            "gobuster dir -u http://{target}:{port} -w /usr/share/wordlists/"
            "seclists/Discovery/Web-Content/common.txt"},
        {"tool": "gobuster", "command":
            "gobuster dir -u http://{target}:{port} -w /no/such/list.txt"},
        {"tool": "gobuster", "command":
            "gobuster dir -u http://{target}:{port} --notaflag"},
        {"tool": "notarealtool", "command": "notarealtool {target}"},
    ]})
    try:
        out = subprocess.run(
            ["docker", "exec", "-i", "kali-listener", "curl", "-sk",
             "--max-time", "180", "-X", "POST",
             "https://127.0.0.1:8019/tools/verify",
             "-H", "Content-Type: application/json", "--data-binary", "@-"],
            input=payload, capture_output=True, text=True, timeout=240)
    except (OSError, subprocess.SubprocessError):
        pytest.skip("kali-listener not reachable")
    if out.returncode != 0 or not out.stdout.strip():
        pytest.skip("verify endpoint did not respond")
    verdicts = [r["verdict"] for r in json.loads(out.stdout)["results"]]
    assert verdicts == ["ok", "missing_path", "bad_option", "no_binary"], (
        f"classification is wrong: {verdicts}. 'ok' for the first proves "
        "connection-refused is read as success; the others must not collapse "
        "into it.")


def test_a_probe_that_would_leave_loopback_is_refused():
    """The catalogue contains `curl ... https://www.google.com/`. Probing it
    would send real traffic, so it must come back unverifiable."""
    payload = json.dumps({"timeout": 10, "commands": [
        {"tool": "curl", "command":
            "curl -x http://{target}:{port} -sk https://www.google.com/"},
    ]})
    try:
        out = subprocess.run(
            ["docker", "exec", "-i", "kali-listener", "curl", "-sk",
             "--max-time", "60", "-X", "POST",
             "https://127.0.0.1:8019/tools/verify",
             "-H", "Content-Type: application/json", "--data-binary", "@-"],
            input=payload, capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.SubprocessError):
        pytest.skip("kali-listener not reachable")
    if out.returncode != 0 or not out.stdout.strip():
        pytest.skip("verify endpoint did not respond")
    r = json.loads(out.stdout)["results"][0]
    assert r["verdict"] == "unverifiable", (
        f"a probe to www.google.com was not refused (verdict {r['verdict']}) — "
        "this check must never send traffic off loopback")
    assert "google.com" in (r.get("detail") or ""), \
        "the refusal does not name the host it declined to contact"


def test_the_markdown_is_present_and_was_ingested():
    """'For RAG ingestion' is a claim; this is the evidence."""
    assert os.path.exists(MARKDOWN), f"{MARKDOWN} was never generated"
    body = open(MARKDOWN, encoding="utf-8").read()
    assert "### gobuster" in body, "no per-tool sections — chunking keys on ###"
    assert "probed as:" in body, \
        "the record no longer shows the exact command that was probed, which is "\
        "the part that makes it evidence rather than an assertion"
    assert "reached the network" in body

    # Match on the body text, not the title: a title-only match would pass even
    # if the chunks held none of the content.
    n = _psql("SELECT count(*) FROM exploit_chunks "
              "WHERE chunk ILIKE '%probed as:%'")
    if n is None:
        pytest.skip("no reachable rag-postgres")
    assert int(n) > 0, (
        "the markdown exists but no chunk of it is in the vector store — run "
        "POST /rag/playbooks/ingest {\"playbook_dir\": \"/knowledge/commands\"}")
