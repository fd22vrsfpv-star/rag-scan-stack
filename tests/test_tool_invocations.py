"""Commands the stack runs must be able to produce output.

Run on demand:

    pytest tests/test_tool_invocations.py -v

WHY THIS EXISTS
---------------
1348 rows in `tool_executions`; 493 produced no output at all. Four different
causes hid behind that one number, and only one of them was the tool honestly
finding nothing:

  * **gobuster: 20 runs, 20 failures.** Every command carried
    `-w /usr/share/wordlists/dirb/common.txt`, and that path does not exist in
    the kali-listener image (it ships seclists, rockyou and nmap.lst). gobuster
    had never once run. With the path corrected it immediately finds `/dav/`,
    `cgi-bin/` and `.htaccess` on the engagement target.
  * **dnsrecon/dnsenum/dig/whois: literal `example.com`.** The templates never
    had a placeholder, so 19 dnsrecon runs queried *someone else's domain*
    through the target's resolver and told the operator nothing.
  * **lftp: 78 runs, exit 0, no output.** `lftp -u anonymous, ftp://host` opens a
    session, is given no commands, and closes. It now runs `ls -la; bye`.
  * **snmpwalk: 12 runs, "Timeout: No Response".** Correct behaviour — SNMP is
    not open. This one is not a bug, and a test that flagged it would be wrong.

So the guards below check the two properties that distinguish a broken
invocation from an empty result: every path a command names must exist where the
command runs, and no command may carry a hardcoded stand-in where a target-
specific value belongs.
"""
import os
import re
import subprocess

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
YAML = os.path.join(REPO, "knowledge", "service_tools.yaml")
LISTENER = os.path.join(REPO, "kali_listener", "listener_service.py")


def _commands():
    src = open(YAML, encoding="utf-8").read()
    return re.findall(r'command:\s*"([^"]+)"', src)


def _in_listener(script):
    try:
        out = subprocess.run(["docker", "exec", "kali-listener", "sh", "-c", script],
                             capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.SubprocessError):
        return None
    return out.stdout.strip() if out.returncode == 0 else None


@pytest.fixture(scope="module")
def listener():
    if _in_listener("echo ok") != "ok":
        pytest.skip("kali-listener not reachable")
    return True


# ── source-level ────────────────────────────────────────────────────────────

@pytest.mark.unit
def test_no_command_hardcodes_a_stand_in_domain():
    """A hardcoded domain sends the engagement's traffic after someone else's
    data. `dnsrecon -d example.com -n <target>` ran 19 times."""
    bad = [c for c in _commands()
           if re.search(r"\b(example\.(com|org|net)|test\.com|foo\.bar)\b", c)]
    assert not bad, (
        "command(s) name a stand-in domain instead of a {placeholder}:\n  "
        + "\n  ".join(bad))


@pytest.mark.unit
def test_the_dead_wordlist_path_is_gone():
    src = open(YAML, encoding="utf-8").read()
    assert "wordlists/dirb/" not in src, (
        "the dirb wordlist path is back; it does not exist in the kali-listener "
        "image and gobuster fails 100% of the time on it")


@pytest.mark.unit
def test_interactive_tools_are_given_something_to_do():
    """A session opened and closed with no commands exits 0 and says nothing."""
    for cmd in _commands():
        tool = cmd.split()[0]
        if tool in ("lftp", "ftp", "telnet", "mysql", "psql"):
            assert re.search(r"(-e\s|-c\s|<<|echo\s|\|)", cmd), (
                f"{tool} is invoked with no commands and no input, so it will "
                f"exit 0 having done nothing: {cmd}")


@pytest.mark.unit
def test_the_execution_chokepoint_refuses_unresolved_placeholders():
    """rag-api already refuses to QUEUE such a command; the runner did not
    refuse to RUN one, which is the gap that let {domain} reach a shell."""
    src = open(LISTENER, encoding="utf-8").read()
    assert 'unresolved = re.findall(r"\\{[a-z_]+\\}", request.command or "")' in src, \
        "the placeholder guard is gone from /tools/execute"
    # It must come AFTER the scope check: an out-of-scope target is the more
    # serious refusal and must not be masked by a formatting complaint.
    assert src.index("scope_error = enforce_scope(") < src.index("unresolved = re.findall"), \
        "the placeholder guard now runs before the scope gate"


# ── executed against the image that runs the commands ───────────────────────

def test_every_path_a_command_names_exists_where_it_runs(listener):
    """The general form of the gobuster bug.

    A command referring to a file that is not in the image cannot work, and the
    failure looks identical to 'found nothing' in every report.
    """
    paths = set()
    for cmd in _commands():
        paths.update(re.findall(r"(/(?:usr|opt|etc|var)/[A-Za-z0-9_./-]+)", cmd))
    assert paths, "no absolute paths found in any command — the parse is wrong"
    missing = []
    for p in sorted(paths):
        if _in_listener(f"test -e '{p}' && echo OK") != "OK":
            missing.append(p)
    assert not missing, (
        "command(s) reference paths absent from the kali-listener image, so "
        "those tools cannot produce output:\n  " + "\n  ".join(missing))


def test_the_corrected_wordlist_is_actually_present(listener):
    """Anti-vacuity: proves the check above can see a real file."""
    assert _in_listener(
        "test -e /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt "
        "&& echo OK") == "OK", "the replacement wordlist is missing too"
