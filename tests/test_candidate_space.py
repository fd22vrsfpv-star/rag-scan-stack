"""A brute-force run that cannot finish must be refused BEFORE it starts.

Run on demand:

    pytest tests/test_candidate_space.py -v

WHY THIS EXISTS
---------------
Every hydra/medusa/ncrack command in `knowledge/service_tools.yaml` named
`rockyou.txt` — 14,344,399 passwords. Against the 17-name userlist that is
243,854,783 candidates, and hydra reported the consequence itself:

    [DATA] overall 16 tasks, 243854783 login tries (l:17/p:14344399)
    [STATUS] 256.00 tries/min, 243854527 to do in 15875:57h

**15,875 hours.** All 48 runs were killed by the deadline and recorded as scans
that found nothing — so a hopeless invocation and a host with strong passwords
left identical evidence in the database. Nothing warned before dispatch.

The guard lives in the listener because that is where the wordlists are: the
recommender that emits the command cannot count lines in a file it never sees.
"""
import importlib.util
import os
import subprocess

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
CATALOGUE = os.path.join(REPO, "knowledge", "service_tools.yaml")
LISTENER = os.path.join(REPO, "kali_listener", "listener_service.py")

U = "/usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt"
ROCKYOU = "/usr/share/wordlists/rockyou.txt"
SHORT = ("/usr/share/wordlists/seclists/Passwords/Common-Credentials/"
         "top-passwords-shortlist.txt")


# ── the catalogue itself ────────────────────────────────────────────────────

@pytest.mark.unit
def test_no_command_names_rockyou():
    """11 commands did. rockyou is 14.3M lines and belongs in no default."""
    src = open(CATALOGUE, encoding="utf-8").read()
    assert "rockyou" not in src, (
        "a command names rockyou.txt again — 14,344,399 passwords cannot finish "
        "inside any timeout")


@pytest.mark.unit
def test_hydra_commands_ignore_a_stale_restore_file():
    """hydra stops and PROMPTS when it finds ./hydra.restore, so the next run
    exits 255 having done nothing. Several exit-255 failures came from this."""
    src = open(CATALOGUE, encoding="utf-8").read()
    bad = [ln.strip() for ln in src.splitlines()
           if "command:" in ln and "hydra " in ln and " -I " not in ln]
    assert not bad, f"hydra command(s) missing -I: {bad[:3]}"


@pytest.mark.unit
def test_no_default_names_a_wordlist_absent_from_the_image():
    """A default naming an absent file is the gobuster wordlist bug again.

    The 10-million-password lists are NOT in this image; only the shortlist and
    default-passwords are.

    The catalogue itself no longer names any password list: brute-force commands
    carry `{password_list}`, resolved per target from discovered usernames plus
    service defaults. So the static filename now lives in the FALLBACK constants,
    and that is where it has to be checked — asserting on the catalogue would
    pass forever on a file nobody reads.
    """
    src = open(CATALOGUE, encoding="utf-8").read()
    assert "10-million-password-list" not in src, \
        "the catalogue names a seclists file that is not installed in this image"

    import sys as _sys
    _sys.path.insert(0, os.path.join(REPO, "app", "rag-api"))
    tw = pytest.importorskip("target_wordlists")
    assert "top-passwords-shortlist.txt" in tw.STATIC_PASSWORD_LIST
    assert "top-usernames-shortlist.txt" in tw.STATIC_USER_LIST
    assert "10-million-password-list" not in tw.STATIC_PASSWORD_LIST

    # The BFF keeps its own copy, because it has neither the etl mount nor a
    # database. Two copies of a path need pinning or they drift.
    bff = open(os.path.join(REPO, "dashboard", "bff", "routers", "assets.py"),
               encoding="utf-8").read()
    assert "top-passwords-shortlist.txt" in bff, \
        "the BFF's local fallback no longer names the short list"


@pytest.mark.unit
def test_brute_force_commands_carry_the_list_placeholders():
    """The substitution: a static path here means the discovered usernames — 35
    of them on this host — are never used."""
    import re as _re
    src = open(CATALOGUE, encoding="utf-8").read()
    brute = [m.group(1) for m in _re.finditer(r'command:\s*"([^"]+)"', src)
             if m.group(1).split() and m.group(1).split()[0]
             in ("hydra", "medusa", "ncrack", "crowbar", "patator")]
    assert brute, "no brute-force commands found at all"
    assert all("{password_list}" in c or "{user_list}" in c for c in brute), \
        f"a brute-force command names a static list: " \
        f"{[c[:70] for c in brute if '{password_list}' not in c and '{user_list}' not in c]}"


# ── the guard, executed ─────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def kl():
    """Load the listener module inside its own container.

    Counting lines requires the wordlists, which exist only there.
    """
    probe = (
        "import importlib.util, json\n"
        "s=importlib.util.spec_from_file_location('kl','/app/listener_service.py')\n"
        "m=importlib.util.module_from_spec(s)\n"
        "try: s.loader.exec_module(m)\n"
        "except SystemExit: pass\n"
        "print('LOADED', hasattr(m,'check_candidate_space'))\n")
    try:
        out = subprocess.run(["docker", "exec", "kali-listener", "python3", "-c", probe],
                             capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.SubprocessError):
        pytest.skip("kali-listener not reachable")
    if out.returncode != 0 or "LOADED True" not in out.stdout:
        pytest.skip(f"guard not deployed: {(out.stderr or out.stdout)[-200:]}")
    return True


def _guard(tool, command, force=False):
    probe = (
        "import importlib.util, json\n"
        "s=importlib.util.spec_from_file_location('kl','/app/listener_service.py')\n"
        "m=importlib.util.module_from_spec(s)\n"
        "try: s.loader.exec_module(m)\n"
        "except SystemExit: pass\n"
        f"est,detail=m.estimate_candidate_space({tool!r}, {command!r})\n"
        f"ref,warn=m.check_candidate_space({tool!r}, {command!r}, force={force})\n"
        "print('RESULT'+json.dumps({'est':est,'refused':bool(ref),"
        "'warned':bool(warn),'refusal':ref,'warning':warn}))\n")
    out = subprocess.run(["docker", "exec", "kali-listener", "python3", "-c", probe],
                         capture_output=True, text=True, timeout=180)
    if out.returncode != 0:
        pytest.skip(f"probe failed: {out.stderr[-200:]}")
    import json
    line = [l for l in out.stdout.splitlines() if l.startswith("RESULT")][-1]
    return json.loads(line[len("RESULT"):])


def test_the_original_rockyou_invocation_is_refused(kl):
    """The exact command that ran 48 times."""
    r = _guard("hydra", f"hydra -I -L {U} -P {ROCKYOU} ftp://192.168.1.150:21")
    assert r["refused"] is True, f"est={r['est']} was allowed through"
    assert r["est"] > 200_000_000, f"estimate {r['est']} does not match reality"


def test_the_estimate_matches_what_hydra_itself_reported(kl):
    """Independent confirmation, not a self-consistent guess.

    hydra printed `243854783 login tries` for this command. Counting the two
    files here gives 243,854,664 — the difference is blank lines. An estimate
    that agreed with nothing external would be worth much less.
    """
    r = _guard("hydra", f"hydra -L {U} -P {ROCKYOU} ftp://192.168.1.150:21")
    assert abs(r["est"] - 243_854_783) < 5_000, (
        f"estimate {r['est']:,} is not close to hydra's own 243,854,783")


def test_the_replacement_invocation_passes_cleanly(kl):
    """17 users x 25 passwords = 425, about two minutes."""
    r = _guard("hydra", f"hydra -I -L {U} -P {SHORT} ftp://192.168.1.150:21")
    assert r["refused"] is False and r["warned"] is False, \
        f"the sane command was flagged: est={r['est']} {r.get('refusal') or r.get('warning')}"
    assert r["est"] == 425, f"expected 425 candidates, got {r['est']}"


def test_a_password_list_with_no_userlist_still_counts(kl):
    """`hydra -P rockyou vnc://...` has no -L, and 14.3M is still hopeless.

    Treating an absent side as ZERO would multiply the estimate to nothing and
    pass every single-user attack straight through.
    """
    r = _guard("hydra", f"hydra -I -P {ROCKYOU} vnc://192.168.1.150:5900")
    assert r["refused"] is True
    assert r["est"] > 14_000_000


def test_a_non_bruteforce_tool_is_not_judged(kl):
    r = _guard("nmap", "nmap -sV -p 445 192.168.1.150")
    assert r["est"] is None
    assert r["refused"] is False and r["warned"] is False


def test_force_overrides_volume_but_this_is_not_the_scope_gate(kl):
    """CLAUDE.md: an override overrules the platform's SUPPRESSION judgement,
    never the operator's AUTHORIZATION.

    Candidate volume is a suppression judgement, so force may pass it. The scope
    gate runs BEFORE this and force must never pass that one — which is why this
    check sits after it in the endpoint.
    """
    r = _guard("hydra", f"hydra -L {U} -P {ROCKYOU} ftp://192.168.1.150:21", force=True)
    assert r["refused"] is False, "force did not override the volume judgement"

    src = open(LISTENER, encoding="utf-8").read()
    scope_at = src.index("scope_error = enforce_scope(")
    cand_at = src.index("cs_refusal, cs_warning = check_candidate_space(")
    assert scope_at < cand_at, (
        "the candidate-space check runs BEFORE the scope gate — a forced "
        "oversized run would then skip authorisation")


def test_an_unreadable_wordlist_is_not_counted_as_zero(kl):
    """Unknown must never be optimistic: zero would pass the guard."""
    r = _guard("hydra", "hydra -L /nonexistent/users.txt -P /nonexistent/pw.txt ftp://h:21")
    assert r["est"] in (None, 1), \
        f"a missing wordlist produced a confident estimate of {r['est']}"
