"""One shell, chosen by measurement — highest privilege that actually holds.

Run on demand:

    pytest tests/test_access_selection.py -v

WHY THIS EXISTS
---------------
Exploits ran and shells were obtained, and the platform had no concept of
either. The vsftpd backdoor opened a root shell on 192.168.1.150:6200; the
`pending_exploits` row said `executed` and nothing recorded that access existed,
what privilege it had, or whether it still worked.

With one exploit that was a gap. Once the planner queues every well-evidenced
candidate, several succeed, and running the post-enumeration checklist through
all of them would be slow, noisy on the target, and would produce several
partial answers to one question instead of one complete one.

So access is MEASURED. `id` gives the privilege; repeated probes give the
stability. On the real host that ranking picks `192.168.1.150:1524` — a root
bind shell answering 3 of 3 probes, score 100 — over two working SSH
credentials at 43, and the checklist runs through it once.

NOT ONLY METASPLOIT
-------------------
A session is anything a command can run through. `bind_shell`,
`ssh_credential` and `listener_callback` are transports alongside
`msf_session`, and the winner on the live host is a raw bind shell that
Metasploit never knew about.

SABOTAGE PROOF
--------------
Make stability stop affecting the score and `test_a_flaky_root_loses_to_a_stable_user`
fails. Let an unknown privilege default to root and
`test_unknown_privilege_is_not_root` fails. Add a generic fallback transport and
`test_an_unknown_transport_is_refused_not_guessed` fails.
"""
import ast
import os
import sys

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, REPO)

ax = pytest.importorskip("etl.access", reason="etl/access.py not importable")
ENGINE = os.path.join(REPO, "autogen_agents", "langgraph_engine.py")


def _read(path):
    if not os.path.exists(path):
        pytest.skip(f"{path} not present")
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def _func_src(path, name):
    tree = ast.parse(_read(path))
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return ast.unparse(node)
    pytest.fail(f"{name} not found in {os.path.basename(path)}")


# ── Ranking ────────────────────────────────────────────────────────────────

def test_privilege_dominates():
    root = ax.score_for(True, 3, 3, "bind_shell")
    user = ax.score_for(False, 3, 3, "bind_shell")
    assert root > user, (root, user)


def test_a_flaky_root_loses_to_a_stable_user():
    """The property that makes this worth doing.

    The checklist is a SEQUENCE. A root shell that drops halfway through
    produces a half-finished enumeration that looks like a complete one, so a
    user shell answering every probe is the better instrument.
    """
    flaky_root = ax.score_for(True, 3, 1, "bind_shell")
    stable_user = ax.score_for(False, 3, 3, "ssh_credential")
    assert flaky_root < stable_user, (flaky_root, stable_user)


def test_an_access_that_answers_nothing_scores_zero():
    """It is not access. Ranking it above nothing would send the checklist into
    a shell that was never going to reply."""
    assert ax.score_for(True, 3, 0, "msf_session") == 0


def test_transport_preference_never_outranks_privilege():
    """An interactive session is nicer to have, not more important than root."""
    root_bind = ax.score_for(True, 3, 3, "bind_shell")
    user_msf = ax.score_for(False, 3, 3, "msf_session")
    assert root_bind > user_msf, (root_bind, user_msf)


def test_unknown_privilege_is_not_root():
    """A channel that answered but said nothing recognisable is not root, and it
    is not unprivileged either — it is unknown, and it ranks accordingly."""
    unknown = ax.score_for(None, 3, 3, "bind_shell")
    assert unknown < ax.score_for(False, 3, 3, "bind_shell")
    assert unknown > 0, "it did answer; ranking it at zero would discard it"


# ── Transports ─────────────────────────────────────────────────────────────

def test_sessions_outside_metasploit_are_supported():
    """The winner on the live host is a raw bind shell Metasploit never knew
    about."""
    for kind in ("msf_session", "bind_shell", "ssh_credential", "listener_callback"):
        assert kind in ax.TRANSPORTS, f"{kind} has no runner"


def test_an_unknown_transport_is_refused_not_guessed():
    """A silent fallback would mean the operator believes a command ran through
    the access they chose when it ran through a different one."""
    res = ax.run({"kind": "carrier-pigeon", "handle": "x"}, "id")
    assert res["ok"] is False
    assert "unsupported transport" in res["error"], res


def test_run_never_raises():
    """A dead shell must not take the phase down with it."""
    res = ax.run({"kind": "bind_shell", "handle": "203.0.113.1:1"}, "id")
    assert res["ok"] is False and res["error"]


def test_a_malformed_handle_is_reported():
    """Asserted on the transport directly.

    Going through run() reports "cannot reach a bind_shell from this container"
    wherever `nc` is absent — which is correct behaviour and a different
    message, so testing through run() would test the environment rather than
    the handle parsing.
    """
    with pytest.raises(ValueError, match="host:port"):
        ax.TRANSPORTS["bind_shell"]("no-port-here", "id")


# ── Probing ────────────────────────────────────────────────────────────────

def test_probing_asks_more_than_once():
    """One answer proves it replied once; 'stable' means it keeps replying."""
    src = _read(os.path.join(REPO, "etl", "access.py"))
    assert "STABILITY_PROBES" in src
    fn = _func_src(os.path.join(REPO, "etl", "access.py"), "probe")
    assert "for _ in range(max(1, rounds))" in fn, (
        "it probes once, so nothing distinguishes a stable shell from a lucky one")


def test_a_dead_probe_leaves_privilege_unknown():
    """"Not probed" and "unprivileged" are different, and recording the first as
    the second would rank a dead root shell as a live user one."""
    res = ax.probe({"kind": "bind_shell", "handle": "203.0.113.1:1"}, rounds=1)
    assert res["is_root"] is None and res["uid"] is None
    assert res["status"] == "dead" and res["score"] == 0


# ── Selection and use ──────────────────────────────────────────────────────

def test_only_live_access_can_be_selected():
    src = _func_src(os.path.join(REPO, "etl", "access.py"), "best_for")
    assert "status = 'live'" in src and "score > 0" in src


def test_an_operator_rejection_is_durable():
    """An operator who ruled an access out is not overruled by it answering."""
    src = _func_src(os.path.join(REPO, "etl", "access.py"), "refresh")
    assert "'rejected'" in src and "THEN 'rejected'" in src


def test_the_checklist_runs_through_one_shell():
    """Running it through every shell would be slow, noisy on the target, and
    would produce several partial answers to one question."""
    fn = _func_src(ENGINE, "_enumerate_through_best_access")
    assert "ax.best_for(target)" in fn, "it no longer selects a single access"
    assert "ax.refresh(target)" in fn, (
        "it selects without measuring first, so the ranking is whatever was "
        "recorded last time — possibly a shell that has since died")
    assert fn.index("refresh") < fn.index("best_for"), (
        "it selects before measuring")


def test_it_does_not_run_mutating_steps():
    """Running the checklist through access we hold is enumeration. Adding a
    backdoor while we are in there is not."""
    fn = _func_src(ENGINE, "_enumerate_through_best_access")
    assert "include_mutating" not in fn, (
        "it asks for mutating steps — persistence is a deliberate operator "
        "action, not something a phase does because it happens to have root")


def test_no_live_access_says_why():
    """"Nothing to enumerate" and "we looked and nothing answered" are different
    states, and the candidate count is what tells them apart."""
    fn = _func_src(ENGINE, "_enumerate_through_best_access")
    assert "candidate(s) probed" in fn


def test_the_chosen_access_is_recorded_in_the_transcript():
    """An operator reading the session has to be able to see which shell the
    enumeration went through, and why that one."""
    fn = _func_src(ENGINE, "_enumerate_through_best_access")
    assert "[access] Using" in fn
    assert "score=" in fn and "whoami=" in fn


# ── Run it where the tools are ─────────────────────────────────────────────

def test_commands_prefer_the_kali_container():
    """autogen-agents has `nc` but no `ssh` and no `sshpass`.

    Probing from there scores every SSH credential zero, so a shell would be
    chosen because the others could not be TESTED rather than because it was
    better — a ranking of tool availability wearing the costume of a ranking of
    access.
    """
    src = _read(os.path.join(REPO, "etl", "access.py"))
    assert "def _run_via_listener" in src
    fn = _func_src(os.path.join(REPO, "etl", "access.py"), "run")
    assert "_run_via_listener(access, command)" in fn
    assert fn.index("_run_via_listener") < fn.index("_have_local_tool"), (
        "it runs locally first and only asks the listener as a fallback, which "
        "is backwards")


def test_a_missing_local_tool_is_not_a_dead_shell():
    """"We could not probe this" and "it did not answer" are different, and
    recording the first as the second is the same mistake as an unparsed run
    counted as fruitless."""
    fn = _func_src(os.path.join(REPO, "etl", "access.py"), "run")
    assert "_have_local_tool(kind)" in fn
    assert "not probed" in fn, (
        "the error does not distinguish 'no tool here' from 'no answer'")


def test_the_listener_exposes_an_access_endpoint():
    """Not /tools/execute: that dispatches a TOOL at a target and is governed by
    the allow-list, which `nc` is deliberately not on. Running a command inside
    access we already hold is a different operation."""
    listener = os.path.join(REPO, "kali_listener", "listener_service.py")
    src = _read(listener)
    assert '@app.post("/access/run")' in src
    assert "from etl.access import TRANSPORTS" in src, (
        "the listener has its own copy of the transports, which will drift")


def test_the_listener_refuses_an_unknown_transport():
    listener = _read(os.path.join(REPO, "kali_listener", "listener_service.py"))
    fn = listener[listener.index("def access_run("):]
    fn = fn[:fn.index("\n@app.")] if "\n@app." in fn else fn
    assert "unsupported transport" in fn
    assert 'return {"ok": False' in fn, (
        "a dead shell raises a 500 instead of being reported as a result — the "
        "caller is probing precisely to find out whether it answers")


# ── Surfaced where an operator will look ───────────────────────────────────

def test_access_is_listed_beside_credentials():
    """Credentials are what we can log in with; access is what we are already
    inside. Same asset, same panel area."""
    page = os.path.join(REPO, "dashboard", "frontend", "src", "pages", "AssetBrowser.tsx")
    src = _read(page)
    assert "Current Access" in src, "the tab is gone"
    assert "function AccessSection" in src
    assert "detailTab === 'access'" in src
    # Ordering, in the TAB BAR — the panel's own definition appears earlier in
    # the file and comparing against that tests nothing about the tab order.
    bar = src[src.index(">Credentials</button>"):]
    bar = bar[:bar.index("Screenshots")]
    assert "Current Access" in bar, (
        "the tab is not between Credentials and Screenshots — access belongs "
        "next to credentials, being the same question one stage later")


def test_the_panel_distinguishes_unknown_from_not_root():
    page = _read(os.path.join(REPO, "dashboard", "frontend", "src", "pages",
                              "AssetBrowser.tsx"))
    fn = page[page.index("function AccessSection"):]
    fn = fn[:fn.index("\nfunction ", 10)]
    assert "a.is_root === null" in fn and "unknown" in fn, (
        "a never-probed access renders as 'not root', which is a different "
        "claim and the wrong one")
    assert "probes_ok" in fn, "stability is not shown, so the score is unexplained"


def test_the_nodes_page_points_at_it():
    """Remote NODES and remote SHELLS are different things with close enough
    names to send someone to the wrong page."""
    page = _read(os.path.join(REPO, "dashboard", "frontend", "src", "pages", "Nodes.tsx"))
    assert "Current Access" in page, "nothing points from Nodes to where shells live"
    assert "/assets" in page
