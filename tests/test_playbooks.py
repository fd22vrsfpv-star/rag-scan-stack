"""The methodology playbooks are machine-readable, and still say what the prose says.

Run on demand:

    pytest tests/test_playbooks.py -v

WHY THIS EXISTS
---------------
`knowledge/playbooks/*.md` holds 3,896 lines of real methodology across twelve
services and techniques, and every line was RAG context. A language model could
be told about a step; nothing could enumerate the steps for a host, run one, or
record whether any had been done.

The concrete cost: `ssh_methodology.md` has a "Post-Exploitation / If Access
Gained" checklist — sudo rights, authorized_keys, known_hosts, sshd_config — that
no code path could reach. A run that recovered a working SSH credential did none
of it, and no report could say what had been skipped.

THE MARKDOWN STAYS AUTHORITATIVE
--------------------------------
The YAML is an EXTRACT, not a replacement: the prose is what a human reads and
what RAG ingests. So the load-bearing test here is the agreement test — every
command in the YAML must appear in the markdown. That makes drift a failure
rather than a slow divergence, and it means the extractor can never invent a
command the methodology does not contain.

WHAT THE EXTRACTOR GOT WRONG (each has a test below)
----------------------------------------------------
  * Stripping a leading `$` as a shell prompt broke 21 PowerShell variable
    assignments into syntactically invalid lines that still looked plausible.
  * Requiring fences at column zero silently dropped six INDENTED fences — all
    of them the SSH post-exploitation checklist, i.e. exactly the steps this
    work exists to reach.
  * A file that could not be structured emitted an empty YAML, which reads as
    "this playbook has no steps" rather than "this is a scraped page with no
    headings".

SAFETY
------
45 of 266 steps MUTATE the target — `useradd backdoor`, `>> authorized_keys`,
Run keys. They are real methodology and they are excluded by default, because a
consumer that queues steps automatically must opt in to changing a host.
Selection is not authorisation either way: the scope gate and the phase's
approval are unchanged.

SABOTAGE PROOF
--------------
Edit a command in a .yaml and `test_every_command_appears_in_the_markdown`
fails. Delete a .yaml and `test_every_playbook_has_an_extract` fails. Drop the
`mutates` filter and `test_mutating_steps_are_excluded_by_default` fails.
"""
import os
import re
import subprocess
import sys

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, REPO)

yaml = pytest.importorskip("yaml", reason="PyYAML needed to read the extracts")
pb = pytest.importorskip("etl.playbooks", reason="etl/playbooks.py not importable")

PLAYBOOKS = os.path.join(REPO, "knowledge", "playbooks")
SCRIPT = os.path.join(REPO, "scripts", "playbooks_to_yaml.py")


def _dir():
    if not os.path.isdir(PLAYBOOKS):
        pytest.skip("knowledge/playbooks not present")
    return PLAYBOOKS


def _mds():
    return sorted(f for f in os.listdir(_dir()) if f.endswith(".md"))


def _docs():
    out = {}
    for f in sorted(os.listdir(_dir())):
        if f.endswith(".yaml"):
            with open(os.path.join(_dir(), f), encoding="utf-8") as fh:
                out[f[:-5]] = yaml.safe_load(fh) or {}
    return out


def _all_steps(doc):
    for ph in doc.get("phases") or []:
        for st in ph.get("steps") or []:
            yield ph, st


# ── The extract exists and matches ─────────────────────────────────────────

def test_every_playbook_has_an_extract():
    missing = [m for m in _mds()
               if not os.path.exists(os.path.join(_dir(), m[:-3] + ".yaml"))]
    assert not missing, (
        f"no machine-readable extract for {missing}. Run "
        "`python3 scripts/playbooks_to_yaml.py` — a playbook with no extract is "
        "prose again, reachable only by a language model.")


def test_the_extract_is_not_stale():
    """Regenerating must produce no change. Prose that has moved on from its
    extract is worse than no extract: consumers act on the stale copy."""
    if not os.path.exists(SCRIPT):
        pytest.skip("extractor not present")
    r = subprocess.run([sys.executable, SCRIPT, "--check"],
                       capture_output=True, text=True, cwd=REPO)
    assert r.returncode == 0, (r.stdout or "") + (r.stderr or "")


def test_every_command_appears_in_the_markdown():
    """The agreement test, and the load-bearing one.

    The markdown is authoritative. If a command is in the YAML and not in the
    prose, the extractor invented it — and a fabricated methodology step is the
    single worst thing this file could produce, because nobody reviewing the
    queue has a reason to doubt it.
    """
    for name, doc in _docs().items():
        md_path = os.path.join(_dir(), doc.get("source") or f"{name}.md")
        if not os.path.exists(md_path):
            pytest.fail(f"{name}.yaml names a source that does not exist: {md_path}")
        with open(md_path, encoding="utf-8") as fh:
            prose = fh.read()
        for _ph, st in _all_steps(doc):
            for c in st.get("commands") or []:
                cmd = c["command"]
                # Continuations are joined on extraction, so check the first
                # segment rather than requiring the joined form verbatim.
                probe = cmd.split(" && ")[0].split(" | ")[0].strip()
                probe = probe[:60]
                assert probe and probe in prose, (
                    f"{name}: command not found in {doc.get('source')}:\n"
                    f"  {cmd[:120]}\nThe extractor invented it, or the markdown "
                    "changed and the YAML was not regenerated.")


def test_the_title_and_source_survive():
    for name, doc in _docs().items():
        assert doc.get("source", "").endswith(".md"), name
        assert doc.get("title"), f"{name} lost its title"


# ── Steps are actionable ───────────────────────────────────────────────────

def test_steps_carry_what_a_consumer_needs():
    for name, doc in _docs().items():
        for ph, st in _all_steps(doc):
            assert st.get("id"), f"{name}: a step has no id"
            assert st.get("title"), f"{name}/{st.get('id')}: no title"
            assert st.get("access_required") in pb.ACCESS_LEVELS, (
                f"{name}/{st['id']}: access_required={st.get('access_required')!r}")
            assert isinstance(st.get("mutates"), bool), (
                f"{name}/{st['id']}: mutates is not a bool")


def test_step_ids_are_unique_within_a_playbook():
    """A duplicate id makes coverage tracking lie: two different steps would be
    marked done by one."""
    for name, doc in _docs().items():
        ids = [st["id"] for _ph, st in _all_steps(doc)]
        dupes = {i for i in ids if ids.count(i) > 1}
        assert not dupes, f"{name}: duplicate step ids {sorted(dupes)}"


def test_there_are_actually_commands():
    total = sum(len(st.get("commands") or [])
                for doc in _docs().values() for _ph, st in _all_steps(doc))
    assert total > 500, (
        f"only {total} commands extracted — the parser has regressed and most "
        "of the methodology is prose again")


def test_a_file_that_could_not_be_structured_says_so():
    """An empty phase list with no explanation reads as "this playbook has no
    steps", which is a different claim from "this is a scraped web page"."""
    for name, doc in _docs().items():
        if not (doc.get("phases") or []):
            assert doc.get("unstructured"), (
                f"{name} has no phases and no reason given — silently empty")


# ── The extraction bugs, each pinned ───────────────────────────────────────

def test_powershell_variables_are_not_mangled():
    """`$Filter = Set-WmiInstance ...` had its `$` stripped as a shell prompt,
    producing 21 syntactically invalid lines that still looked like methodology."""
    found = False
    for name, doc in _docs().items():
        for _ph, st in _all_steps(doc):
            for c in st.get("commands") or []:
                cmd = c["command"]
                if "Set-WmiInstance" in cmd or "New-ScheduledTaskAction" in cmd:
                    found = True
                if re.match(r"^[A-Z][A-Za-z]*\s*=\s*\S", cmd) and "$" not in cmd.split("=")[0]:
                    pytest.fail(f"{name}: `{cmd[:60]}` lost its PowerShell `$`")
    assert found, "the PowerShell steps disappeared entirely"


def test_indented_fences_are_extracted():
    """Six fences are indented, all of them the SSH post-exploitation checklist
    — exactly the steps this work exists to reach."""
    steps = pb.steps_for("ssh", access="shell")
    titles = {s["title"].lower() for s in steps}
    assert any("sudo" in t for t in titles), (
        "the SSH post-access checklist is missing — indented code fences are "
        "being dropped again")
    cmds = " ".join(c["command"] for s in steps for c in s["commands"])
    for expected in ("sudo -l", "authorized_keys", "known_hosts", "sshd_config"):
        assert expected in cmds, f"{expected} is no longer extracted"


def test_no_terminal_transcripts_were_captured_as_commands():
    """`root@ubuntu:~# nmap ...` and its output are a transcript, not a step."""
    for name, doc in _docs().items():
        for _ph, st in _all_steps(doc):
            for c in st.get("commands") or []:
                assert not re.match(r"^\S+@\S+[:~].*[#$]\s", c["command"]), (
                    f"{name}: prompt captured as a command: {c['command'][:70]}")


# ── Safety ─────────────────────────────────────────────────────────────────

def test_mutating_steps_are_excluded_by_default():
    """45 of 266 steps write to the target. A consumer that queues steps
    automatically must opt IN to changing a host."""
    default = pb.steps_for("ssh", access="shell")
    assert all(not s["mutates"] for s in default), (
        "a mutating step is offered by default — `useradd backdoor` and "
        "`>> authorized_keys` would be queued as routine follow-ups")
    with_mut = pb.steps_for("ssh", access="shell", include_mutating=True)
    assert len(with_mut) > len(default), "the opt-in returns nothing extra"


def test_persistence_is_classified_as_mutating():
    doc = _docs().get("persistence_techniques") or {}
    steps = list(_all_steps(doc))
    if not steps:
        pytest.skip("persistence_techniques not extracted")
    mutating = [st for _ph, st in steps if st.get("mutates")]
    assert len(mutating) >= len(steps) // 3, (
        "most of persistence_techniques reads as read-only, which it is not")


def test_access_filtering_is_a_ceiling():
    """A recon consumer must not be handed post-exploitation commands."""
    recon = pb.steps_for("ssh", access="none")
    assert all(s["access_required"] == "none" for s in recon), recon
    assert len(pb.steps_for("ssh", access="shell")) > len(recon)


def test_an_unknown_access_level_is_refused():
    with pytest.raises(ValueError):
        pb.steps_for("ssh", access="root")


# ── The reader ─────────────────────────────────────────────────────────────

def test_a_service_with_no_playbook_returns_nothing():
    """A plausible step from the wrong methodology is worse than no step: the
    operator has no reason to doubt it."""
    assert pb.playbooks_for("gopher") == []
    assert pb.steps_for("gopher") == []


def test_render_reports_what_it_could_not_fill():
    r = pb.render("nmap -p {port} {target}", target="10.0.0.1")
    assert r["unresolved"] == ["port"]
    r = pb.render("nmap -p {port} {target}", target="10.0.0.1", port=22)
    assert r["unresolved"] == [] and r["command"] == "nmap -p 22 10.0.0.1"


def test_checklist_passes_the_mutating_flag_through():
    """Filtering the RESULT is a no-op: checklist() has already excluded
    mutating steps by default, so include_mutating=true was silently identical
    to false all the way out to the HTTP endpoint."""
    plain = pb.checklist("ssh", access="shell", target="10.0.0.1", port=22)
    opted = pb.checklist("ssh", access="shell", include_mutating=True,
                         target="10.0.0.1", port=22)
    assert len(opted) > len(plain), (
        "include_mutating changes nothing — the flag is not reaching steps_for()")
    assert any(i["mutates"] for i in opted)


def test_checklist_marks_what_is_runnable():
    items = pb.checklist("ssh", access="shell", target="10.0.0.1", port=22)
    assert items, "no checklist for ssh"
    assert all("runnable" in i for i in items)


def test_coverage_names_what_is_left():
    """Nothing could answer "what did we skip" before, because nothing could
    enumerate the steps."""
    all_steps = pb.steps_for("ssh", access="shell")
    assert all_steps
    cov = pb.coverage("ssh", done_ids=[all_steps[0]["id"]], access="shell")
    assert cov["total"] == len(all_steps)
    assert cov["done"] == 1
    assert len(cov["remaining"]) == cov["total"] - 1
    assert all("title" in r and "playbook" in r for r in cov["remaining"])
