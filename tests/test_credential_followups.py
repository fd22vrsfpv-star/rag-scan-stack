"""A working credential queues the work it unlocks — and only in scope.

Run on demand:

    pytest tests/test_credential_followups.py -v

WHY THIS EXISTS
---------------
A full run against 192.168.1.150 recovered **ten** valid credentials — ssh, ftp
and telnet, `msfadmin:msfadmin` among them — and left the recommendation queue
**empty**. The run ended there. An operator had to notice the credentials in the
assets panel and drive every follow-on by hand, so in practice the ones nobody
scrolled to were never used.

`knowledge/service_tools.yaml` was no help: every credential entry in it is a
brute-force tool — how to OBTAIN a credential. Nothing answered what to do with
one.

WHAT IS ENFORCED
----------------
  * Follow-ups are **data** (`knowledge/credential_followups.yaml`), so adding
    one needs no Python. A dict in a module is the thing this replaced.
  * **The secret is never written into the stored command.** A command string is
    shown in the UI, written into reports and included in exports; a password
    substituted into it leaks through all three.
  * **The scope gate is checked per entry, with the rendered command**, and its
    polarity is pinned. `check_dispatch` returns a refusal STRING and None to
    proceed — backwards here means every out-of-scope proposal is waved through,
    which is the single worst defect this file could have.
  * **Refusals are recorded, not dropped.** A refusal nobody can see is
    indistinguishable from a proposal that was never made.
  * It **proposes, never dispatches**: `status='pending'`.

SABOTAGE PROOF
--------------
Invert the `if refusal:` test in `queue_followups` and
`test_out_of_scope_is_refused` fails against the live database. Substitute
`{password}` in `render()` and `test_the_secret_never_reaches_the_command`
fails. Replace the YAML lookup with a Python dict and
`test_followups_are_data_not_code` fails.
"""
import ast
import os
import re
import sys

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, REPO)

MODULE = os.path.join(REPO, "etl", "credential_followups.py")
WRITER = os.path.join(REPO, "etl", "parse_brutus.py")


def _catalogue_path():
    """The checkout copy, or the mount when running inside a container.

    `knowledge/` is bind-mounted at `/knowledge` in every service image, so a
    test executing from `/app` has the catalogue but not under the repo root.
    Hard-coding the repo path made these tests report "no follow-ups configured"
    — which is the same symptom as the bug they guard, from the opposite cause.
    """
    for candidate in (os.path.join(REPO, "knowledge", "credential_followups.yaml"),
                      "/knowledge/credential_followups.yaml"):
        if os.path.exists(candidate):
            return candidate
    pytest.skip("credential_followups.yaml not reachable from here")


CATALOGUE = None  # resolved per test via _catalogue_path()

cf = pytest.importorskip("etl.credential_followups",
                         reason="etl/credential_followups.py not importable")


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


# ── The catalogue ──────────────────────────────────────────────────────────

def test_the_catalogue_loads():
    cat = cf.load_catalogue(_catalogue_path())
    assert cat, "no protocols loaded — every credential would queue nothing"
    for proto in ("ssh", "ftp", "telnet", "mysql", "postgresql", "smb"):
        assert proto in cat, f"{proto} has no follow-up; a credential for it dead-ends"


def test_every_entry_is_usable():
    """A catalogue entry nobody can act on is worse than an absent one: it fills
    the queue and teaches the operator to ignore it."""
    for proto, entries in cf.load_catalogue(_catalogue_path()).items():
        for e in entries:
            for field in ("name", "purpose", "command", "priority", "why"):
                assert e.get(field), f"{proto}/{e.get('name')} has no {field}"
            assert isinstance(e["priority"], int) and 0 <= e["priority"] <= 100, \
                f"{proto}/{e['name']} priority {e['priority']!r} is not 0-100"


def test_followups_are_ordered_by_priority():
    entries = cf.followups_for("ssh", cf.load_catalogue(_catalogue_path()))
    assert len(entries) >= 2
    assert entries[0]["priority"] >= entries[-1]["priority"]


def test_followups_are_data_not_code():
    """The mapping lives in YAML so the operator who adds a tool can say what it
    does with a password without touching Python."""
    src = _read(MODULE)
    tree = ast.parse(src)
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for t in node.targets:
                name = getattr(t, "id", "")
                if name.isupper() and isinstance(node.value, ast.Dict) and node.value.keys:
                    pytest.fail(
                        f"{name} is a module-level dict of follow-ups — that is "
                        "the hardcoded mapping this file exists to replace. It "
                        "belongs in knowledge/credential_followups.yaml.")
    assert "yaml" in src and "load_catalogue" in src


def test_an_unknown_protocol_proposes_nothing():
    assert cf.followups_for("gopher", cf.load_catalogue(_catalogue_path())) == []


def test_every_followup_names_a_tool_the_platform_can_run():
    """Ten of the first fourteen named a tool the listener does not allow.

    `nxc` is the modern short name for netexec and the allow-list has
    `netexec`; `ssh`, `impacket-secretsdump` and `vncsnapshot` are not on it at
    all. So the queue filled with work that could only ever come back
    `Tool 'nxc' is not in allowed list` — which looks like a tool problem and is
    really a catalogue that was never checked against reality.

    The allow-list is read from the listener's own fallback set, so this runs on
    a bare checkout with no stack up. The live set is a superset (registry plus
    operator additions), so passing here cannot become a false negative there.
    """
    import re as _re
    import yaml
    listener = os.path.join(REPO, "kali_listener", "listener_service.py")
    if not os.path.exists(listener):
        pytest.skip("kali_listener not present")
    src = _read(listener)
    block = src[src.index("_FALLBACK_ALLOWED_TOOLS = {"):]
    block = block[:block.index("}")]
    allowed = set(_re.findall(r'"([a-z0-9._-]+)"', block))
    assert len(allowed) > 20, "the allow-list could not be parsed"

    with open(_catalogue_path(), encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    offenders = {}
    for proto, entries in data["protocols"].items():
        for e in entries:
            tool = e["command"].strip().split()[0]
            if tool not in allowed:
                offenders[f"{proto}/{e['name']}"] = tool
    assert not offenders, (
        f"these follow-ups name a tool the listener will refuse: {offenders}\n"
        "They queue as pending, get dispatched, and come back "
        "\"is not in allowed list\" — work that looks queued and can never run.")


def test_the_command_starts_with_the_tool():
    """The allow-list checks the FIRST token. `PGPASSWORD='...' psql ...` read
    as a tool named after the password."""
    import yaml
    with open(_catalogue_path(), encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    for proto, entries in data["protocols"].items():
        for e in entries:
            first = e["command"].strip().split()[0]
            assert "=" not in first and "{" not in first, (
                f"{proto}/{e['name']} starts with {first!r}, not a tool name — "
                "an env-var prefix makes the allow-list check nonsense")


# ── The secret ─────────────────────────────────────────────────────────────

def test_the_secret_never_reaches_the_command():
    """A stored command is rendered in the UI, written into reports and included
    in exports. A password substituted into it leaks through all three."""
    cat = cf.load_catalogue(_catalogue_path())
    for proto, entries in cat.items():
        for e in entries:
            rendered = cf.render(e["command"], target="10.0.0.1", port=22,
                                 username="alice", credential_id="cred-1")
            assert "hunter2" not in rendered
            if "{password}" in e["command"]:
                assert "{password}" in rendered, (
                    f"{proto}/{e['name']}: the password placeholder was "
                    "substituted; the secret would be stored in the command")


def test_render_substitutes_everything_else():
    out = cf.render("t {target}:{port} u {username} c {credential_id} p {password}",
                    target="10.0.0.1", port=2222, username="alice", credential_id="c-9")
    assert out == "t 10.0.0.1:2222 u alice c c-9 p {password}"


def test_an_unknown_placeholder_is_left_alone():
    """A catalogue typo should queue a visibly-wrong command an operator can see
    and fix, not abort the ingest that produced the credential."""
    assert cf.render("x {nonsense}", target="t", port=1, username="u",
                     credential_id="c") == "x {nonsense}"


# ── The gate ───────────────────────────────────────────────────────────────

def test_the_gate_polarity_is_not_inverted():
    """check_dispatch returns a refusal STRING and None to proceed. Reading it
    as a boolean 'allowed' waves every out-of-scope proposal through."""
    fn = _func(_read(MODULE), "queue_followups")
    assert "refusal = check_dispatch(" in fn, "the gate call was renamed or removed"
    assert re.search(r"if refusal:\s*\n\s+out\[.refused.\]", fn), (
        "the refusal is no longer acted on as a refusal — check the polarity")
    assert "command=command" in fn, (
        "the rendered command is not passed to the gate, so a template naming a "
        "different host than the target column would not be checked")


def test_the_gate_fails_closed():
    fn = _func(_read(MODULE), "queue_followups")
    assert 'scope_source == "unavailable"' in fn, (
        "an unloadable scope no longer stops the proposal — an unconfigured "
        "scope must never read as permission")


def test_refusals_are_carried_not_dropped():
    fn = _func(_read(MODULE), "queue_followups")
    assert 'out["refusals"].append' in fn
    writer = _read(WRITER)
    assert "followup_refusals" in writer, (
        "the writer discards refusals, so a wrongly-scoped credential looks "
        "identical to one with no follow-ups")


def test_it_proposes_and_never_dispatches():
    fn = _func(_read(MODULE), "queue_followups")
    assert "'pending'" in fn, "follow-ups no longer land as pending"
    for verb in ("subprocess", "requests.post", "httpx."):
        assert verb not in fn, f"queue_followups reaches for {verb} — it must only propose"


# ── The writer hooks it up ─────────────────────────────────────────────────

def test_the_credential_writer_queues_followups():
    src = _read(WRITER)
    assert "queue_followups" in src, (
        "credentials no longer queue their follow-ups, so a run can recover ten "
        "valid credentials and leave the queue empty again")


def test_the_writer_uses_the_stored_id_not_the_generated_one():
    """trg_credential_findings_dedup UPDATEs the existing row and cancels the
    insert, so on a re-verified credential the generated uuid was never stored
    and a follow-up carrying it points at a row that does not exist."""
    src = _read(WRITER)
    assert "stored_id" in src and "SELECT id::text" in src


# ── The queue must actually run them ───────────────────────────────────────

def test_lower_priority_runs_first():
    """The convention is ascending, and getting it backwards is silent.

    The recon agent's drain orders `sr.priority ASC`, the recommender uses
    `base_priority = 5 if msf else 10`, and every ORDER BY priority in the
    codebase agrees. The first version of the catalogue used "higher first", so
    nxc at 90 sorted BEHIND an nmap script at 55 — the follow-up that confirms
    command execution would have run last, and nothing would have looked wrong.
    """
    import yaml
    with open(_catalogue_path(), encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    by_name = {e["name"]: e["priority"]
               for entries in data["protocols"].values() for e in entries}
    assert by_name["netexec"] < by_name["nmap"], (
        "an enumeration script outranks the follow-up that proves command "
        "execution — the priority scale is inverted")

    drain = os.path.join(REPO, "dashboard", "bff", "services", "recon_agent.py")
    if os.path.exists(drain):
        assert "ORDER BY sr.priority ASC" in _read(drain), (
            "the drain no longer orders ascending; this catalogue's numbers "
            "now mean the opposite of what they say")


def test_the_dispatcher_resolves_the_password():
    """Without this the feature is inert.

    `_fill_placeholders` reports any surviving `{...}` as unresolved and the
    dispatch is SKIPPED — so ten queued follow-ups were all skipped with "no
    value known for it". The secret is resolved at dispatch, in memory, from the
    credential_id the row carries.
    """
    path = os.path.join(REPO, "dashboard", "bff", "routers", "assets.py")
    src = _read(path)
    assert "def _resolve_credential" in src, (
        "nothing resolves {password}, so every credential follow-up is skipped")
    fn = _func(src, "_fill_placeholders")
    assert "_resolve_credential(rec)" in fn
    assert '"{password}"' in fn


def test_the_resolved_secret_is_not_recorded():
    """CLAUDE.md: provenance is the "command line (sanitized)".

    kali_listener stores what it runs in tool_executions.command, which the
    scans UI, the post-review agent and every export read. Making follow-ups
    runnable without this would have published the password to all three.
    """
    bff = _read(os.path.join(REPO, "dashboard", "bff", "routers", "assets.py"))
    assert "def _secrets_in" in bff
    assert '"redact": _secrets_in(rec)' in bff, (
        "the dispatcher no longer tells the listener what to mask")

    listener = _read(os.path.join(REPO, "kali_listener", "listener_service.py"))
    assert "redact: List[str]" in listener, "the listener dropped the redact field"
    assert "stored_command = _redacted(" in listener, (
        "the listener records the raw command again — the secret reaches "
        "tool_executions.command")
    # The command that RUNS must still be the real one.
    assert 'active_executions[exec_id] = {' in listener


def test_redaction_masks_the_whole_secret():
    import re as _re
    from typing import List as _List
    src = _read(os.path.join(REPO, "kali_listener", "listener_service.py"))
    ns = {"List": _List}
    start = src.index("def _redacted(")
    exec(src[start:src.index("def db_create_tool_execution(")], ns)
    redacted = ns["_redacted"]

    cmd = "nxc ssh 10.0.0.1 -u msfadmin -p 'msfadmin' -x id"
    out = redacted(cmd, ["msfadmin"])
    assert "'<redacted>'" in out, out
    # A one-character secret would shred the command into noise and tell the
    # operator nothing, so it is deliberately not masked.
    assert redacted("a b c", ["a"]) == "a b c"
    # Longest first: a secret containing another must be masked whole.
    assert "<redacted>" in redacted("p=supersecret", ["secret", "supersecret"])
    assert "super<redacted>" not in redacted("p=supersecret", ["secret", "supersecret"])


def test_the_post_enum_checklist_is_covered():
    """knowledge/playbooks/ssh_methodology.md has a "Post-Exploitation / If
    Access Gained" list. It was prose for RAG context: nothing executed it and
    nothing tracked whether any of it had been done."""
    import yaml
    with open(_catalogue_path(), encoding="utf-8") as fh:
        ssh = yaml.safe_load(fh)["protocols"]["ssh"]
    commands = " ".join(e["command"] for e in ssh)
    for step in ("sudo -n -l", "authorized_keys", "known_hosts", "sshd_config"):
        assert step in commands, (
            f"the post-access checklist no longer covers {step!r} — it is in "
            "the playbook and nothing would run it")


# ── Captured evidence must not re-expose the secret ────────────────────────

def test_the_confirming_line_masks_the_password():
    """Capturing the tool's proof re-exposed the secret somewhere the UI does
    not mask it.

    hydra prints `login: msfadmin   password: msfadmin` and nmap prints
    `msfadmin:msfadmin - Valid credentials`, and the evidence block renders both
    verbatim. `SecretValue` hides the password behind a deliberate Reveal click
    because that panel is on screen during screen-shares and report writing — an
    unmasked copy two rows above it defeats the whole control.

    Only the PASSWORD is masked. The username stays readable, and a blunt string
    replacement would mangle `anonymous` / `anonymous@` where the two overlap.
    """
    import re as _re
    from typing import Any, Dict, List, Optional, Tuple
    src = _read(os.path.join(REPO, "nmap_scanner", "cred_checker.py"))
    # Exec just the helper block rather than importing the module: cred_checker
    # pulls in the scope gate and the scan-slot semaphore at import, neither of
    # which a pure redaction test should need.
    ns = {"re": _re, "Optional": Optional, "Tuple": Tuple, "List": List,
          "Dict": Dict, "Any": Any}
    exec(src[src.index("def _mask_password"):src.index("def _classify_hydra_failure")], ns)
    redact = ns["_redact_secret"]

    cases = [  # real captured output from 192.168.1.150
        ("[21][ftp] host: 192.168.1.150   login: msfadmin   password: msfadmin",
         "msfadmin", "msfadmin"),
        ("|     msfadmin:msfadmin - Valid credentials", "msfadmin", "msfadmin"),
        ("|     user:user - Valid credentials", "user", "user"),
        ("[21][ftp] host: 1.2.3.4   login: anonymous   password: anonymous@",
         "anonymous", "anonymous@"),
        ("[22][ssh] host: 10.0.0.1   login: admin   password: Sup3rSecret!",
         "admin", "Sup3rSecret!"),
    ]
    for line, user, password in cases:
        out = redact(line, user, password)
        assert not _re.search(
            rf"(?:pass(?:word)?|passwd)\s*[:=]\s*{_re.escape(password)}", out, _re.I), out
        assert not _re.search(
            rf"{_re.escape(user)}\s*:\s*{_re.escape(password)}\b", out), out
        assert user in out, f"the username was mangled: {out}"


# ── Against the live database ──────────────────────────────────────────────

@pytest.fixture
def cur():
    psycopg2 = pytest.importorskip("psycopg2")
    dsn = os.environ.get("DB_DSN") or os.environ.get("DATABASE_URL")
    if not dsn:
        pytest.skip("no DB_DSN")
    try:
        conn = psycopg2.connect(dsn, connect_timeout=5)
    except Exception as e:  # noqa: BLE001
        pytest.skip(f"database unreachable: {e}")
    c = conn.cursor()
    yield c
    conn.rollback()          # nothing this test proposes is ever committed
    conn.close()


def test_in_scope_queues_pending_rows(cur):
    r = cf.queue_followups(cur, ip="192.168.1.150", port=22, protocol="ssh",
                           username="msfadmin", credential_id="00000000-0000-0000-0000-000000000001")
    if r["scope_source"] == "unavailable":
        pytest.skip("no scope configured in this database")
    assert r["proposed"] >= 2
    assert r["refused"] == 0, r["refusals"]
    # Not `queued >= 1`: the insert is idempotent on fingerprint, so a second
    # run legitimately reports 0 NEW rows. What must hold is that the work is
    # queued — whether this call or an earlier one put it there.
    assert r["queued"] >= 1 or r["entries"], r
    cur.execute("SELECT status FROM scan_recommendations "
                "WHERE source = %s AND host(ip) = %s ORDER BY created_at DESC LIMIT 1",
                (cf.SOURCE, "192.168.1.150"))
    row = cur.fetchone()
    assert row and row[0] == "pending", (
        f"the follow-up is not queued as pending: {row!r} — it either never "
        "landed, or it landed in a state a human is not asked to approve")


def test_out_of_scope_is_refused(cur):
    """The invariant. A proposal naming an out-of-scope host is an authorization
    defect whether or not it ever executes."""
    r = cf.queue_followups(cur, ip="8.8.8.8", port=22, protocol="ssh",
                           username="root", credential_id="00000000-0000-0000-0000-000000000002")
    assert r["queued"] == 0, "an out-of-scope credential queued work"
    assert r["refused"] == r["proposed"], r
    assert r["refusals"], "the refusal was not recorded"
    assert "scope" in r["refusals"][0]["reason"].lower()
