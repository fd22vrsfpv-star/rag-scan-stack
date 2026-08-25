"""Per-tool analysis profiles: extract, interpret, and act on what a tool found.

Run on demand:

    pytest tests/test_analysis_profiles.py -v

WHY THIS EXISTS
---------------
103 catalogue tools, 5 extraction specs, and 182 runs whose output nothing
interpreted. Worse, the two mechanisms that DID exist detected the same
conditions with different pattern sets: `artifact_rules/builtin.yaml` matched
`SMBv1\\s*[:=]\\s*True` over raw text to propose an nmap command, while the
extractor independently emitted the `smb_v1_enabled` fact. Neither could see the
other's work, so an action could never use an extracted VALUE — the extractor
knew a share was called `tmp` and a text regex could only say "shares exist".

`follow_on` closes that: rules fire on extracted FIELDS, so `for_each: shares`
turns the same fact into `smbclient //target/tmp`.
"""
import json
import os
import subprocess
import sys

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
for path in (REPO, os.path.join(REPO, "app", "rag-api")):
    if path not in sys.path:
        sys.path.insert(0, path)

pytest.importorskip("yaml")
es = pytest.importorskip("extractor_specs", reason="extractor_specs not importable")
SPEC_DIR = os.path.join(REPO, "knowledge", "extractors")
RULES = os.path.join(REPO, "knowledge", "artifact_rules", "builtin.yaml")


@pytest.fixture(scope="module")
def specs():
    loaded, problems = es.load_specs(SPEC_DIR, force=True)
    assert not problems, f"spec problems: {problems}"
    return loaded


# ── class templates ─────────────────────────────────────────────────────────

def test_the_class_file_is_not_loaded_as_a_tool(specs):
    """`_classes.yaml` is a template, not a spec. `_spec_files` skips names
    beginning with '_'."""
    assert "_classes" not in specs and "classes" not in specs


def test_a_tool_inherits_its_class_rules(specs):
    """The scalability lever: the class carries the shape, the tool carries the
    patterns. 103 tools are not 103 different problems."""
    spec = es.spec_for("smtp-user-enum", SPEC_DIR)
    assert spec["_class"] == "user_enumeration"
    ids = {r["id"] for r in spec["follow_on"]}
    assert "users_to_identities" in ids, "the class follow_on was not inherited"
    assert "spray_enumerated_smtp_users" in ids, "the tool's own rule was lost"
    assert {r["id"] for r in spec["notable"]} >= {"users_enumerated"}


def test_a_tool_rule_replaces_the_class_rule_of_the_same_id():
    """A class ships a default; one tool overrides it without copying the rest."""
    tmpl = {"user_enumeration": {
        "notable": [{"id": "users_enumerated", "severity": "low",
                     "when": "len(valid_users) > 0", "title": "class version"}]}}
    spec = {"tool": "x", "class": "user_enumeration",
            "notable": [{"id": "users_enumerated", "severity": "high",
                         "when": "len(valid_users) > 0", "title": "tool version"}]}
    merged = es._apply_class(spec, tmpl)
    rules = [r for r in merged["notable"] if r["id"] == "users_enumerated"]
    assert len(rules) == 1, "the rule was inherited AND kept — it is duplicated"
    assert rules[0]["severity"] == "high", "the class overrode the tool"


def test_the_tool_wins_on_a_scalar_key():
    tmpl = {"c": {"max_chars": 1000, "description": "class"}}
    merged = es._apply_class({"tool": "x", "class": "c", "max_chars": 40000}, tmpl)
    assert merged["max_chars"] == 40000
    assert merged["description"] == "class", "an absent key should inherit"


# ── follow_on validation ────────────────────────────────────────────────────

@pytest.mark.unit
def test_a_rule_that_neither_runs_nor_feeds_is_rejected():
    """A declaration with no effect reads as coverage."""
    problems = es._validate_spec(
        {"tool": "x", "prompt": "p", "schema": {"a": {"type": "list"}},
         "follow_on": [{"id": "noop", "when": "len(a) > 0"}]}, "bad.yaml")
    assert any("neither 'script' nor 'feeds'" in p for p in problems), problems


@pytest.mark.unit
def test_an_unknown_feed_sink_is_rejected():
    """A sink nothing consumes is plumbing that moves nothing."""
    problems = es._validate_spec(
        {"tool": "x", "prompt": "p", "schema": {"a": {"type": "list"}},
         "follow_on": [{"id": "f", "when": "len(a) > 0", "feeds": "nowhere"}]},
        "bad.yaml")
    assert any("which nothing consumes" in p for p in problems), problems


@pytest.mark.unit
def test_for_each_must_name_a_list_field():
    for schema, expect in (({"a": {"type": "string"}}, "not a list"),
                           ({"b": {"type": "list"}}, "not in the schema")):
        problems = es._validate_spec(
            {"tool": "x", "prompt": "p", "schema": schema,
             "follow_on": [{"id": "f", "when": "len(a) > 0", "for_each": "a",
                            "scanner": "s", "script": "cmd {item}"}]}, "bad.yaml")
        assert any(expect in p for p in problems), (expect, problems)


@pytest.mark.unit
def test_a_script_without_a_scanner_is_rejected():
    """The dispatcher routes on `scanner`; a script without one cannot run."""
    problems = es._validate_spec(
        {"tool": "x", "prompt": "p", "schema": {"a": {"type": "list"}},
         "follow_on": [{"id": "f", "when": "len(a) > 0", "script": "do it"}]},
        "bad.yaml")
    assert any("no 'scanner'" in p for p in problems), problems


# ── for_each: the capability a text regex cannot express ───────────────────

@pytest.mark.unit
def test_one_action_per_share_and_none_for_ipc_endpoints(specs):
    """The old engine could only say "shares were found". This names them."""
    spec = es.spec_for("smbclient", SPEC_DIR)
    extracted = {"shares": ["print$", "tmp", "opt"],
                 "ipc_endpoints": ["IPC$", "ADMIN$"], "null_session": True}
    actions = es.follow_on_from(spec, extracted, {"target": "10.0.0.1"})
    browse = [a for a in actions if a["id"].startswith("browse_share")]
    assert len(browse) == 3, [a["id"] for a in browse]
    scripts = " ".join(a["script"] for a in browse)
    for share in ("print$", "tmp", "opt"):
        assert f"/{share}" in scripts, share
    for endpoint in ("IPC$", "ADMIN$"):
        assert f"/{endpoint}" not in scripts, (
            f"{endpoint} became a browse action — it is an IPC service "
            "endpoint, not a browsable share")


@pytest.mark.unit
def test_an_empty_list_produces_no_actions(specs):
    spec = es.spec_for("smbclient", SPEC_DIR)
    assert es.follow_on_from(spec, {"shares": []}, {"target": "h"}) == []


# ── the action contract, shared with artifact_actions ──────────────────────

@pytest.mark.unit
def test_an_unresolved_placeholder_never_auto_queues():
    """Same rule as artifact_actions: an action that cannot run as written must
    never queue, or it sits there as permanently un-runnable noise.

    The rule below OPTS IN to auto_queue and still must not get it. An earlier
    version of this test used a shipped rule that never sets `auto_queue: true`,
    so `bool(rule.get("auto_queue"))` was False on its own — the assertion held
    no matter what the suppression did, and it passed a sabotage that deleted
    the suppression entirely.
    """
    spec = {"tool": "x", "follow_on": [{
        "id": "wants_to_queue", "when": "len(users) > 0",
        "scanner": "hydra", "auto_queue": True,
        "script": "hydra -L {user_list} -P {password_list} smtp://{target}:25"}]}
    action = es.follow_on_from(spec, {"users": ["root"]},
                               {"target": "10.0.0.1"})[0]
    assert "{user_list}" in action["script"], "the fixture no longer proves it"
    assert action["needs_input"] is True
    assert action["auto_queue"] is False, (
        "an action with an unresolved placeholder opted into auto_queue and got "
        "it — it would sit in the queue permanently un-runnable")


@pytest.mark.unit
def test_a_fully_resolved_action_may_auto_queue():
    """The other half: the suppression must not block everything."""
    spec = {"tool": "x", "follow_on": [{
        "id": "runnable", "when": "len(users) > 0", "scanner": "showmount",
        "auto_queue": True, "script": "showmount -e {target}"}]}
    action = es.follow_on_from(spec, {"users": ["root"]},
                               {"target": "10.0.0.1"})[0]
    assert action["needs_input"] is False
    assert action["auto_queue"] is True


@pytest.mark.unit
def test_actions_match_the_shape_artifact_actions_returns(specs):
    """So _insert_recommendation and the UI are unchanged."""
    required = {"id", "category", "title", "scanner", "script", "rationale",
                "priority", "evidence", "needs_input", "auto_queue", "source"}
    spec = es.spec_for("rpcinfo", SPEC_DIR)
    actions = es.follow_on_from(
        spec, {"services": ["nfs"], "service_ports": ["2049"],
               "nfs_present": True}, {"target": "10.0.0.1"})
    assert actions
    for a in actions:
        assert required <= set(a), required - set(a)
        assert a["source"] == "analysis_profile"


@pytest.mark.unit
def test_a_feed_action_is_data_not_a_command(specs):
    """`feeds` carries a result to a sink; it is not something a human runs."""
    spec = es.spec_for("smtp-user-enum", SPEC_DIR)
    actions = es.follow_on_from(spec, {"valid_users": ["root", "mysql"]},
                                {"target": "h", "port": 25})
    feed = [a for a in actions if a.get("feeds")][0]
    assert feed["feeds"] == "identities"
    assert feed["auto_queue"] is False and feed["needs_input"] is False
    assert feed["feed_values"] == ["root", "mysql"]


# ── the profiles, against real captured output ─────────────────────────────

SMTP_OUT = """Mode ..................... VRFY
Usernames file ........... /usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt
192.168.1.150: user exists
192.168.1.150: mysql exists
192.168.1.150: ftp exists
4 results.
"""

RPCINFO_OUT = """   program vers proto   port  service
    100000    2   tcp    111  portmapper
    100024    1   udp  45406  status
    100003    2   udp   2049  nfs
    100005    1   tcp  48005  mountd
"""

MEDUSA_OUT = """2026-08-19 21:59:49 ACCOUNT CHECK: [ssh] Host: 192.168.1.150 (1 of 1, 0 complete) User: root (1 of 17, 0 complete) Password: 123456 (1 of 14344391 complete)
2026-08-19 22:10:02 ACCOUNT FOUND: [ssh] Host: 192.168.1.150 User: msfadmin Password: msfadmin [SUCCESS]
"""


@pytest.mark.unit
def test_smtp_user_enum_extracts_only_confirmed_accounts(specs):
    """The header block names the usernames FILE. Reading account names from it
    would invent every name in the shortlist as a discovered account."""
    spec = es.spec_for("smtp-user-enum", SPEC_DIR)
    got = es.run_deterministic(spec, SMTP_OUT)
    assert got["valid_users"] == ["user", "mysql", "ftp"], got["valid_users"]
    assert got["mode"] == "VRFY"
    assert "top-usernames-shortlist.txt" not in str(got["valid_users"])


@pytest.mark.unit
def test_rpcinfo_finds_the_ports_a_port_scan_misses(specs):
    """`status` on 45406 sits far outside any default nmap range."""
    spec = es.spec_for("rpcinfo", SPEC_DIR)
    got = es.run_deterministic(spec, RPCINFO_OUT)
    assert got["services"] == ["portmapper", "status", "nfs", "mountd"]
    assert "45406" in got["service_ports"] and "48005" in got["service_ports"]
    assert got["nfs_present"] is True
    assert "program" not in got["services"], "the column header became a service"


@pytest.mark.unit
def test_rpcinfo_proposes_showmount_once_not_per_row(specs):
    spec = es.spec_for("rpcinfo", SPEC_DIR)
    actions = es.follow_on_from(spec, es.run_deterministic(spec, RPCINFO_OUT),
                                {"target": "10.0.0.1"})
    showmount = [a for a in actions if a["id"] == "list_nfs_exports"]
    assert len(showmount) == 1, f"{len(showmount)} showmount actions"
    assert showmount[0]["script"] == "showmount -e 10.0.0.1"


@pytest.mark.unit
def test_medusa_never_reads_a_tried_candidate_as_a_result(specs):
    """ACCOUNT CHECK is a candidate being tried. All 6 stored medusa runs are
    CHECK lines with zero FOUND — reading one as a hit would report six
    credential discoveries where there were none."""
    spec = es.spec_for("medusa", SPEC_DIR)
    got = es.run_deterministic(spec, MEDUSA_OUT)
    assert len(got["credentials"]) == 1, got["credentials"]
    assert "msfadmin" in got["credentials"][0]
    assert "123456" not in str(got["credentials"]), \
        "an ACCOUNT CHECK line was read as a recovered credential"
    assert got["candidates_total"] == 14344391


@pytest.mark.unit
def test_medusa_with_no_recovery_reports_none(specs):
    spec = es.spec_for("medusa", SPEC_DIR)
    checks_only = MEDUSA_OUT.splitlines()[0] + "\n"
    got = es.run_deterministic(spec, checks_only)
    assert not got.get("credentials"), got.get("credentials")


# ── migration: one condition, one engine ───────────────────────────────────

@pytest.mark.unit
def test_a_tool_only_leaves_a_text_rule_once_its_profile_can_replace_it():
    """The migration precondition, not the migration itself.

    `smbv1_enabled` matches raw text for 7 tools while the profiles emit the
    same condition as a FACT, so one condition has two detections with two
    pattern sets that can drift. The fix is to remove a tool from the rule — but
    ONLY once its profile emits an equivalent `follow_on`, because the rule's
    value is the ACTION it proposes, not the detection.

    Removing five tools before checking that cost them their follow-ups: of
    crackmapexec, netexec, smbclient, enum4linux and enum4linux-ng, only
    smbclient has any `follow_on` at all, and it browses a share rather than
    scanning for MS17-010. Two existing tests caught it. This asserts the
    precondition so the next attempt cannot repeat it.
    """
    yaml = pytest.importorskip("yaml")
    rules = (yaml.safe_load(open(RULES, encoding="utf-8")) or {}).get("rules") or []
    loaded, _ = es.load_specs(SPEC_DIR, force=True)

    SMB_RULES = {"smbv1_enabled", "smb_signing_disabled", "smb_shares"}
    # Every tool these rules covered when the migration was attempted.
    EXPECTED = {"crackmapexec", "netexec", "smbmap", "smbclient",
                "enum4linux", "enum4linux-ng", "nmap"}

    for rule in rules:
        if rule["id"] not in SMB_RULES:
            continue
        listed = {t.lower() for t in (rule.get("tools") or [])}
        for tool in EXPECTED - listed:
            spec = loaded.get(tool)
            assert spec, (
                f"{tool} was removed from {rule['id']} but has no analysis "
                "profile at all — its follow-up is simply gone")
            assert spec.get("follow_on"), (
                f"{tool} was removed from {rule['id']} but its profile emits no "
                "follow_on, so the action that rule proposed is not replaced. A "
                "tool may only leave a text rule once its profile can act.")
