"""Follow-on action suggestions derived from raw tool output.

Run on demand:

    pytest tests/test_artifact_actions.py -v

These rules decide what a pentester is prompted to do next, so the failure
modes that matter are the quiet ones:

* a rule firing on the TOOL's own chatter instead of the target's behaviour
  (crackmapexec prints "Generating SSL certificate" while creating its own
  config dir — that once proposed a TLS audit of a host with no TLS at all,
  the same class of bug that filed nmap.org banner URLs as findings),
* a suggestion with no evidence, which an operator cannot justify or act on,
* a command still holding a placeholder being presented as runnable,
* turning a host merely MENTIONED in output into a new scan target.

No database or network — pure functions over fixtures.
"""
import importlib.util
import os

import pytest

_PATH = os.path.join(os.path.dirname(__file__), "..", "app", "rag-api", "artifact_actions.py")


_RULES_DIR = os.path.join(os.path.dirname(__file__), "..", "knowledge", "artifact_rules")


@pytest.fixture(scope="module")
def aa():
    if not os.path.exists(_PATH):                # pragma: no cover
        pytest.skip("artifact_actions.py not present")
    spec = importlib.util.spec_from_file_location("artifact_actions", _PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    # Point at the repo's shipped rules rather than the container path, so the
    # suite runs from a checkout with no /knowledge mount.
    mod.RULES_DIR = _RULES_DIR
    return mod


def ids(actions):
    return [a["id"] for a in actions]


# ── Real captured output ──────────────────────────────────────────────────

CRACKMAPEXEC = (
    "[*] First time use detected\n"
    "[*] Creating home directory structure\n"
    "[*] Copying default configuration file\n"
    "[*] Generating SSL certificate\n"
    "SMB    192.168.1.150   445    METASPLOITABLE   [*] Unix (name:metasploitable) "
    "(domain:localdomain) (signing:False) (SMBv1:True)\n"
)

WHATWEB_JSON = (
    '[{"target":"http://192.168.1.150","http_status":200,'
    '"plugins":{"Apache":{"version":["2.2.8"]},"HTTPServer":{"os":["Ubuntu Linux"]}}}]'
)

NMAP = (
    "Starting Nmap 7.94 ( https://nmap.org ) at 2026-08-19 09:00\n"
    "PORT     STATE SERVICE VERSION\n"
    "21/tcp   open  ftp     vsftpd 2.3.4\n"
    "|_ftp-anon: Anonymous FTP login allowed (FTP code 230)\n"
    "445/tcp  open  netbios-ssn Samba smbd 3.X\n"
)


def test_smb_evidence_produces_smb_actions(aa):
    got = ids(aa.suggest_actions(CRACKMAPEXEC, tool="crackmapexec", target="192.168.1.150"))
    assert "smbv1_enabled" in got
    assert "smb_signing_disabled" in got


def test_tool_setup_chatter_does_not_trigger_rules(aa):
    """The regression this filter exists for: crackmapexec generating its OWN
    certificate must not propose a TLS audit of the target."""
    assert "tls_present" not in ids(aa.suggest_actions(CRACKMAPEXEC, tool="crackmapexec",
                                                       target="192.168.1.150"))


def test_genuine_tls_evidence_still_fires(aa):
    """The noise filter must not be so broad that it silences real findings."""
    real = "443/tcp open ssl/http\n|_ssl-cert: Subject: commonName=target.local\nTLSv1.2"
    assert "tls_present" in ids(aa.suggest_actions(real, tool="nmap", target="10.0.0.1"))


def test_nmap_banner_url_is_not_treated_as_web_surface(aa):
    """`Starting Nmap ( https://nmap.org )` is the tool's banner, not the target."""
    actions = aa.suggest_actions(NMAP, tool="nmap", target="192.168.1.150")
    for a in actions:
        assert "nmap.org" not in a["evidence"]


def test_anonymous_ftp_detected(aa):
    assert "anonymous_ftp" in ids(aa.suggest_actions(NMAP, tool="nmap", target="192.168.1.150"))


def test_software_version_detected_from_native_json(aa):
    """The whole point of preferring native JSON: Apache 2.2.8 as a real field."""
    assert "software_version" in ids(aa.suggest_actions(WHATWEB_JSON, tool="whatweb",
                                                        target="192.168.1.150"))


def test_every_action_cites_evidence(aa):
    """A suggestion with no evidence cannot be justified by the operator."""
    for content, tool in ((CRACKMAPEXEC, "crackmapexec"), (NMAP, "nmap"), (WHATWEB_JSON, "whatweb")):
        for a in aa.suggest_actions(content, tool=tool, target="192.168.1.150"):
            if a["source"] == "rules":
                assert a["evidence"].strip(), f"{a['id']} produced no evidence"


def test_target_is_substituted_into_commands(aa):
    for a in aa.suggest_actions(CRACKMAPEXEC, tool="crackmapexec", target="192.168.1.150"):
        if not a["needs_input"]:
            assert "{target}" not in a["script"]
            assert "192.168.1.150" in a["script"]


def test_unfilled_placeholder_is_flagged_not_hidden(aa):
    """A command with a placeholder must be marked needs_input — one that looks
    runnable but isn't is worse than one honestly marked incomplete."""
    creds = "[+] WORKGROUP\\msfadmin:msfadmin"
    action = next(a for a in aa.suggest_actions(creds, tool="netexec", target="10.0.0.1")
                  if a["id"] == "credentials_found")
    assert action["needs_input"] is True


def test_cves_are_extracted_into_the_lookup_command(aa):
    out = "VULNERABLE: Samba (CVE-2007-2447), also CVE-2011-1234"
    a = next(x for x in aa.suggest_actions(out, tool="nmap", target="10.0.0.1")
             if x["id"] == "cve_referenced")
    assert "CVE-2007-2447" in a["script"] and "CVE-2011-1234" in a["script"]
    assert "{cve}" not in a["script"]


def test_mentioned_hosts_never_become_targets(aa):
    """Scope safety. Output referencing twiki.org / twitter.com previously led to
    scans of third-party hosts; suggestions must only ever act on the artifact's
    own target."""
    out = ("Redirect to https://twitter.com/example\n"
           "Powered by TWiki - see https://twiki.org\n200 OK")
    for a in aa.suggest_actions(out, tool="whatweb", target="192.168.1.150"):
        assert "twitter.com" not in a["script"]
        assert "twiki.org" not in a["script"]


def test_ansi_escapes_stripped_from_evidence(aa):
    """whatweb colours stdout; raw escapes make evidence unreadable in the UI."""
    coloured = "\x1b[1m\x1b[34mhttp://192.168.1.150\x1b[0m [200 OK] \x1b[1mApache\x1b[0m[2.2.8]"
    for a in aa.suggest_actions(coloured, tool="whatweb", target="192.168.1.150"):
        assert "\x1b[" not in a["evidence"]


def test_results_sorted_by_priority(aa):
    got = aa.suggest_actions(NMAP + CRACKMAPEXEC, tool="nmap", target="192.168.1.150")
    assert [a["priority"] for a in got] == sorted((a["priority"] for a in got), reverse=True)


def test_empty_content_yields_nothing(aa):
    assert aa.suggest_actions("", tool="nmap", target="10.0.0.1") == []


def test_no_duplicate_rule_ids(aa):
    got = ids(aa.suggest_actions(NMAP + CRACKMAPEXEC + WHATWEB_JSON, tool="nmap",
                                 target="192.168.1.150"))
    assert len(got) == len(set(got))


def test_max_actions_is_respected(aa):
    got = aa.suggest_actions(NMAP + CRACKMAPEXEC + WHATWEB_JSON, tool="nmap",
                             target="10.0.0.1", max_actions=2)
    assert len(got) == 2


# ── LLM-proposed suggestions ──────────────────────────────────────────────

def test_llm_suggestions_are_merged_and_labelled(aa):
    got = aa.suggest_actions(CRACKMAPEXEC, tool="crackmapexec", target="10.0.0.1",
                             llm_result={"suggested_actions": [
                                 {"title": "Check for null sessions", "scanner": "enum4linux",
                                  "script": "enum4linux -a 10.0.0.1", "priority": 60}]})
    llm = [a for a in got if a["source"] == "llm"]
    assert len(llm) == 1
    assert llm[0]["title"] == "Check for null sessions"
    assert llm[0]["needs_input"] is False


def test_llm_string_items_are_accepted(aa):
    """Models return prose as often as objects; a bare string must not crash."""
    got = aa.suggest_actions(CRACKMAPEXEC, tool="x", target="10.0.0.1",
                             llm_result={"follow_ups": ["Review SMB share ACLs"]})
    llm = [a for a in got if a["source"] == "llm"]
    assert llm and llm[0]["title"] == "Review SMB share ACLs"
    # No scanner or command means nothing to dispatch — must be flagged.
    assert llm[0]["needs_input"] is True


def test_malformed_llm_result_is_ignored_not_fatal(aa):
    for bad in (None, "nonsense", {"suggested_actions": "not a list"},
                {"actions": [None, 42, {}]}):
        got = aa.suggest_actions(CRACKMAPEXEC, tool="x", target="10.0.0.1", llm_result=bad)
        assert all(a["source"] == "rules" for a in got)


def test_evidence_centres_on_the_match_in_long_json_lines(aa):
    """Native JSON is one long line. Trimming from the start showed the opening
    of the document instead of the thing that triggered the rule."""
    long_json = ('{"scan":{"meta":"' + "x" * 400 + '"},'
                 '"plugins":{"Apache":{"version":["2.2.8"]}}}')
    a = next(x for x in aa.suggest_actions(long_json, tool="whatweb", target="10.0.0.1")
             if x["id"] == "software_version")
    assert "Apache" in a["evidence"], f"match not shown: {a['evidence'][:80]}"
    assert len(a["evidence"]) <= aa.EVIDENCE_CHARS + 2   # +2 for the ellipses


# ── YAML rule loading, tool scoping and auto-queue ────────────────────────

def test_shipped_rules_load_without_errors(aa):
    """A broken builtin.yaml silently disables every suggestion, so the shipped
    file must parse cleanly and completely."""
    rules, errors = aa.load_rules(_RULES_DIR, force=True)
    assert errors == [], f"shipped rules have errors: {errors}"
    assert len(rules) >= 15


def test_every_shipped_rule_is_complete_and_compiles(aa):
    rules, _ = aa.load_rules(_RULES_DIR, force=True)
    for r in rules:
        for field in ("id", "pattern", "scanner", "script", "title", "rationale"):
            assert r.get(field), f"{r.get('id')} missing {field}"
        assert r["_rx"] is not None
        assert 0 <= r["priority"] <= 100


def test_tool_scoping_filters_rules(aa):
    """The point of per-tool rules: identical text, different tools, different
    suggestions. Previously every artifact was evaluated against every rule."""
    smb = "SMB 10.0.0.1 445 HOST [*] Unix (signing:False) (SMBv1:True)"
    assert ids(aa.suggest_actions(smb, tool="crackmapexec", target="10.0.0.1"))
    assert ids(aa.suggest_actions(smb, tool="katana", target="10.0.0.1")) == []


def test_universal_rules_apply_to_any_tool(aa):
    """A CVE is worth looking up whichever tool mentioned it."""
    out = "VULNERABLE: CVE-2007-2447"
    for tool in ("crackmapexec", "katana", "some-unknown-tool"):
        assert "cve_referenced" in ids(aa.suggest_actions(out, tool=tool, target="10.0.0.1"))


def test_auto_queue_is_opt_in_per_rule(aa):
    """Only rules that explicitly opt in may be queued without a human."""
    rules, _ = aa.load_rules(_RULES_DIR, force=True)
    auto = {r["id"] for r in rules if r.get("auto_queue")}
    assert auto, "expected some rules to opt into auto-queue"
    assert len(auto) < len(rules), "auto-queue must not be the default for everything"


def test_needs_input_actions_never_auto_queue(aa):
    """An action with an unfilled placeholder cannot run, so auto-queuing it
    would park permanently un-runnable work in the operator's queue."""
    creds = "[+] WORKGROUP\\msfadmin:msfadmin"
    for a in aa.suggest_actions(creds, tool="netexec", target="10.0.0.1"):
        if a["needs_input"]:
            assert a["auto_queue"] is False, f"{a['id']} would auto-queue un-runnable"


def test_llm_suggestions_never_auto_queue(aa):
    """Model output carries no verified evidence and no rule author."""
    got = aa.suggest_actions("SMBv1:True", tool="crackmapexec", target="10.0.0.1",
                             llm_result={"suggested_actions": [
                                 {"title": "Do a thing", "scanner": "nmap",
                                  "script": "nmap 10.0.0.1"}]})
    for a in got:
        if a["source"] == "llm":
            assert a["auto_queue"] is False


def test_custom_yaml_overrides_builtin_by_id(aa, tmp_path):
    """Local rules must win over shipped ones without editing builtin.yaml."""
    (tmp_path / "custom").mkdir()
    (tmp_path / "builtin.yaml").write_text(
        "rules:\n"
        "  - id: demo\n    pattern: 'FOO'\n    scanner: nmap\n"
        "    script: 'nmap {target}'\n    title: Builtin\n    rationale: b\n")
    (tmp_path / "custom" / "local.yaml").write_text(
        "rules:\n"
        "  - id: demo\n    pattern: 'FOO'\n    scanner: nmap\n"
        "    script: 'nmap -A {target}'\n    title: Overridden\n    rationale: o\n")
    got = aa.suggest_actions("FOO", tool="nmap", target="10.0.0.1", rules_dir=str(tmp_path))
    assert len(got) == 1
    assert got[0]["title"] == "Overridden"


def test_rule_can_be_disabled(aa, tmp_path):
    (tmp_path / "builtin.yaml").write_text(
        "rules:\n"
        "  - id: off_rule\n    pattern: 'FOO'\n    scanner: nmap\n"
        "    script: 'nmap {target}'\n    title: t\n    rationale: r\n    enabled: false\n")
    assert aa.suggest_actions("FOO", tool="nmap", target="10.0.0.1",
                              rules_dir=str(tmp_path)) == []


def test_invalid_rule_is_skipped_not_fatal(aa, tmp_path):
    """One bad rule must not take out the whole rule set — the others still
    have to produce suggestions, and the error has to be reported."""
    (tmp_path / "builtin.yaml").write_text(
        "rules:\n"
        "  - id: broken\n    pattern: '([unclosed'\n    scanner: nmap\n"
        "    script: 'nmap {target}'\n    title: t\n    rationale: r\n"
        "  - id: missing_script\n    pattern: 'FOO'\n    scanner: nmap\n"
        "    title: t\n    rationale: r\n"
        "  - id: good\n    pattern: 'FOO'\n    scanner: nmap\n"
        "    script: 'nmap {target}'\n    title: Good\n    rationale: r\n")
    rules, errors = aa.load_rules(str(tmp_path), force=True)
    assert [r["id"] for r in rules] == ["good"]
    assert len(errors) == 2
    assert any("broken" in e for e in errors) and any("missing_script" in e for e in errors)


def test_missing_rules_dir_reports_an_error(aa, tmp_path):
    """Silence here means no suggestions ever appear, with no explanation."""
    rules, errors = aa.load_rules(str(tmp_path / "nope"), force=True)
    assert rules == []
    assert errors and "no rule files" in errors[0]


def test_edited_yaml_takes_effect_without_restart(aa, tmp_path):
    """Rules are bind-mounted, so an edit must be picked up on the next
    analysis — otherwise operators change a pattern and see no effect."""
    f = tmp_path / "builtin.yaml"
    f.write_text("rules:\n  - id: r\n    pattern: 'AAA'\n    scanner: nmap\n"
                 "    script: 'nmap {target}'\n    title: First\n    rationale: r\n")
    first = aa.suggest_actions("AAA", tool="nmap", target="10.0.0.1", rules_dir=str(tmp_path))
    assert first[0]["title"] == "First"
    os.utime(f, (0, 0))   # force a distinct mtime
    f.write_text("rules:\n  - id: r\n    pattern: 'AAA'\n    scanner: nmap\n"
                 "    script: 'nmap {target}'\n    title: Second\n    rationale: r\n")
    second = aa.suggest_actions("AAA", tool="nmap", target="10.0.0.1", rules_dir=str(tmp_path))
    assert second[0]["title"] == "Second", "edited rule file was not re-read"
