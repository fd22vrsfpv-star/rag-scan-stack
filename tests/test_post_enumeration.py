"""Post-exploitation enumeration is a phase, netexec output is parsed, and the
re-run proposer sees what the review sees.

Run on demand:

    pytest tests/test_post_enumeration.py -v

WHY THIS EXISTS
---------------
Three defects that shared a shape: work was done, output was captured, and
nothing read it back.

  * The graph went `exploit_exec -> report`, and every other route went straight
    to `report` too. A run that recovered **ten working credentials** on
    192.168.1.150 and found no exploit candidate stopped there — nothing
    enumerated the access it had just obtained, and no report could say what had
    been skipped.
  * `tool_executions.parsed_results` was NULL for every netexec run because
    nothing computed it. A run wrote 6,816 bytes containing a rendered Python
    traceback, exited 0, and was recorded as an unmeasured success.
  * `propose_reruns` selected a narrower set of executions than the review
    classified, so the report could say `remedy: rerun` about something the
    proposer could not see.

FIXTURES ARE REAL
-----------------
`tests/fixtures/netexec_*.txt` are captured from actual runs against
192.168.1.150 — a successful `--shares` enumeration and a failed SSH connection.
CLAUDE.md: fixtures come from real captured tool output, not invented shapes.

SABOTAGE PROOF
--------------
Point any conditional edge back at `"report"` and
`test_every_route_passes_through_post_enumeration` fails. Make the parser count
traceback lines as output and `test_a_traceback_is_not_a_result` fails. Narrow
the proposer's query and `test_the_proposer_and_the_review_agree` fails.
"""
import ast
import os
import re
import sys

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, REPO)

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
ENGINE = os.path.join(REPO, "autogen_agents", "langgraph_engine.py")


def _read(path):
    if not os.path.exists(path):
        pytest.skip(f"{path} not present")
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def _fixture(name):
    path = os.path.join(FIXTURES, name)
    if not os.path.exists(path):
        pytest.skip(f"fixture {name} not present")
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def _graph_block():
    src = _read(ENGINE)
    start = src.index('g.add_edge(START, "recon")')
    return src[start:src.index('g.add_edge("report", END)')]


# ── The phase exists and nothing bypasses it ───────────────────────────────

def test_the_phase_is_a_node():
    src = _read(ENGINE)
    assert "def post_enumeration(state: PentestState)" in src, "the phase is gone"
    assert 'g.add_node("post_enumeration", post_enumeration)' in src


def test_every_route_passes_through_post_enumeration():
    """A route that goes straight to report is a run that finishes without
    enumerating access it holds — which is the whole defect."""
    block = _graph_block()
    assert '"report": "report"' not in block, (
        "a conditional edge still routes straight to report, so that path "
        "finishes without post-enumerationation enumeration")
    assert block.count('"report": "post_enumeration"') >= 7, block.count('"report": "post_enumeration"')
    assert 'g.add_edge("exploit_exec", "post_enumeration")' in block
    assert 'g.add_edge("post_enumeration", "report")' in block


def test_the_phase_never_proposes_a_mutating_step():
    """45 of the 266 extracted steps write to the target — `useradd backdoor`,
    `>> authorized_keys`. Persistence is an operator's deliberate act, not a
    pipeline default."""
    src = _read(ENGINE)
    fn = src[src.index("def _enumerate_post_access"):]
    fn = fn[:fn.index("\ndef ", 10)] if "\ndef " in fn[10:] else fn
    assert "include_mutating" not in fn, (
        "the phase asks for mutating steps — it must take the default, which "
        "excludes them")
    assert 'access="shell"' in fn


def test_the_phase_says_why_it_did_nothing():
    """"Nothing to enumerate" and "we hold no credential" are different states
    and only one of them is a gap."""
    src = _read(ENGINE)
    fn = src[src.index("def post_enumeration(state: PentestState)"):]
    fn = fn[:fn.index("\ndef _analyse_session_output")]
    assert 'enumerated["reason"]' in fn or "enumerated.get(\"reason\")" in fn


def test_it_only_enumerates_where_a_credential_is_held():
    """A post-access step against a service nobody can reach is noise, and a
    queue that fills with noise stops being read."""
    src = _read(ENGINE)
    fn = src[src.index("def _enumerate_post_access"):]
    assert "credential_findings" in fn
    assert "valid_cred = true" in fn


def test_playbook_steps_are_wrapped_for_remote_execution():
    """A post-access step is written for someone already ON the host.

    `sudo -l` and `cat ~/.ssh/id_rsa` queued verbatim name `sudo` and `cat` as
    the tool, and the listener refuses both — work that looks queued and can
    never run, exactly the defect the credential follow-ups had.
    """
    src = _read(ENGINE)
    assert "def _wrap_remote" in src, "steps are queued unwrapped again"
    fn = src[src.index("def _wrap_remote"):]
    fn = fn[:fn.index("\ndef ", 10)]
    assert "sshpass" in fn and "ssh " in fn
    assert "{password}" in fn, (
        "the secret is substituted into the stored command instead of being "
        "resolved at dispatch")
    assert "settings_for(" in fn, (
        "the derived algorithm options are not applied, so ssh will not "
        "negotiate with a legacy host and every step fails before it runs")


def test_an_unreachable_protocol_queues_nothing():
    """"We cannot reach this service" is a real answer. Queueing something
    unrunnable is not."""
    src = _read(ENGINE)
    fn = src[src.index("def _wrap_remote"):]
    fn = fn[:fn.index("\ndef ", 10)]
    assert 'if proto != "ssh":' in fn and "return None" in fn
    enum = src[src.index("def _enumerate_post_access"):]
    assert "unwrappable" in enum, (
        "a step that could not be wrapped vanishes silently, which looks "
        "identical to a step that was never proposed")


def test_the_credential_is_carried_by_reference():
    src = _read(ENGINE)
    enum = src[src.index("def _enumerate_post_access"):]
    assert '"credential_id": cred_id' in enum, (
        "the recommendation does not say which credential it needs, so the "
        "dispatcher cannot resolve {password}")


def test_the_analysis_backfills_what_nobody_parsed():
    src = _read(ENGINE)
    fn = src[src.index("def _analyse_session_output"):]
    assert "parse_for(" in fn, "the analysis no longer parses unparsed output"
    assert "UPDATE tool_executions SET parsed_results" in fn, (
        "the analysis reads output but does not record what it found, so the "
        "next run re-does the work and the learner still sees NULL")


def test_unparsed_tools_are_named_not_counted():
    """"17 unparsed" is not actionable. The tool names are — each one is a
    parser somebody can write."""
    src = _read(ENGINE)
    fn = src[src.index("def post_enumeration(state: PentestState)"):]
    assert "unparsed_tools" in fn


# ── The netexec parser, against real captured output ───────────────────────

def _parse(text):
    pn = pytest.importorskip("etl.parse_netexec",
                             reason="etl/parse_netexec.py not importable")
    return pn.parse_netexec_output(text)


def test_a_successful_share_enumeration_is_parsed():
    r = _parse(_fixture("netexec_smb_shares.txt"))
    assert r["productive"] is True
    assert r["counts"]["credentials"] == 1
    cred = r["credentials"][0]
    assert (cred["domain"], cred["username"], cred["secret"]) == \
        ("localdomain", "msfadmin", "msfadmin")
    assert r["counts"]["shares"] == 6, [s["share"] for s in r["shares"]]


def test_the_secret_is_masked_in_the_verbatim_line():
    """`raw_line` lands in a jsonb blob the UI dumps without masking.

    The structured `secret` field is stored deliberately — same as
    credential_findings.secret_value, which the UI hides behind a Reveal click.
    A verbatim copy two keys away defeats that, which is exactly what the
    credential audit evidence did before it was fixed.
    """
    r = _parse(_fixture("netexec_smb_shares.txt"))
    cred = r["credentials"][0]
    assert cred["secret"] == "msfadmin", "the structured field should keep it"
    assert "msfadmin:msfadmin" not in cred["raw_line"], cred["raw_line"]
    assert "msfadmin:msf" in cred["raw_line"], (
        f"the username was mangled or the mask is unrecognisable: {cred['raw_line']}")


def test_writable_shares_are_identified():
    """The finding in that output is that two shares are writable. A parser that
    returns six share names and no permission analysis has read the text without
    understanding any of it."""
    r = _parse(_fixture("netexec_smb_shares.txt"))
    writable = sorted(s["share"] for s in r["shares"] if s["writable"])
    assert writable == ["msfadmin", "tmp"], writable
    assert r["counts"]["writable_shares"] == 2


def test_an_empty_column_does_not_shift_the_row():
    """IPC$ and ADMIN$ have no permissions at all. Splitting on whitespace moved
    the Remark into Permissions and reported
    `IPC$ | IPC Service (metasploitable server ...)` as a permission string."""
    r = _parse(_fixture("netexec_smb_shares.txt"))
    ipc = next(s for s in r["shares"] if s["share"] == "IPC$")
    assert ipc.get("permissions") == "", ipc
    assert "IPC Service" in (ipc.get("remark") or ""), ipc
    assert ipc["writable"] is False


def test_host_facts_are_captured():
    r = _parse(_fixture("netexec_smb_shares.txt"))
    facts = r["hosts"][0]["facts"]
    assert facts.get("smbv1") == "True"
    assert facts.get("null_auth") == "True"
    assert facts.get("signing") == "False"


def test_a_traceback_is_not_a_result():
    """The run exited 0 with 6,816 bytes of rendered traceback. Counting those
    lines as output is how a run that achieved nothing reports as productive —
    and could then have activated a learned rule as proof the tool works."""
    r = _parse(_fixture("netexec_ssh_incompatible.txt"))
    assert r["productive"] is False, r["counts"]
    assert r["counts"]["command_output_lines"] == 0, r["command_output"][:3]
    assert r["counts"]["diagnostic_lines"] > 10


def test_command_output_from_dash_x_survives():
    """For a post-enumerationation run the unprefixed lines ARE the entire result."""
    r = _parse("SSH   10.0.0.5   22   10.0.0.5   [+] msfadmin:msfadmin\n"
               "uid=1000(msfadmin) gid=1000(msfadmin) groups=4(adm),112(admin)\n"
               "Linux metasploitable 2.6.24-16-server")
    assert r["counts"]["credentials"] == 1
    assert any("uid=1000" in line for line in r["command_output"]), r["command_output"]
    assert r["productive"] is True


def test_first_run_chatter_is_not_a_result():
    """netexec prints a dozen [*] lines about creating its own directories."""
    r = _parse("[*] First time use detected\n[*] Creating home directory structure\n"
               "[*] Initializing SMB protocol database")
    assert r["productive"] is False
    assert r["noise_lines"] == 3


# ── The registry, and what "unmeasured" means ──────────────────────────────

def test_an_unknown_tool_returns_none_not_empty():
    """"Nobody wrote a parser" and "the parser found nothing" are different
    facts, and the learner acts differently on each."""
    reg = pytest.importorskip("etl.tool_output_parsers")
    assert reg.parse_for("some-tool-nobody-parsed", "lots of output") is None
    assert reg.result_count(None) is None


def test_the_registry_handles_netexec_and_its_aliases():
    reg = pytest.importorskip("etl.tool_output_parsers")
    for name in ("netexec", "nxc", "crackmapexec"):
        parsed = reg.parse_for(name, _fixture("netexec_smb_shares.txt"))
        assert parsed and parsed["counts"]["credentials"] == 1, name


def test_an_unproductive_parse_counts_zero_not_unknown():
    """A parsed run that achieved nothing IS measured, and zero is the answer —
    that is what lets the learner reach for another tool."""
    reg = pytest.importorskip("etl.tool_output_parsers")
    parsed = reg.parse_for("netexec", _fixture("netexec_ssh_incompatible.txt"))
    assert parsed is not None
    assert reg.result_count(parsed) == 0


def test_the_listener_parses_when_the_caller_did_not():
    listener = os.path.join(REPO, "kali_listener", "listener_service.py")
    src = _read(listener)
    assert "_parse_output_for(exec_id, output, error)" in src, (
        "tool output is no longer parsed at the chokepoint, so parsed_results "
        "goes back to NULL for every run")
    assert "if parsed_results is None:" in src


# ── The re-run proposer ────────────────────────────────────────────────────

def test_the_proposer_and_the_review_agree():
    pr_path = os.path.join(REPO, "app", "rag-api", "post_review_agent.py")
    src = _read(pr_path)
    fn = src[src.index("def propose_reruns("):]
    fn = fn[:fn.index("\ndef ", 10)]
    assert "status IN ('failed', 'timeout')" not in fn, (
        "the proposer has its own narrower candidate set again — the review can "
        "report remedy:rerun about an execution nothing will queue")
    assert "left(COALESCE(output, ''), 400)" not in fn, (
        "the proposer classifies a truncated prefix, so it classifies something "
        "different from what the review classified")
    assert "classify_execution(row, catalogue)" in fn


# ── Every command goes through it, and the loop closes ─────────────────────

def test_every_command_goes_through_post_enumeration():
    """Not just a phase at the end of a pipeline. The hook is the single point
    every tool the platform runs passes through."""
    listener = os.path.join(REPO, "kali_listener", "listener_service.py")
    src = _read(listener)
    fn = src[src.index("def db_update_tool_execution("):]
    fn = fn[:fn.index("\ndef ", 10)]
    assert "_post_enumerate(exec_id" in fn, (
        "commands no longer feed post-enumeration, so only a pipeline phase "
        "would analyse anything and every other dispatch path is blind")


def test_the_phase_and_the_hook_share_one_analysis():
    """Two analyses that had to agree would drift, and the one that drifted
    would be the one nobody watched."""
    engine = _read(ENGINE)
    assert "from etl.post_enumeration import analyse" in engine
    listener = _read(os.path.join(REPO, "kali_listener", "listener_service.py"))
    assert "from etl.post_enumeration import analyse" in listener


def test_rules_are_data():
    """The implication is domain knowledge an operator can write down. A dict in
    a module is the thing this replaces."""
    pe = pytest.importorskip("etl.post_enumeration")
    src = _read(os.path.join(REPO, "etl", "post_enumeration.py"))
    tree = ast.parse(src)
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if getattr(t, "id", "").isupper() and isinstance(node.value, ast.List) \
                        and node.value.elts:
                    pytest.fail(f"{t.id} is a module-level rule list — rules "
                                "belong in knowledge/enumeration_rules.yaml")
    assert "yaml" in src and "load_rules" in src


def test_the_real_output_fires_the_rules_it_should():
    """netexec reported `tmp READ,WRITE` and nothing followed. That is the
    defect this exists to fix, so it is tested against the real output."""
    pe = pytest.importorskip("etl.post_enumeration")
    pn = pytest.importorskip("etl.parse_netexec")
    parsed = pn.parse_netexec_output(_fixture("netexec_smb_shares.txt"))
    facts = pe.facts_from(parsed, target="192.168.1.150", service="smb")
    assert len(facts) >= 10, facts

    rules = pe.load_rules()
    assert rules, "no rules loaded"
    fired = {r["id"] for f in facts for r in rules if pe._matches(r, f)}
    assert "writable-share-list" in fired, (
        "a writable share no longer proposes anything — the original defect")
    assert "null-session-enumerate" in fired
    assert "smbv1-only" in fired


def test_the_secret_is_not_written_into_a_proposal():
    """A stored command is shown in the UI, written into reports and exported."""
    pe = pytest.importorskip("etl.post_enumeration")
    fact = {"fact": "share", "target": "10.0.0.1", "share": "tmp", "writable": True,
            "username": "alice", "password": "hunter2"}
    out = pe.render("smbclient //{target}/{share} -U {username}%{password} -c 'ls'",
                    fact)
    assert "hunter2" not in out, out
    assert "{password}" in out and "{username}" in out, out
    assert "//10.0.0.1/tmp" in out


def test_the_fact_recorded_with_an_observation_carries_no_secret():
    src = _read(os.path.join(REPO, "etl", "post_enumeration.py"))
    assert 'k != "password"' in src, (
        "the observation stores the whole fact including the password, in a "
        "jsonb column the UI dumps unmasked")


def test_proposals_pass_the_scope_gate():
    """A known_hosts entry is a lead, not a licence."""
    pe = pytest.importorskip("etl.post_enumeration")
    src = _read(os.path.join(REPO, "etl", "post_enumeration.py"))
    fn = src[src.index("def analyse("):]
    assert "check_dispatch(" in fn and "command=command" in fn
    assert 'scope_source == "unavailable"' in fn, (
        "an unloadable scope no longer stops proposals — fail closed")
    assert 'out["refusals"].append' in fn, "refusals are dropped"


def test_the_loop_carries_forward():
    """Without the write-back every rule stays at "fired N, outcome unknown"
    forever: the loop would propose and never find out."""
    pe = pytest.importorskip("etl.post_enumeration")
    assert hasattr(pe, "record_outcome_for_command")
    listener = _read(os.path.join(REPO, "kali_listener", "listener_service.py"))
    assert "record_outcome_for_command(" in listener


def test_an_unmeasured_outcome_is_not_recorded_as_zero():
    """Third time this conflation has surfaced.

    enum4linux-ng returned 9,525 bytes of real findings and was recorded
    produced=false purely because no parser exists for it — which would have
    suppressed a working rule after five runs.
    """
    listener = _read(os.path.join(REPO, "kali_listener", "listener_service.py"))
    fn = listener[listener.index("def _post_enumerate("):]
    fn = fn[:fn.index("\ndef ", 10)]
    assert "if n is not None:" in fn, (
        "an unmeasured run is written back as 'produced nothing', which "
        "suppresses rules whose tools simply have no parser")


def test_a_rule_is_only_suppressed_after_it_was_actually_tried():
    """A rule nobody ran has not been disproved — it has been ignored."""
    pe = pytest.importorskip("etl.post_enumeration")
    src = _read(os.path.join(REPO, "etl", "post_enumeration.py"))
    fn = src[src.index("def rule_status("):]
    fn = fn[:fn.index("\ndef ", 10)]
    assert "executed >= SUPPRESS_AFTER" in fn, (
        "suppression counts firings rather than outcomes, so a rule nobody "
        "acted on gets killed")


# ── "No parser" is a different error, with a fix ───────────────────────────

def test_a_missing_parser_is_a_distinct_state():
    """"No parser exists for this tool" and "the parser found nothing" are
    different facts. Only the first is actionable — somebody can write one, and
    the output to write it from is already stored."""
    reg = pytest.importorskip("etl.tool_output_parsers")
    st = reg.parse_status("netexec")
    assert st["has_parser"] is True and st["kind"] == "registry"
    gap = reg.parse_status("a-tool-nobody-has-parsed")
    assert gap["has_parser"] is False and gap["kind"] is None


def test_an_extractor_spec_counts_as_a_parser():
    """Authoring a spec through Extract & Learn is the supported way to close a
    parser gap. If a spec did not count, authoring one would change nothing."""
    reg = pytest.importorskip("etl.tool_output_parsers")
    spec_dir = reg.SPEC_DIR if os.path.isdir(reg.SPEC_DIR) else \
        os.path.join(REPO, "knowledge", "extractors")
    if not os.path.isdir(spec_dir):
        pytest.skip("no extractor specs available here")
    reg.SPEC_DIR = spec_dir
    reg._SPEC_CACHE.clear()
    st = reg.parse_status("hydra")
    assert st["has_parser"] is True and st["kind"] == "extractor", st


def test_a_spec_that_matched_nothing_is_still_a_measurement():
    """That is the whole difference from having no parser: the output was read."""
    reg = pytest.importorskip("etl.tool_output_parsers")
    spec_dir = os.path.join(REPO, "knowledge", "extractors")
    if not os.path.isdir(spec_dir):
        pytest.skip("no extractor specs")
    reg.SPEC_DIR = spec_dir
    reg._SPEC_CACHE.clear()
    parsed = reg.parse_for("hydra", "nothing a hydra spec would ever match")
    assert parsed is not None, "a tool WITH a spec must not report as unparsed"
    assert parsed["parser"] == "extractor_spec"
    assert reg.result_count(parsed) == 0, (
        "a spec that read the output and found nothing must count zero, not "
        "unknown — that is what lets a rule be judged")


def test_the_listener_flags_a_missing_parser_loudly():
    """Logged at WARNING, not debug: it is a gap somebody can close."""
    src = _read(os.path.join(REPO, "kali_listener", "listener_service.py"))
    fn = src[src.index("def _post_enumerate("):]
    fn = fn[:fn.index("\ndef ", 10)]
    assert "PARSER MISSING" in fn, "the gap is no longer flagged distinctly"
    assert "logger.warning" in fn
    assert "/parsers/draft" in fn, (
        "the flag does not say how to fix it, which makes it a complaint")


def test_there_is_a_way_to_see_the_gaps_and_close_them():
    api = _read(os.path.join(REPO, "app", "rag-api", "api.py"))
    assert '@app.get("/parsers/missing"' in api, "the gaps are not listable"
    assert '@app.post("/parsers/draft"' in api, "there is no way to create one"
    fn = api[api.index('@app.get("/parsers/missing"'):]
    fn = fn[:fn.index("@app.post")]
    assert "sample_execution" in fn, (
        "a gap with no sample cannot be acted on — a parser written against an "
        "invented format is the defect this repo keeps finding")
    assert "covered_count" in fn, (
        "a list of gaps with no denominator cannot be read as progress or as a "
        "crisis")


def test_drafting_uses_a_real_stored_sample():
    api = _read(os.path.join(REPO, "app", "rag-api", "api.py"))
    fn = api[api.index('@app.post("/parsers/draft"'):]
    fn = fn[:fn.index("\n@app.")]
    assert "FROM tool_executions" in fn, (
        "the draft is not taken from stored output, so it is written against a "
        "guess at the format")
    assert "extractor_learn.distill_artifact" in fn, (
        "a second authoring path would be a second thing to keep correct — it "
        "must use the same distiller as Extract & Learn")
    assert "body.learn" in fn, "there is no preview; the default writes"


def test_the_two_spec_runners_agree():
    """etl/ applies specs and app/rag-api/ authors and applies them. A
    duplicated rule that drifts is worse than one never shared, so they are
    pinned to the same output for the same input."""
    reg = pytest.importorskip("etl.tool_output_parsers")
    spec_dir = os.path.join(REPO, "knowledge", "extractors")
    hydra = os.path.join(spec_dir, "hydra.yaml")
    if not os.path.exists(hydra):
        pytest.skip("hydra spec not present")
    import re as _re
    import yaml as _yaml
    with open(hydra, encoding="utf-8") as fh:
        spec = _yaml.safe_load(fh)
    sample = "0 of 1 target completed, 3 valid passwords found"

    reg.SPEC_DIR = spec_dir
    reg._SPEC_CACHE.clear()
    mine = (reg.parse_for("hydra", sample) or {}).get("extracted") or {}

    theirs = {}
    for name, decl in (spec.get("deterministic") or {}).items():
        pattern = decl.get("pattern") if isinstance(decl, dict) else decl
        if not pattern:
            continue
        m = _re.search(pattern, sample, _re.M | _re.I)
        if m:
            theirs[name] = m.group(1) if m.groups() else m.group(0)
    assert mine == theirs, (mine, theirs)
