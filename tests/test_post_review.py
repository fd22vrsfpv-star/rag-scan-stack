"""Post-execution review: does it classify, or does it just count?

Run on demand:

    pytest tests/test_post_review.py -v

WHY THIS EXISTS
---------------
The defect this module addresses is that a broken invocation, an interrupted
container and a genuinely empty result are INDISTINGUISHABLE in the database —
all three are a status plus an empty `output`. So the thing worth testing is not
"does it produce a number" but "does it put each of the observed cases in the
right bucket, with the right remedy".

Every case below is real captured output from `tool_executions`, quoted. The
counts in the docstrings are what the live table held when these were written:
157 interrupted, 143 timed out, 96 crashed, 76 silent no-ops, 66 with output
discarded on a non-zero exit, 57 aimed at example.com, 41 broken, and 18 that
were simply empty and must NOT be reported as problems.
"""
import os
import re
import subprocess
import sys

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
for path in (REPO, os.path.join(REPO, "app", "rag-api")):
    if path not in sys.path:
        sys.path.insert(0, path)

pr = pytest.importorskip("post_review_agent",
                         reason="post_review_agent not importable")

CATALOGUE = os.path.join(REPO, "knowledge", "service_tools.yaml")


def _row(**kw):
    base = {"tool": "nmap", "command": "nmap -sV 192.168.1.150",
            "target": "192.168.1.150", "port": None, "service": None,
            "status": "completed", "exit_code": 0, "output": "", "error": ""}
    base.update(kw)
    return base


# ── classification: one case per observed failure mode ──────────────────────

@pytest.mark.unit
def test_interrupted_is_a_rerun_not_a_tool_defect():
    """157 rows. The runner restarted; the work was lost, not performed.

    Nothing in the stack ever re-ran these, and they read as "we scanned it".
    """
    v = pr.classify_execution(_row(
        status="failed", exit_code=None,
        error="interrupted: kali-listener restarted while this was running"))
    assert v["category"] == "interrupted"
    assert v["remedy"] == "rerun"
    assert v["actionable"] is True


@pytest.mark.unit
def test_timeout_wins_over_the_crash_heuristic():
    """The deadline killer uses SIGKILL, so EVERY timeout also exits 137.

    Ordering the crash check first reclassified all 143 timeouts as crashes and
    threw away the one fact the runner actually recorded. Sabotage proof: move
    the `status == "timeout"` branch below the crash branch and this fails.
    """
    v = pr.classify_execution(_row(status="timeout", exit_code=137,
                                   output="", error=""))
    assert v["category"] == "timed_out", \
        "a timeout was classified as something else; check the branch order"
    assert v["remedy"] == "rerun_scoped"


@pytest.mark.unit
def test_nmap_assertion_abort_is_a_crash():
    """44 nmap runs died inside nse_nsock.cc — no verdict was ever reached."""
    v = pr.classify_execution(_row(
        status="failed", exit_code=134,
        output="nmap: nse_nsock.cc:381: void callback(nsock_pool, nsock_event, "
               "void*): Assertion `lua_status(thr) == 1' failed."))
    assert v["category"] == "crashed"
    assert v["remedy"] == "rerun"
    assert "134" in v["evidence"]


@pytest.mark.unit
def test_sigkill_without_a_timeout_status_is_a_crash():
    """exit 137 with status='failed' is a kill nobody recorded as a deadline."""
    assert pr.classify_execution(
        _row(status="failed", exit_code=137, output="Killed")
    )["category"] == "crashed"


@pytest.mark.unit
@pytest.mark.parametrize("tool,command,target", [
    ("dig", "dig @192.168.1.150 -p 53 ANY example.com", "192.168.1.150"),
    ("dnsenum", "dnsenum --dnsserver 192.168.1.150 example.com", "192.168.1.150"),
    ("dnsrecon", "dnsrecon -d {domain} -n 192.168.1.150", "192.168.1.150"),
])
def test_stand_in_domain_is_its_own_category(tool, command, target):
    """57 rows queried someone else's domain through the target's resolver.

    Not merely a wrong result — traffic aimed at a third party. It gets its own
    category because the remedy is to fix the command, not to re-run it.
    """
    v = pr.classify_execution(_row(tool=tool, command=command, target=target,
                                   status="failed", exit_code=9,
                                   output="connection timed out"))
    assert v["category"] == "placeholder_target"


@pytest.mark.unit
def test_a_real_example_com_engagement_is_not_flagged():
    """The false positive this category could easily have been.

    An engagement whose scope genuinely IS example.com is not doing anything
    wrong, so the check compares the command against the row's own target
    rather than assuming the domain is a stand-in.
    """
    v = pr.classify_execution(_row(
        tool="dig", command="dig @example.com ANY example.com",
        target="example.com", status="completed", exit_code=0,
        output="a" * 500))
    assert v["category"] != "placeholder_target"


@pytest.mark.unit
def test_interactive_client_with_no_commands_is_a_silent_no_op():
    """78 lftp and 43 ftp runs connected, did nothing, and exited 0.

    Exit 0 and no output is the most dangerous possible signature: it is
    indistinguishable from success against an empty directory.
    """
    v = pr.classify_execution(_row(tool="lftp", target="192.168.1.150",
                                   command="lftp -u anonymous, ftp://192.168.1.150:21",
                                   status="completed", exit_code=0, output=""))
    assert v["category"] == "silent_no_op"
    assert v["actionable"] is True


@pytest.mark.unit
def test_the_fixed_form_of_the_same_command_is_not_flagged():
    """`-e` supplies the work, so this invocation is no longer a no-op."""
    v = pr.classify_execution(_row(
        tool="lftp", command="lftp -u anonymous, -e 'ls -la; bye' ftp://192.168.1.150:21",
        status="completed", exit_code=0, output=""))
    assert v["category"] == "empty_result"


@pytest.mark.unit
def test_output_on_a_nonzero_exit_is_data_that_was_discarded():
    """ssh-audit exits 3 when it FINDS something. 17 rows carried ~9 KB each.

    Treating a non-zero exit as failure threw away real results, so the remedy
    is to ingest, not to re-run.
    """
    v = pr.classify_execution(_row(
        tool="ssh-audit", status="failed", exit_code=3,
        output="# general (gen) banner: SSH-2.0-OpenSSH_4.7p1 " + "x" * 400))
    assert v["category"] == "output_despite_failure"
    assert v["remedy"] == "ingest"


@pytest.mark.unit
def test_a_short_error_line_is_not_mistaken_for_a_result():
    """The floor exists so a one-line error is not reported as lost data."""
    v = pr.classify_execution(_row(tool="ntpdate", status="failed",
                                   exit_code=1, output="ntpdig: no eligible servers"))
    assert v["category"] != "output_despite_failure"


@pytest.mark.unit
def test_an_empty_result_is_not_reported_as_a_problem():
    """THE false-positive guard.

    nuclei and whatweb against live hosts legitimately return nothing. 18 rows.
    A check that flagged these would be wrong, and would bury the 698 that are
    real under noise nobody trusts.
    """
    v = pr.classify_execution(_row(tool="nuclei", status="completed", exit_code=0,
                                   command="nuclei -u http://192.168.1.150:8180 -tags cve",
                                   output=""))
    assert v["category"] == "empty_result"
    assert v["actionable"] is False
    assert v["remedy"] == "none"


@pytest.mark.unit
def test_missing_file_is_a_broken_invocation():
    """onesixtyone's community file, and gobuster's wordlist: 41 rows."""
    for text in ("Error opening community file community.txt",
                 "/usr/share/wordlists/dirb/common.txt does not exist"):
        v = pr.classify_execution(_row(tool="gobuster", status="failed",
                                       exit_code=1, output=text))
        assert v["category"] == "broken_invocation", text
        assert "missing path" in v["evidence"]


@pytest.mark.unit
def test_every_category_declares_a_remedy_and_a_reason():
    """A category with no remedy is a count, which is what this replaces."""
    for name, meta in pr.CATEGORIES.items():
        assert meta["remedy"], name
        assert meta["why"], name
        if meta["remedy"] == "none":
            assert meta["actionable"] is False, \
                f"{name} has no remedy but is reported as actionable"


# ── cause_fixed: the difference between a bug report and a re-run queue ─────

@pytest.mark.unit
def test_cause_fixed_requires_the_catalogue_to_have_changed():
    """A command the catalogue STILL emits is not fixed, so re-running it just
    reproduces the failure."""
    catalogue = {"lftp": ["lftp -u anonymous, ftp://{target}:{port}"]}
    still_broken = pr.classify_execution(
        _row(tool="lftp", command="lftp -u anonymous, ftp://{target}:{port}",
             status="completed", exit_code=0, output=""), catalogue)
    assert still_broken["cause_fixed"] is False
    assert still_broken["remedy"] == "fix_command"

    now_fixed = pr.classify_execution(
        _row(tool="lftp", command="lftp -u anonymous, ftp://192.168.1.150:21",
             status="completed", exit_code=0, output=""),
        {"lftp": ["lftp -u anonymous, -e 'ls -la; bye' ftp://{target}:{port}"]})
    assert now_fixed["cause_fixed"] is True
    assert now_fixed["remedy"] == "rerun", \
        "an already-repaired command should be re-run, not re-reported"


@pytest.mark.unit
def test_no_catalogue_never_claims_a_fix():
    """An unreadable catalogue must not silently mark everything as fixed."""
    v = pr.classify_execution(_row(tool="lftp", status="completed", exit_code=0,
                                   command="lftp ftp://192.168.1.150:21",
                                   output=""), {})
    assert v["cause_fixed"] is False


# ── template substitution ───────────────────────────────────────────────────

@pytest.mark.unit
def test_unfillable_template_is_withheld_not_shipped():
    """`dig ... {domain}` against a bare IP has no domain to enumerate.

    Proposing the template verbatim would dispatch the braces literally and
    recreate the very defect being reported.
    """
    cmd, missing = pr._fill_command("dig @{target} -p {port} ANY {domain}",
                                    {"target": "192.168.1.150", "port": 53})
    assert missing == ["domain"]
    assert "{domain}" in cmd, "an unfilled placeholder must stay visible"


@pytest.mark.unit
def test_fillable_template_is_fully_substituted():
    cmd, missing = pr._fill_command(
        "gobuster dir -u {url} -w /usr/share/wordlists/seclists/x.txt",
        {"target": "192.168.1.150", "port": 80})
    assert missing == []
    assert not re.search(r"\{[a-z_]+\}", cmd), f"placeholders survived: {cmd}"
    assert "192.168.1.150:80" in cmd


@pytest.mark.unit
def test_a_hostname_target_can_fill_domain():
    cmd, missing = pr._fill_command("dnsenum --dnsserver {target} {domain}",
                                    {"target": "internal.example.test"})
    assert missing == []
    assert cmd.count("internal.example.test") == 2


# ── the duplicated catalogue parse, pinned ──────────────────────────────────

@pytest.mark.unit
def test_catalogue_parse_agrees_with_command_checker():
    """CLAUDE.md: duplicated logic needs an agreement test.

    `scripts/check_tool_commands.py` is not on rag-api's path, so the yaml
    adjacency parse exists twice. Both are pinned to the REAL catalogue file
    rather than a re-typed sample, because two copies of a sample agree with
    each other while the deployed one has drifted.
    """
    if not os.path.exists(CATALOGUE):
        pytest.skip("service_tools.yaml not present")
    sys.path.insert(0, os.path.join(REPO, "scripts"))
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "check_tool_commands", os.path.join(REPO, "scripts", "check_tool_commands.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    theirs = {(c["tool"], c["command"]) for c in mod.extract_commands(CATALOGUE)}
    mine = {(t, c) for t, cmds in pr._catalogue_commands(CATALOGUE).items()
            for c in cmds}
    assert mine == theirs, (
        "the two catalogue parsers disagree:\n"
        f"  only in post_review_agent: {sorted(mine - theirs)[:5]}\n"
        f"  only in check_tool_commands: {sorted(theirs - mine)[:5]}")
    assert len(mine) > 50, f"only {len(mine)} commands parsed — parser is broken"


@pytest.mark.unit
def test_unreadable_catalogue_returns_empty_not_an_exception():
    assert pr._catalogue_commands("/nonexistent/service_tools.yaml") == {}


# ── executed against the live stack ─────────────────────────────────────────

def _curl(method, path, timeout=180):
    """Call rag-api from inside its own container.

    HTTPS and an `x-api-key` header are both required — plain HTTP on 8000
    returns "empty reply from server" while the access log still shows a 200,
    which reads as a broken endpoint rather than a wrong scheme. The key is read
    from the container's own environment so no secret is passed on a command
    line or duplicated into the test.
    """
    cmd = (f'curl -sk --max-time {timeout} -H "x-api-key: $API_KEY" '
           f'-X {method} "https://127.0.0.1:8000{path}"')
    try:
        out = subprocess.run(["docker", "exec", "rag-api", "sh", "-c", cmd],
                             capture_output=True, text=True, timeout=timeout + 30)
    except (OSError, subprocess.SubprocessError):
        return None
    return out.stdout if out.returncode == 0 else None


@pytest.fixture(scope="module")
def live():
    body = _curl("GET", "/agent/post-review/reports?limit=1", timeout=30)
    if not body or "reports" not in body:
        pytest.skip("rag-api not reachable or post-review endpoints not deployed")
    return True


def test_post_review_endpoint_executes_and_classifies(live):
    """CLAUDE.md: every endpoint needs a test that EXECUTES it."""
    import json
    body = _curl("POST", "/agent/post-review")
    assert body, "POST /agent/post-review returned nothing"
    data = json.loads(body)
    assert data.get("ok") is True, data
    s = data["summary"]
    assert s["executions_reviewed"] > 0, "reviewed nothing"
    cats = {g["category"] for g in data["executions"]["groups"]}
    assert len(cats) > 1, f"everything landed in one bucket: {cats}"
    # The whole point: correct-but-empty is separated from actionable.
    assert "actionable" in s and "correct_but_empty" in s


def test_report_is_stored_and_readable(live):
    import json
    data = json.loads(_curl("POST", "/agent/post-review"))
    rid = data["report_id"]
    got = json.loads(_curl("GET", f"/agent/post-review/reports/{rid}", timeout=60))
    assert got["report"]["status"] == "completed"
    assert got["report"]["report"]["summary"]["executions_reviewed"] == \
        data["summary"]["executions_reviewed"]


def test_unknown_report_id_is_404(live):
    body = _curl("GET",
                 "/agent/post-review/reports/00000000-0000-0000-0000-000000000000",
                 timeout=60)
    assert body and "not found" in body.lower(), body


def test_proposals_are_scope_gated(live):
    """An out-of-scope re-run must be REFUSED and the refusal reported.

    Override flags overrule suppression, never authorization — and a proposal
    naming a third-party host is an authorization problem whether or not it
    ever executes.
    """
    import json
    data = json.loads(_curl("POST", "/agent/post-review"))
    reruns = data["reruns"]
    assert reruns.get("scope_source") != "unavailable", \
        "the scope gate could not load; proposals must fail closed"
    for p in reruns["proposals"]:
        assert not re.search(r"\{[a-z_]+\}", p["script"] or ""), \
            f"a proposal shipped an unsubstituted placeholder: {p['script']}"
    # Refusals are recorded, not silently dropped.
    assert "refusals" in reruns


def test_dry_run_queues_nothing(live):
    import json
    data = json.loads(_curl("POST", "/agent/post-review"))
    assert data["summary"]["reruns_queued"] == 0, \
        "the default run inserted recommendations; it must be dry by default"
    assert data["reruns"]["dry_run"] is True


def test_queue_reruns_inserts_pending_rows_and_dispatches_nothing(live):
    """The MUTATING leg. Dry-run coverage alone missed a real bug here.

    `RETURNING (xmax = 0) AS inserted` comes back as a dict under a
    RealDictCursor, and indexing it `[0]` raised KeyError(0) — surfacing as
    "post review failed: 0". Only this leg reaches that line, so every dry-run
    test passed while queueing was completely broken.

    Safe to run repeatedly: the generated `fingerprint` column makes the insert
    idempotent, so a second run adds nothing.
    """
    import json
    first = json.loads(_curl("POST", "/agent/post-review?queue_reruns=true"))
    assert first.get("ok") is True, first
    again = json.loads(_curl("POST", "/agent/post-review?queue_reruns=true"))
    assert again["summary"]["reruns_queued"] == 0, (
        "re-running queued MORE rows — the fingerprint dedup is not holding")
    assert again["summary"]["reruns_proposed"] > 0, "nothing was proposed at all"

    out = subprocess.run(
        ["docker", "exec", "rag-postgres", "psql", "-U", "app", "-d", "scans", "-tAc",
         "SELECT count(*), count(*) FILTER (WHERE status <> 'pending'), "
         "count(*) FILTER (WHERE executed_at IS NOT NULL) "
         "FROM scan_recommendations WHERE source = 'post_review'"],
        capture_output=True, text=True, timeout=60)
    if out.returncode != 0:
        pytest.skip("rag-postgres not reachable")
    total, not_pending, executed = [int(x) for x in out.stdout.strip().split("|")]
    assert total > 0, "queue_reruns=true stored nothing"
    # NOT asserted: that these rows stay pending forever. They do not, and
    # believing otherwise was a real error in this feature's first version.
    # dashboard/bff/services/recon_agent.py:117 selects `WHERE status='pending'`
    # with NO filter on `source`, so the recon agent dispatches post_review
    # proposals like any other in-scope recommendation. What the AGENT must
    # never do is create a row already dispatched.
    assert executed <= not_pending, (
        "a post_review row has executed_at set but a pending status — the agent "
        "wrote a dispatched row instead of a proposal")


def test_queued_proposals_carry_their_evidence(live):
    """A proposal with no reason is indistinguishable from a guess."""
    out = subprocess.run(
        ["docker", "exec", "rag-postgres", "psql", "-U", "app", "-d", "scans", "-tAc",
         "SELECT count(*) FROM scan_recommendations WHERE source='post_review' "
         "AND (extra->>'post_review_category' IS NULL OR extra->>'evidence' IS NULL "
         "     OR extra->>'prior_execution_id' IS NULL)"],
        capture_output=True, text=True, timeout=60)
    if out.returncode != 0:
        pytest.skip("rag-postgres not reachable")
    assert int(out.stdout.strip()) == 0, \
        "a queued proposal is missing its category, evidence or prior execution id"


# ── the ingest remedy: extracted facts become real findings ─────────────────

def _psql(sql):
    try:
        out = subprocess.run(
            ["docker", "exec", "rag-postgres", "psql", "-U", "app", "-d", "scans",
             "-tAc", sql], capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return None
    return out.stdout.strip() if out.returncode == 0 else None


def test_ingest_facts_endpoint_is_dry_by_default(live):
    """It writes findings that appear in reports and exports, so the default
    must not write."""
    import json
    body = _curl("POST", "/agent/post-review/ingest-facts")
    assert body, "endpoint returned nothing"
    d = json.loads(body)
    assert d.get("ok") is True, d
    assert d["dry_run"] is True
    assert d["inserted"] == 0, "a dry run inserted rows"
    assert d["facts_found"] > 0, "no facts extracted at all"


def test_the_facts_reached_recon_findings_with_a_real_type(live):
    """94.2% of recon_findings was `tool_output` / `tool_table_row` with
    key_values EMPTY — text stored, meaning never recorded. Nothing said
    "SMBv1 is enabled", so nothing could filter or sort it."""
    got = _psql("SELECT count(*) FROM recon_findings WHERE finding_type "
                "NOT IN ('tool_output','tool_table_row','tool_finding')")
    if got is None:
        pytest.skip("rag-postgres not reachable")
    assert int(got) >= 12, (
        f"only {got} interpreted findings — the ingest pass has not run, or "
        "regressed back to generic dumps")


def test_the_high_severity_smb_facts_are_stored(live):
    """The motivating case: a null session and a world-writable share."""
    for ftype in ("smb_null_session", "smb_writable_share"):
        got = _psql("SELECT count(*) FROM recon_findings WHERE finding_type = "
                    f"'{ftype}' AND severity = 'high'")
        if got is None:
            pytest.skip("rag-postgres not reachable")
        assert int(got) > 0, f"{ftype} is not stored as a high-severity finding"


def test_one_condition_is_one_finding_type_across_tools(live):
    """crackmapexec, enum4linux and enum4linux-ng all find the same null
    session. That must be ONE finding_type with three sources, or a severity
    filter counts one problem three times."""
    got = _psql("SELECT count(DISTINCT source) FROM recon_findings "
                "WHERE finding_type = 'smb_null_session'")
    if got is None:
        pytest.skip("rag-postgres not reachable")
    assert int(got) >= 2, (
        "smb_null_session has one source; the per-tool ids have come back")


def test_ingest_is_idempotent(live):
    """`trg_recon_findings_dedup` is BEFORE INSERT and RETURNs NULL on a
    duplicate, so an INSERT reports zero rows and ON CONFLICT is unreachable.
    Novelty must therefore be checked BEFORE inserting."""
    import json
    before = _psql("SELECT count(*) FROM recon_findings")
    if before is None:
        pytest.skip("rag-postgres not reachable")
    d = json.loads(_curl("POST", "/agent/post-review/ingest-facts?dry_run=false"))
    after = _psql("SELECT count(*) FROM recon_findings")
    assert d["inserted"] == 0, f"re-running inserted {d['inserted']} duplicate rows"
    assert int(after) == int(before), \
        f"recon_findings grew {before} -> {after} on a repeat run"
    assert d["already_stored"] > 0, "nothing was recognised as already stored"


def test_the_payload_carries_no_volatile_field(live):
    """`data` is part of the dedup fingerprint
    (md5('recon|'||source||'|'||finding_type||'|'||target||'|'||data::text)),
    so an execution id or a per-run counter inside it forks the fingerprint on
    every pass and the index stores both copies."""
    got = _psql("SELECT count(*) FROM recon_findings "
                "WHERE finding_type LIKE 'smb_%' AND ("
                " data ? 'execution_id' OR data ? 'execution_ids' "
                " OR data ? 'seen_in' OR data ? 'started_at')")
    if got is None:
        pytest.skip("rag-postgres not reachable")
    assert int(got) == 0, \
        "a volatile key is inside the fingerprinted payload"


def test_no_bare_username_was_written_to_the_vault(live):
    """A deliberate decision, not an omission.

    credential_vault.credential_type has no username-only value and status no
    "unverified", so 35 bare names would have to be stored as an `active`
    credential of type `other` — which is not what they are. The names already
    reach the generated wordlists via target_wordlists.harvest_usernames.
    """
    got = _psql("SELECT count(*) FROM credential_vault "
                "WHERE credential_type = 'other' AND "
                "(credential_value IS NULL OR credential_value = '')")
    if got is None:
        pytest.skip("rag-postgres not reachable")
    assert int(got) == 0, (
        f"{got} username-only rows in credential_vault — these are spray "
        "candidates, not credentials")


def test_the_summary_reports_storage_honestly(live):
    """`high_or_worse_unstored` read 5 after all five had been ingested, because
    it was derived from output alone and never asked the database. A metric
    named "unstored" that cannot tell is worse than no metric."""
    import json
    d = json.loads(_curl("POST", "/agent/post-review"))
    s = d["summary"]
    assert s["notable_facts_stored"] + s["notable_facts_unstored"] \
        == s["notable_facts_in_output"], "the storage split does not add up"
    for n in d["notable_in_output"]:
        assert "stored" in n, "a fact carries no storage state"
    unstored_high = [n for n in d["notable_in_output"]
                     if not n["stored"] and n["severity"] in ("critical", "high")]
    assert len(unstored_high) == s["high_or_worse_unstored"], \
        "the headline count disagrees with the list it summarises"
