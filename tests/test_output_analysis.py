"""Reading tool output for RESULTS — and not inventing any.

Run on demand:

    pytest tests/test_output_analysis.py -v

WHY THIS EXISTS
---------------
One crackmapexec run against 192.168.1.150 disclosed SMBv1 enabled, SMB signing
disabled, an accepted null session, five shares (one WORLD-WRITABLE), the
hostname and the Samba version. All of that text reached the database — and none
of it was ever interpreted: it sits inside `recon_findings` rows of
`finding_type='tool_table_row'` with `key_values` EMPTY. 94.2% of that table
(98 of 104 rows, from 17 tools) is those generic dumps. Nothing says "SMBv1 is
enabled", so nothing can filter, sort or triage it.

THE HEADER TRAP
---------------
The share table's first two lines are

    Share           Permissions     Remark
    -----           -----------     ------

A line-wise extractor turns those into shares named "Share" and "-----", and a
truncated read of the header turns "Permissions" into a share called "Pe". Junk
assets are indistinguishable from real ones once stored, so these tests pin the
header and separator handling against the REAL captured output.

The fixture below is that output, verbatim.
"""
import os
import sys

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
for path in (REPO, os.path.join(REPO, "app", "rag-api")):
    if path not in sys.path:
        sys.path.insert(0, path)

oa = pytest.importorskip("output_analysis",
                         reason="output_analysis not importable")

# Real captured crackmapexec output, 192.168.1.150, exit 0.
CME_SMB = """[*] First time use detected
[*] Creating home directory structure
[*] Initializing SMB protocol database
SMB                      192.168.1.150   445    METASPLOITABLE   [*] Unix (name:METASPLOITABLE) (domain:localdomain) (signing:False) (SMBv1:True)
SMB                      192.168.1.150   445    METASPLOITABLE   [+] localdomain\\: 
SMB                      192.168.1.150   445    METASPLOITABLE   [+] Enumerated shares
SMB                      192.168.1.150   445    METASPLOITABLE   Share           Permissions     Remark
SMB                      192.168.1.150   445    METASPLOITABLE   -----           -----------     ------
SMB                      192.168.1.150   445    METASPLOITABLE   print$                          Printer Drivers
SMB                      192.168.1.150   445    METASPLOITABLE   tmp             READ,WRITE      oh noes!
SMB                      192.168.1.150   445    METASPLOITABLE   opt                             
SMB                      192.168.1.150   445    METASPLOITABLE   IPC$                            IPC Service (metasploitable server (Samba 3.0.20-Debian))
SMB                      192.168.1.150   445    METASPLOITABLE   ADMIN$                          IPC Service (metasploitable server (Samba 3.0.20-Debian))
"""


# ── the header trap ─────────────────────────────────────────────────────────

@pytest.mark.unit
def test_column_header_never_becomes_a_share():
    """THE guard. 'Share', 'Permissions', 'Remark' and 'Pe' are not shares."""
    names = {s["name"] for s in oa.extract_smb(CME_SMB)["shares"]}
    for bogus in ("Share", "share", "Permissions", "Pe", "Remark", "-----",
                  "-----------"):
        assert bogus not in names, (
            f"the extractor produced a share called {bogus!r} — a header or "
            "separator cell was stored as data")


@pytest.mark.unit
def test_the_separator_row_is_skipped():
    names = [s["name"] for s in oa.extract_smb(CME_SMB)["shares"]]
    assert not any(set(n) <= {"-", "="} for n in names), \
        f"a rule line survived as a share: {names}"


@pytest.mark.unit
def test_exactly_the_five_real_shares_are_found():
    shares = oa.extract_smb(CME_SMB)["shares"]
    assert [s["name"] for s in shares] == \
        ["print$", "tmp", "opt", "IPC$", "ADMIN$"], \
        f"share list wrong: {[s['name'] for s in shares]}"


@pytest.mark.unit
def test_permissions_are_attached_to_the_right_share():
    by = {s["name"]: s for s in oa.extract_smb(CME_SMB)["shares"]}
    assert by["tmp"]["permissions"] == "READ,WRITE"
    assert by["tmp"]["remark"] == "oh noes!"
    # A share with no permissions column must not inherit its neighbour's.
    assert by["opt"]["permissions"] == ""
    assert by["print$"]["permissions"] == ""


# ── the facts ───────────────────────────────────────────────────────────────

@pytest.mark.unit
def test_host_facts_are_extracted():
    f = oa.extract_smb(CME_SMB)["facts"]
    assert f["netbios_name"] == "METASPLOITABLE"
    assert f["domain"] == "localdomain"
    assert f["smbv1"] is True
    assert f["signing"] is False
    assert f["os"] == "Unix"
    assert f["samba_version"] == "Samba 3.0.20-Debian"


@pytest.mark.unit
def test_empty_credentials_are_read_as_a_null_session():
    """`[+] localdomain\\:` — empty user AND empty password. That is the finding."""
    r = oa.extract_smb(CME_SMB)
    assert r["facts"].get("null_session") is True
    assert any(n["id"] == "smb_null_session" for n in r["notable"])


@pytest.mark.unit
def test_a_real_login_is_not_reported_as_a_null_session():
    """The false positive: a successful authenticated login is not anonymous."""
    text = ("SMB   192.168.1.150   445    HOST   [+] localdomain\\msfadmin:msfadmin \n")
    r = oa.extract_smb(text)
    assert r["facts"].get("null_session") is not True
    assert not any(n["id"] == "smb_null_session" for n in r["notable"])
    assert r["facts"]["authenticated_as"][0]["username"] == "msfadmin"


@pytest.mark.unit
def test_the_five_notable_facts_are_all_raised():
    ids = {n["id"] for n in oa.extract_smb(CME_SMB)["notable"]}
    assert ids == {"smb_v1_enabled", "smb_signing_disabled", "smb_null_session",
                   "smb_writable_share", "smb_anonymous_share_enumeration"}, ids


@pytest.mark.unit
def test_writable_share_and_null_session_are_high_severity():
    by = {n["id"]: n for n in oa.extract_smb(CME_SMB)["notable"]}
    assert by["smb_null_session"]["severity"] == "high"
    assert by["smb_writable_share"]["severity"] == "high"
    assert "tmp" in by["smb_writable_share"]["title"]


@pytest.mark.unit
def test_every_notable_fact_quotes_its_evidence():
    """A finding whose evidence cannot be quoted cannot be triaged."""
    for n in oa.extract_smb(CME_SMB)["notable"]:
        assert n.get("evidence"), f"{n['id']} carries no evidence"
        assert n.get("detail"), f"{n['id']} carries no explanation"


@pytest.mark.unit
def test_severities_come_from_the_shared_scale():
    """CLAUDE.md: one severity scale. Values must be ones it recognises."""
    from etl.severity import severity_rank
    for n in oa.extract_smb(CME_SMB)["notable"]:
        assert severity_rank(n["severity"]) > 0, \
            f"{n['id']} uses severity {n['severity']!r}, unknown to etl/severity.py"


# ── verdicts ────────────────────────────────────────────────────────────────

@pytest.mark.unit
def test_results_found_on_the_real_output():
    a = oa.analyse_output("crackmapexec", CME_SMB, 0)
    assert a["verdict"] == "results_found"
    assert a["notable_count"] == 5
    assert a["needs_llm_review"] is False


@pytest.mark.unit
def test_truncated_output_loses_the_share_table():
    """Why analysis must read FULL output.

    The review used to classify from `left(output, 400)`. The share table begins
    past that mark, so a prefix read still saw SMBv1 and signing but silently
    lost the WRITABLE SHARE — the highest-severity fact in the whole run. The
    real captured output carried 12 preamble lines rather than this fixture's
    three, so in production the prefix lost everything.
    """
    assert CME_SMB.index("Enumerated shares") > 400, \
        "fixture no longer places the share table past the old truncation point"
    lost = {n["id"] for n in oa.analyse_output("crackmapexec", CME_SMB, 0)["notable"]} \
        - {n["id"] for n in oa.analyse_output("crackmapexec", CME_SMB[:400], 0)["notable"]}
    assert "smb_writable_share" in lost, \
        "truncation no longer costs the writable share; the point is unproven"
    assert "smb_anonymous_share_enumeration" in lost


@pytest.mark.unit
def test_explicitly_empty_output_is_not_called_unclear():
    a = oa.analyse_output("snmpwalk", "Timeout: No Response from 192.168.1.150", 1)
    assert a["verdict"] == "confirmed_empty"
    assert a["needs_llm_review"] is False


@pytest.mark.unit
def test_a_banner_is_not_a_result():
    a = oa.analyse_output("vncviewer", "TigerVNC viewer v1.15.0\nCopyright (C)", 1)
    assert a["verdict"] == "banner_only"


@pytest.mark.unit
def test_unknown_substantial_output_is_unclear_not_empty():
    """The honest bucket, and the queue an LLM pass should work from.

    Claiming "nothing found" for output nobody wrote an extractor for is how a
    blind spot becomes a clean report.
    """
    a = oa.analyse_output("some-new-tool", "x" * 900, 0)
    assert a["verdict"] == "unclear"
    assert a["needs_llm_review"] is True


@pytest.mark.unit
def test_an_extractor_crash_does_not_lose_the_analysis():
    """A malformed line must not take the whole review down."""
    a = oa.analyse_output("crackmapexec", "SMB \x00\x00 garbage (name:", 0)
    assert "verdict" in a


@pytest.mark.unit
def test_empty_output_is_handled():
    a = oa.analyse_output("nmap", "", 0)
    assert a["verdict"] == "banner_only"
    assert a["notable_count"] == 0


# ── invocation options and return codes ─────────────────────────────────────

pr = pytest.importorskip("post_review_agent",
                         reason="post_review_agent not importable")


@pytest.mark.unit
def test_flags_and_values_are_separated():
    o = pr._parse_options("gobuster dir -u http://h:80 -w /list.txt -t 50 -q")
    assert o["subcommands"] == ["dir"]
    assert o["flags"]["-u"] == "http://h:80"
    assert o["flags"]["-w"] == "/list.txt"
    assert o["flags"]["-q"] is True, "a bare switch should not swallow the next token"


@pytest.mark.unit
def test_a_pipeline_is_attributed_to_the_tool_not_the_feeder():
    """`printf ... | ftp -n host` is an ftp invocation."""
    o = pr._parse_options("printf 'user anon anon\\nls\\nbye\\n' | ftp -n 192.168.1.150 21")
    assert o["argv0"] == "ftp", f"attributed to {o['argv0']}"
    assert o["pipeline"] is True
    assert "-n" in o["flags"]


@pytest.mark.unit
def test_option_signature_ignores_values_but_keeps_names():
    """-p 80 and -p 443 are the same invocation FORM aimed at different things.

    Folding values in would make 379 nmap runs into 27 uncomparable strings.
    """
    a = pr.option_signature("nmap -sV -p 80 192.168.1.150")
    b = pr.option_signature("nmap -sV -p 443 10.0.0.1")
    assert a == b, f"{a!r} != {b!r}"
    assert pr.option_signature("nmap -sV -p 80 h") != pr.option_signature("nmap -sC -p 80 h")


@pytest.mark.unit
def test_unbalanced_quotes_do_not_raise():
    o = pr._parse_options("smbclient -c 'ls unclosed 192.168.1.150")
    assert o["parse_ok"] is False, "a fallback parse must be flagged, not silent"
    assert o["argv0"] == "smbclient"


@pytest.mark.unit
def test_empty_command_is_handled():
    o = pr._parse_options("")
    assert o["argv0"] is None and o["flags"] == {}
    assert pr.option_signature("") == "(no options)"
