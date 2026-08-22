"""Fingerprint stability, and agreement between the Python and SQL copies.

Run on demand:

    pytest tests/test_fingerprint.py -v

WHY THIS EXISTS
---------------
CLAUDE.md requires unit tests for fingerprinting, and `etl/fingerprint.py` had
none — the module every dedup path depends on was the one with no coverage.

The more important half is the AGREEMENT tests. The hash is implemented TWICE:

  * `etl/fingerprint.py`      — Python, called by the parsers
  * `vulns_dedup()` /
    `web_findings_dedup()`   — PL/pgSQL, applied by trigger when a writer
                               inserts with fingerprint NULL (about 19 insert
                               sites do exactly that)

If those two drift, a row written by a parser and a row written by a raw INSERT
of the SAME finding get different fingerprints, stop recognising each other,
and the unique index happily stores both. The duplication this whole effort
removed comes straight back, silently.

CLAUDE.md already names this pattern for the scope gate: "When gate logic must
be duplicated, add an agreement test pinning both implementations to a shared
case table." Same reasoning, same fix — the case table below is shared, and the
SQL side is exercised through the REAL trigger (insert with fingerprint NULL,
read back what the trigger computed) rather than through a re-typed copy of the
expression, which would only test the copy.

The DB-backed tests skip cleanly when no database is reachable.
"""
import os
import subprocess
import sys
import uuid

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
if REPO not in sys.path:
    sys.path.insert(0, REPO)

fingerprint = pytest.importorskip(
    "etl.fingerprint", reason="etl.fingerprint not importable from this checkout"
)

vuln_fingerprint = fingerprint.vuln_fingerprint
web_fingerprint = fingerprint.web_fingerprint
recon_fingerprint = fingerprint.recon_fingerprint


# ── shared case table, used by BOTH the unit and agreement tests ─────────────
#
# Fixed, unusual values: a fingerprint that already exists in the database makes
# the trigger skip the insert, and then the agreement test has no row to read
# back. 203.0.113.x is TEST-NET-3 (RFC 5737) and never a real scan target.
VULN_CASES = [
    # (label, ip, port, script, cves)
    ("script only",        "203.0.113.41", 8443, "nmap:smb-vuln-ms17-010", None),
    ("cve wins over script", "203.0.113.42", 445, "nmap:whatever", ["CVE-2017-0144"]),
    ("no port",            "203.0.113.43", None, "nuclei:tp-link-default", None),
    ("mixed-case cve",     "203.0.113.44", 80,   "x", ["cve-2021-44228"]),
    ("script needs trim",  "203.0.113.45", 22,   "  NMAP:SSH-Weak  ", None),
    ("empty script",       "203.0.113.46", 3306, "", None),
]

WEB_CASES = [
    # (label, url, source, name, issue_type)
    ("plain",             "https://example.test/login", "zap", "XSS", "reflected-xss"),
    ("trailing slash",    "https://example.test/admin/", "zap", "Info Leak", "info"),
    ("uppercase url",     "HTTPS://EXAMPLE.TEST/Path",   "nuclei", "Open Redirect", "redirect"),
    ("no issue_type",     "https://example.test/x",      "burp", "Missing Header", None),
    ("padded name",       "https://example.test/y",      "zap", "  Padded  ", "hdr"),
]


# ── determinism and sensitivity (no database needed) ─────────────────────────

@pytest.mark.unit
@pytest.mark.parametrize("label,ip,port,script,cves", VULN_CASES)
def test_vuln_fingerprint_is_stable(label, ip, port, script, cves):
    """Same input, same hash — twice in a row and across call order."""
    a = vuln_fingerprint(ip, port, script, cves)
    b = vuln_fingerprint(ip, port, script, cves)
    assert a == b, label
    assert len(a) == 32 and all(c in "0123456789abcdef" for c in a), a


@pytest.mark.unit
@pytest.mark.parametrize("label,url,source,name,issue", WEB_CASES)
def test_web_fingerprint_is_stable(label, url, source, name, issue):
    assert web_fingerprint(url, source, name, issue) == \
           web_fingerprint(url, source, name, issue), label


@pytest.mark.unit
def test_vuln_port_changes_the_fingerprint():
    """Same CVE on a different port is a different finding."""
    a = vuln_fingerprint("10.0.0.1", 80, "s", ["CVE-2021-1"])
    b = vuln_fingerprint("10.0.0.1", 443, "s", ["CVE-2021-1"])
    assert a != b


@pytest.mark.unit
def test_vuln_ip_changes_the_fingerprint():
    assert vuln_fingerprint("10.0.0.1", 80, "s") != vuln_fingerprint("10.0.0.2", 80, "s")


@pytest.mark.unit
def test_vuln_cve_takes_precedence_over_script():
    """Two tools reporting one CVE on one host:port must collapse to one row.

    That is the entire point of the CVE branch — nmap's script name and nuclei's
    template id differ, so a script-based hash would keep both.
    """
    nmap = vuln_fingerprint("10.0.0.1", 445, "nmap:smb-vuln-ms17-010", ["CVE-2017-0144"])
    nuclei = vuln_fingerprint("10.0.0.1", 445, "nuclei:ms17-010", ["CVE-2017-0144"])
    assert nmap == nuclei


@pytest.mark.unit
def test_vuln_cve_case_and_order_are_normalized():
    assert vuln_fingerprint("10.0.0.1", 1, "s", ["cve-2021-44228"]) == \
           vuln_fingerprint("10.0.0.1", 1, "s", ["CVE-2021-44228"])
    # The FIRST cve-shaped entry wins; non-CVE junk ahead of it is skipped.
    assert vuln_fingerprint("10.0.0.1", 1, "s", ["not-a-cve", "CVE-2021-44228"]) == \
           vuln_fingerprint("10.0.0.1", 1, "s", ["CVE-2021-44228"])


@pytest.mark.unit
def test_different_cves_are_different_vulns():
    """Two distinct CVEs on one host:port are two findings, not one."""
    a = vuln_fingerprint(ip="10.0.0.1", port=80, script="s", cves=["CVE-2011-2523"])
    b = vuln_fingerprint(ip="10.0.0.1", port=80, script="s", cves=["CVE-2026-4480"])
    assert a != b


@pytest.mark.unit
def test_empty_string_and_none_are_equivalent():
    """A parser emitting "" and another emitting None describe the same absence.

    Hashing them differently would create one duplicate row per parser.
    """
    assert web_fingerprint("http://h/a", "zap", "XSS", None) == \
           web_fingerprint("http://h/a", "zap", "XSS", "")
    assert vuln_fingerprint(None, 80, "s") == vuln_fingerprint("", 80, "s")
    assert vuln_fingerprint("10.0.0.1", 80, None) == vuln_fingerprint("10.0.0.1", 80, "")


@pytest.mark.unit
def test_null_fields_stay_stable_across_calls():
    """All-null input must be deterministic, not merely non-raising."""
    assert vuln_fingerprint(None, None, None, None) == \
           vuln_fingerprint(None, None, None, None)
    assert web_fingerprint(None, None, None, None) == \
           web_fingerprint(None, None, None, None)
    assert recon_fingerprint(None, None, None, None) == \
           recon_fingerprint(None, None, None, None)


@pytest.mark.unit
def test_vuln_script_is_trimmed_and_lowercased():
    assert vuln_fingerprint("10.0.0.1", 22, "  NMAP:SSH-Weak  ") == \
           vuln_fingerprint("10.0.0.1", 22, "nmap:ssh-weak")


@pytest.mark.unit
def test_vuln_missing_port_is_zero_not_null():
    """None and 0 must agree, or a port-less finding forks into two rows."""
    assert vuln_fingerprint("10.0.0.1", None, "s") == vuln_fingerprint("10.0.0.1", 0, "s")


@pytest.mark.unit
def test_vuln_handles_all_nulls():
    assert len(vuln_fingerprint(None, None, None, None)) == 32


@pytest.mark.unit
def test_web_source_is_excluded():
    """Documented intent: the same finding from ZAP and Nuclei must dedupe."""
    assert web_fingerprint("https://x.test/a", "zap", "XSS", "xss") == \
           web_fingerprint("https://x.test/a", "nuclei", "XSS", "xss")


@pytest.mark.unit
def test_web_url_normalization():
    base = web_fingerprint("https://x.test/a", "zap", "n", "t")
    assert web_fingerprint("https://x.test/a/", "zap", "n", "t") == base, "trailing slash"
    assert web_fingerprint("HTTPS://X.TEST/A", "zap", "n", "t") == base, "case"
    assert web_fingerprint("  https://x.test/a  ", "zap", "n", "t") == base, "padding"


@pytest.mark.unit
def test_web_distinct_urls_do_not_collide():
    assert web_fingerprint("https://x.test/a", "zap", "n", "t") != \
           web_fingerprint("https://x.test/b", "zap", "n", "t")


@pytest.mark.unit
def test_recon_is_source_specific():
    """A subfinder subdomain and a crtsh cert for one target are not the same."""
    assert recon_fingerprint("subfinder", "subdomain", "x.test", "a.x.test") != \
           recon_fingerprint("crtsh", "subdomain", "x.test", "a.x.test")


@pytest.mark.unit
def test_recon_data_key_discriminates():
    assert recon_fingerprint("subfinder", "subdomain", "x.test", "a.x.test") != \
           recon_fingerprint("subfinder", "subdomain", "x.test", "b.x.test")


@pytest.mark.unit
def test_recon_normalizes_case_and_padding():
    assert recon_fingerprint(" SubFinder ", "SubDomain", "X.Test", "A.X.Test") == \
           recon_fingerprint("subfinder", "subdomain", "x.test", "a.x.test")


# ── agreement between the Python module and the SQL triggers ─────────────────

_LAST_PSQL_ERROR = {"msg": ""}


def _psql(sql):
    """Run SQL, returning stdout or None.

    On failure the stderr is stashed rather than discarded — a helper that
    returns a bare None turns every SQL mistake into "assert None", which says
    nothing about what actually broke.
    """
    try:
        out = subprocess.run(
            ["docker", "exec", "rag-postgres", "psql", "-U", "app", "-d", "scans",
             "-v", "ON_ERROR_STOP=1", "-tAc", sql],
            capture_output=True, text=True, timeout=60,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        _LAST_PSQL_ERROR["msg"] = f"{type(exc).__name__}: {exc}"
        return None
    if out.returncode != 0:
        _LAST_PSQL_ERROR["msg"] = (out.stderr or out.stdout).strip()[:500]
        return None
    _LAST_PSQL_ERROR["msg"] = ""
    return out.stdout.strip()


def _last_row(out):
    """The last non-empty line that is not a psql status tag.

    With -c, psql echoes BEGIN / INSERT 0 1 / ROLLBACK alongside the result, so
    splitlines()[-1] is "ROLLBACK", not the value being asserted on.
    """
    tags = ("BEGIN", "COMMIT", "ROLLBACK", "DO", "SET")
    rows = [
        l.strip() for l in (out or "").splitlines()
        if l.strip()
        and not l.strip().startswith(("INSERT ", "UPDATE ", "DELETE ", "SELECT "))
        and l.strip() not in tags
    ]
    return rows[-1] if rows else ""


@pytest.fixture(scope="module")
def db():
    if _psql("SELECT 1") != "1":
        pytest.skip("no reachable rag-postgres; SQL-side agreement cannot be checked")
    return True


def test_dedup_triggers_are_installed(db):
    """Without these, ~19 insert sites that supply no fingerprint write NULL."""
    got = _psql(
        "SELECT count(*) FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid "
        "WHERE NOT t.tgisinternal AND t.tgname IN "
        "('trg_vulns_dedup','trg_web_findings_dedup')"
    )
    assert got == "2", f"expected both dedup triggers, found {got}"


@pytest.mark.parametrize("label,ip,port,script,cves", VULN_CASES)
def test_vuln_trigger_agrees_with_python(db, label, ip, port, script, cves):
    """Insert with fingerprint NULL and compare what the TRIGGER computed.

    Exercising the real trigger — rather than re-typing its md5 expression here —
    is the point: a re-typed copy would agree with itself while the deployed
    function had drifted.
    """
    expected = vuln_fingerprint(ip, port, script, cves)
    cve_sql = (
        "ARRAY[" + ",".join("'%s'" % c.replace("'", "''") for c in cves) + "]::text[]"
        if cves else "NULL::text[]"
    )
    script_sql = "NULL" if script is None else "'%s'" % script.replace("'", "''")
    port_meta = "'{}'::jsonb" if port is None else "'{\"port\": %d}'::jsonb" % port
    marker = uuid.uuid4()

    sql = f"""
        BEGIN;
        INSERT INTO public.assets (id, ip, hostname)
        VALUES ('{marker}'::uuid, '{ip}'::inet, NULL)
        ON CONFLICT (ip, COALESCE(hostname, '')) DO NOTHING;
        INSERT INTO public.vulns (asset_id, script, cve, severity, title, output, metadata)
        SELECT a.id, {script_sql}, {cve_sql}, 'info', 'agreement probe', '', {port_meta}
          FROM public.assets a WHERE a.ip = '{ip}'::inet LIMIT 1;
        SELECT fingerprint FROM public.vulns WHERE title = 'agreement probe';
        ROLLBACK;
    """
    got = _psql(sql)
    assert got, f"{label}: query failed -> {_LAST_PSQL_ERROR['msg']}"
    assert _last_row(got) == expected, (
        f"{label}: SQL trigger and etl/fingerprint.py disagree.\n"
        f"  python:  {expected}\n  trigger: {_last_row(got)}\n"
        "Rows written by a parser and by a raw INSERT would stop deduplicating."
    )


@pytest.mark.parametrize("label,url,source,name,issue", WEB_CASES)
def test_web_trigger_agrees_with_python(db, label, url, source, name, issue):
    expected = web_fingerprint(url, source, name, issue)
    issue_sql = "NULL" if issue is None else "'%s'" % issue.replace("'", "''")
    sql = f"""
        BEGIN;
        INSERT INTO public.web_findings (url, source, issue_type, name, severity)
        VALUES ('{url.replace("'", "''")}', '{source}', {issue_sql},
                '{name.replace("'", "''")}', 'info');
        SELECT fingerprint FROM public.web_findings
         WHERE url = '{url.replace("'", "''")}' ORDER BY created_at DESC LIMIT 1;
        ROLLBACK;
    """
    got = _psql(sql)
    assert got, f"{label}: query failed -> {_LAST_PSQL_ERROR['msg']}"
    assert _last_row(got) == expected, (
        f"{label}: SQL trigger and etl/fingerprint.py disagree.\n"
        f"  python:  {expected}\n  trigger: {_last_row(got)}"
    )


# ── the invariants the triggers exist to hold ────────────────────────────────

def test_unique_fingerprint_indexes_exist(db):
    for idx in ("uq_vulns_fingerprint", "uq_web_findings_fingerprint"):
        assert _psql(
            f"SELECT count(*) FROM pg_indexes WHERE indexname = '{idx}' "
            "AND schemaname = 'public'"
        ) == "1", f"{idx} missing — duplicates can be stored again"


def test_no_null_fingerprints(db):
    """A unique index permits unlimited NULLs, so a NULL is an unconstrained row."""
    for table in ("vulns", "web_findings", "recon_findings"):
        assert _psql(
            f"SELECT count(*) FROM public.{table} WHERE fingerprint IS NULL"
        ) == "0", f"{table} has NULL fingerprints; they bypass the unique index"


def test_tables_carry_no_fingerprint_duplicates(db):
    for table in ("vulns", "web_findings", "recon_findings"):
        total = _psql(f"SELECT count(*) FROM public.{table}")
        distinct = _psql(f"SELECT count(DISTINCT fingerprint) FROM public.{table}")
        assert total == distinct, (
            f"{table}: {total} rows but {distinct} distinct fingerprints"
        )


def test_vulns_has_first_and_last_seen(db):
    """The delta view needs a scan-observation timestamp.

    updated_at cannot serve: trg_vulns_updated_at touches it on ANY write, so an
    operator editing tester_notes looks identical to a scan re-finding the vuln.
    """
    got = _psql(
        "SELECT count(*) FROM information_schema.columns "
        "WHERE table_name = 'vulns' AND column_name IN ('first_seen','last_seen')"
    )
    assert got == "2", "vulns is missing first_seen/last_seen"
    assert _psql("SELECT count(*) FROM public.vulns WHERE last_seen IS NULL") == "0"


@pytest.mark.parametrize("table,cols,vals,where", [
    # vulns.script and vulns.output are both NOT NULL.
    ("vulns", "severity, title, script, output, metadata",
     "'info', 'reinsert probe', 'probe:reinsert', '', '{}'::jsonb",
     "title = 'reinsert probe'"),
    # web_findings has no `title` column, so the probe is keyed on `name`.
    ("web_findings", "url, source, issue_type, name, severity",
     "'https://reinsert.test/p', 'zap', 'probe', 'reinsert probe', 'info'",
     "name = 'reinsert probe'"),
])
def test_reinsert_bumps_last_seen_without_adding_a_row(db, table, cols, vals, where):
    """Re-seeing a finding is new information about WHEN, not a new finding."""
    sql = f"""
        BEGIN;
        INSERT INTO public.{table} ({cols}) VALUES ({vals});
        UPDATE public.{table} SET last_seen = now() - interval '10 days'
         WHERE {where};
        SELECT count(*) FROM public.{table};
        INSERT INTO public.{table} ({cols}) VALUES ({vals});
        SELECT count(*) || ',' || (
            SELECT count(*) FROM public.{table}
             WHERE last_seen > now() - interval '1 minute'
        ) FROM public.{table};
        ROLLBACK;
    """
    out = _psql(sql)
    assert out, f"{table}: probe query failed -> {_LAST_PSQL_ERROR['msg']}"
    rows = [l.strip() for l in out.splitlines()
            if l.strip() and (l.strip().isdigit() or "," in l.strip())]
    before = int(rows[-2])
    after, bumped = (int(x) for x in rows[-1].split(","))
    assert after == before, f"{table}: re-insert created a row ({before} -> {after})"
    assert bumped >= 1, f"{table}: re-insert did not bump last_seen"
