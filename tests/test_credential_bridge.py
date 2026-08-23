"""The bridge from verified credential findings to the vault + identity directory.

Run on demand:

    pytest tests/test_credential_bridge.py -v

WHY THIS EXISTS
---------------
Brutus verified seven credentials on 192.168.1.150 and stored them in
`credential_findings`. The Users page reads `identities` and badges a row when a
matching `credential_vault` entry exists — so did every other vault consumer.
Nothing joined the two tables, and the operator's report was simply "under users
the found credentials do not show anything".

Two things here are only checkable by execution:

  * the GRAIN. `credential_findings` is per service, `credential_vault` has no
    service column. One vault row per finding would store three
    indistinguishable rows for one `msfadmin` account.
  * the JOIN. `has_credential` matches on `username` OR `username@domain`, so
    the identifier the bridge writes has to line up with the domain it writes.
    Getting either half wrong leaves the badge dark with no error anywhere.

And one is only checkable statically: `credential_findings.secret_type` and
`credential_vault.credential_type` are two different CHECK-constrained
vocabularies. A value in the first that is not in the second aborts the insert,
which is how a verified credential gets lost to a spelling difference.
"""
import json
import os
import subprocess
import sys

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
if REPO not in sys.path:
    sys.path.insert(0, REPO)

bridge = pytest.importorskip(
    "etl.credential_bridge", reason="etl.credential_bridge not importable")

# Documentation-range addresses (RFC 5737 TEST-NET-3) so the probe rows can never
# collide with a real engagement target. TWO hosts, because the same account name
# on two boxes is the case a bare-username identifier silently merges.
PROBE_IP = "203.0.113.77"
PROBE_IP2 = "203.0.113.78"


def _in_container(script):
    try:
        out = subprocess.run(["docker", "exec", "rag-api", "python3", "-c", script],
                             capture_output=True, text=True, timeout=180)
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return None
    return out.stdout


@pytest.fixture(scope="module")
def rag_api():
    if _in_container("print('ok')") is None:
        pytest.skip("rag-api container not reachable")
    return True


# ── the two CHECK vocabularies must line up (static, but load-bearing) ───────

def _vault_allowed_credential_types():
    """The credential_type CHECK as it ends up after ensure_all_tables.sql runs.

    The file defines it TWICE — a narrow list in the CREATE TABLE, then an
    `ALTER ... DROP CONSTRAINT / ADD CONSTRAINT` further down that widens it with
    the cloud types. The last definition is the one in force, so reading the
    CREATE TABLE alone reports a constraint that does not exist.
    """
    ddl = open(os.path.join(REPO, "db_init", "ensure_all_tables.sql"),
               encoding="utf-8").read()
    marker = "credential_type IN ("
    assert marker in ddl, "credential_type CHECK not found in ensure_all_tables.sql"
    tail = ddl.rsplit(marker, 1)[1]           # rsplit: the LAST definition wins
    return {v.strip().strip("'\"")
            for v in tail.split(")", 1)[0].replace("\n", "").split(",")}


@pytest.mark.unit
def test_every_secret_type_maps_into_the_vault_vocabulary():
    """parse_brutus can write any of VALID_SECRET_TYPES; the vault CHECK accepts
    a DIFFERENT set. An unmapped value aborts the insert and loses the row."""
    src = open(os.path.join(REPO, "etl", "parse_brutus.py"), encoding="utf-8").read()
    line = [l for l in src.splitlines() if l.startswith("VALID_SECRET_TYPES")][0]
    secret_types = {v.strip().strip("'\"")
                    for v in line.split("{", 1)[1].rsplit("}", 1)[0].split(",")}
    assert "password" in secret_types and len(secret_types) >= 8, \
        f"failed to read VALID_SECRET_TYPES, got {secret_types!r}"

    allowed = _vault_allowed_credential_types()
    assert {"password", "aws_access_key"} <= allowed, \
        f"failed to read the vault CHECK, got {allowed!r}"

    for st in sorted(secret_types):
        mapped = bridge.vault_credential_type(st)
        assert mapped in allowed, (
            f"secret_type {st!r} maps to {mapped!r}, which the credential_vault "
            f"CHECK rejects — the insert would abort and the credential is lost")


def test_the_live_check_matches_the_ddl(rag_api):
    """Drift between the deployed constraint and the install script would make
    the mapping test agree with a file while the insert fails in production."""
    out = _in_container("""
import os, psycopg2
conn = psycopg2.connect(os.environ['DB_DSN']); cur = conn.cursor()
cur.execute("SELECT pg_get_constraintdef(oid) FROM pg_constraint "
            "WHERE conname = 'credential_vault_credential_type_check'")
row = cur.fetchone()
print('RESULT', row[0] if row else 'MISSING')
""")
    assert out, "probe failed to run"
    live = [l for l in out.splitlines() if l.startswith("RESULT")][-1]
    assert "MISSING" not in live, "credential_vault has no credential_type CHECK"
    for t in sorted(_vault_allowed_credential_types()):
        assert f"'{t}'" in live, (
            f"ensure_all_tables.sql allows {t!r} but the deployed constraint does "
            "not — a clean install and this database would behave differently")


@pytest.mark.unit
def test_unknown_secret_type_falls_back_rather_than_raising():
    """A future secret_type must not take the whole bridge down with a CHECK
    violation; 'other' keeps the credential."""
    assert bridge.vault_credential_type("some_new_thing_2027") == "other"
    assert bridge.vault_credential_type(None) == "password"   # the column default
    assert bridge.vault_credential_type("  PASSWORD  ") == "password"


@pytest.mark.unit
def test_upsert_repeats_the_partial_index_predicate():
    """ux_credvault_source_entity is PARTIAL. Postgres refuses an ON CONFLICT
    that does not repeat the predicate exactly."""
    src = open(os.path.join(REPO, "etl", "credential_bridge.py"),
               encoding="utf-8").read()
    assert "ON CONFLICT (source, source_entity_id) WHERE source_entity_id IS NOT NULL" in src


@pytest.mark.unit
def test_the_masked_password_is_never_written_as_a_credential():
    """parse_brutus keeps only masked passwords ('msf*****').

    Copying one into credential_value would be worse than a NULL: a downstream
    tool would treat it as usable and every auth attempt would fail invisibly.
    """
    src = open(os.path.join(REPO, "etl", "credential_bridge.py"),
               encoding="utf-8").read()
    # Check the VALUES clause specifically. Asserting "NULL" appears anywhere in
    # the statement is vacuous — the ON CONFLICT predicate says IS NOT NULL, so
    # that assertion survives replacing the NULL with a bound parameter.
    insert = src.split("INSERT INTO credential_vault", 1)[1].split("\"\"\"", 1)[0]
    cols = insert.split("(", 1)[1].split(")", 1)[0].replace("\n", " ").split(",")
    cols = [c.strip() for c in cols]
    values = insert.split("VALUES (", 1)[1].split(")", 1)[0].split(",")
    values = [v.strip() for v in values]
    assert len(cols) == len(values), \
        f"{len(cols)} columns but {len(values)} values in the vault insert"
    assert values[cols.index("credential_value")] == "NULL", (
        "credential_value is bound to a parameter instead of a literal NULL — "
        "the only thing available to bind is a masked password")
    assert "password_masked" not in src and "passwords_tried_masked" not in src, \
        "the bridge is reading masked password material out of metadata.audit"


@pytest.mark.unit
def test_identity_is_keyed_per_host_not_per_username():
    """'msfadmin' on two hosts is two local accounts.

    identities is unique on (provider, lower(identifier)), so a bare username
    would merge unrelated accounts across every host in the engagement.
    """
    src = open(os.path.join(REPO, "etl", "credential_bridge.py"),
               encoding="utf-8").read()
    assert '"identity_identifier": f"{acct[\'username\']}@{host}"' in src, \
        "the identity identifier no longer includes the host"


# ── executed against the live database ──────────────────────────────────────

_PROBE_SETUP = f"""
import sys, os, psycopg2
from psycopg2.extras import RealDictCursor
sys.path.insert(0, '/app')
from etl.credential_bridge import bridge_credential_findings
conn = psycopg2.connect(os.environ['DB_DSN'])
cur = conn.cursor(cursor_factory=RealDictCursor)
IP = '{PROBE_IP}'
IP2 = '{PROBE_IP2}'
IPS = (IP, IP2)

def clean():
    # host(ip), NOT ip::text -- an inet renders as '203.0.113.77/32', so
    # `ip::text = '203.0.113.77'` is false for every row and the DELETE silently
    # removes nothing. That left probe rows in the database after every run.
    cur.execute("DELETE FROM credential_findings WHERE host(ip) = ANY(%s)", (list(IPS),))
    cur.execute("DELETE FROM credential_vault WHERE domain = ANY(%s)", (list(IPS),))
    cur.execute("DELETE FROM identities WHERE domain = ANY(%s) AND provider = 'local'", (list(IPS),))
    conn.commit()

def leftovers():
    cur.execute("SELECT (SELECT count(*) FROM credential_findings WHERE host(ip) = ANY(%s))"
                "     + (SELECT count(*) FROM credential_vault WHERE domain = ANY(%s))"
                "     + (SELECT count(*) FROM identities WHERE domain = ANY(%s)) AS n",
                (list(IPS), list(IPS), list(IPS)))
    return cur.fetchone()['n']

clean()
# One account proven on TWO services of one host, a privileged-by-definition
# account, and THE SAME account name on a second host.
for ip, port, proto, user in ((IP,  21, 'ftp',    'bridge-probe-svc'),
                              (IP,  23, 'telnet', 'bridge-probe-svc'),
                              (IP,  21, 'ftp',    'root'),
                              (IP2, 21, 'ftp',    'bridge-probe-svc')):
    cur.execute(\"\"\"
        INSERT INTO credential_findings (ip, port, protocol, username, valid_cred,
                                         auth_type, secret_type, source, status)
        VALUES (%s::inet, %s, %s, %s, true, 'password', 'password',
                'bridge-probe', 'valid')
    \"\"\", (ip, port, proto, user))
conn.commit()
"""

# A teardown that deletes nothing looks identical to one that works, which is
# how the probe rows survived every run. Report what is left so the test can
# fail on it instead of leaving debris in a real database.
_PROBE_TEARDOWN = "\nclean()\nconn.commit()\nprint('LEFTOVERS', leftovers())\n"


def _probe(body):
    out = _in_container(_PROBE_SETUP + body + _PROBE_TEARDOWN)
    if out is not None:
        left = [l for l in out.splitlines() if l.startswith("LEFTOVERS")]
        assert left, "the probe teardown did not run"
        assert left[-1].split()[1] == "0", (
            f"{left[-1].split()[1]} probe row(s) left in the database — the "
            "teardown is not deleting what it thinks it is")
    return out


def test_findings_are_grouped_into_accounts_not_copied_per_finding(rag_api):
    out = _probe("""
r = bridge_credential_findings(cur, dry_run=True, sources=['bridge-probe'])
mine = [p for p in r['proposals'] if p['domain'] in IPS]
host1 = [p for p in mine if p['domain'] == IP]
svc = [p for p in host1 if p['username'] == 'bridge-probe-svc'][0]
shared = [p for p in mine if p['username'] == 'bridge-probe-svc']
print('RESULT', len(mine), len(svc['services']), '|'.join(svc['services']), len(shared))
""")
    assert out, "probe failed to run"
    line = [l for l in out.splitlines() if l.startswith("RESULT")][-1].split()
    accounts, n_services, services, shared = (
        int(line[1]), int(line[2]), line[3], int(line[4]))
    assert accounts == 3, (
        f"4 findings produced {accounts} accounts, expected 3 — one username on "
        "two services of one host must not become two vault rows")
    assert n_services == 2, f"the two services collapsed to {n_services}"
    assert services == "ftp/21|telnet/23", (
        f"services are {services} — ordered by port number, not lexically")
    assert shared == 2, (
        "the same account name on two hosts collapsed into one row — these are "
        "two unrelated local accounts")


def test_bridge_is_idempotent_and_fills_the_has_credential_join(rag_api):
    out = _probe("""
r1 = bridge_credential_findings(cur, dry_run=False, sources=['bridge-probe']); conn.commit()
r2 = bridge_credential_findings(cur, dry_run=False, sources=['bridge-probe']); conn.commit()
L = list(IPS)
def one(sql, args):
    cur.execute(sql, args); return cur.fetchone()['n']

vault = one("SELECT count(*) n FROM credential_vault WHERE domain = ANY(%s)", (L,))
ids   = one("SELECT count(*) n FROM identities "
            "WHERE domain = ANY(%s) AND provider = 'local'", (L,))
per_host = one("SELECT count(DISTINCT identifier) n FROM identities "
               "WHERE domain = ANY(%s) AND provider = 'local' "
               "AND identifier LIKE 'bridge-probe-svc@%%'", (L,))
# the EXACT expression /identities uses for the has_credential badge
badged = one("SELECT count(*) n FROM identities i "
             "WHERE i.domain = ANY(%s) AND i.provider = 'local' AND EXISTS ("
             "  SELECT 1 FROM credential_vault cv "
             "   WHERE LOWER(cv.username) = LOWER(i.identifier) "
             "      OR LOWER(cv.username || '@' || COALESCE(cv.domain,'')) "
             "         = LOWER(i.identifier))", (L,))
with_secret = one("SELECT count(*) n FROM credential_vault "
                  "WHERE domain = ANY(%s) AND credential_value IS NOT NULL", (L,))
admins = one("SELECT count(*) n FROM identities WHERE domain = ANY(%s) "
             "AND provider = 'local' AND is_admin", (L,))
print('RESULT', r1['errors'] or 'none', vault, ids, per_host, badged, with_secret, admins)
""")
    assert out, "probe failed to run"
    line = [l for l in out.splitlines() if l.startswith("RESULT")][-1].split()
    errs = line[1]
    vault, ids, per_host, badged, with_secret, admins = map(int, line[2:8])
    assert errs == "none", f"bridge reported errors: {errs}"
    assert vault == 3, f"{vault} vault rows after TWO runs — the upsert is not deduping"
    assert ids == 3, f"{ids} identities after two runs"
    assert per_host == 2, (
        f"'bridge-probe-svc' produced {per_host} identifiers across two hosts — a "
        "bare username merges unrelated local accounts")
    assert badged == 3, (
        f"only {badged}/3 identities satisfy the has_credential join — this is the "
        "reported symptom, the badge stays dark")
    assert with_secret == 0, (
        "a credential_value was written; brutus stores only masked passwords")
    assert admins == 1, (
        f"{admins} admin identities — 'root' is privileged by definition and sorts "
        "first on the Users page")


def test_the_endpoint_executes(rag_api):
    """CLAUDE.md: a mutating endpoint ships an executing test in the same commit.

    rag-api serves TLS on 8000 (`curl -fk https://…` is its own healthcheck), so
    a plain-http probe here fails with RemoteDisconnected and looks like a broken
    endpoint. Verified against the mounted CA bundle when one is present.
    """
    out = _probe("""
import ssl, json, urllib.request
ctx = ssl.create_default_context()
bundle = '/certs/ca-bundle.crt'
if os.path.exists(bundle):
    try:
        ctx.load_verify_locations(bundle)
    except Exception:
        ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
else:
    ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
req = urllib.request.Request(
    'https://127.0.0.1:8000/vault/bridge-credential-findings',
    data=json.dumps({'dry_run': True, 'limit': 1000,
                     'sources': ['bridge-probe']}).encode(),
    headers={'Content-Type': 'application/json',
             'x-api-key': os.environ.get('API_KEY', '')}, method='POST')
body = json.loads(urllib.request.urlopen(req, timeout=60, context=ctx).read())
mine = [p for p in body.get('proposals', []) if p['domain'] in IPS]
print('RESULT', body.get('ok'), body.get('dry_run'), len(mine))
""")
    assert out, "endpoint probe failed to run"
    line = [l for l in out.splitlines() if l.startswith("RESULT")][-1].split()
    assert line[1] == "True", f"endpoint returned ok={line[1]}"
    assert line[2] == "True", "dry_run was not honoured"
    assert int(line[3]) == 3, f"endpoint saw {line[3]} probe accounts, expected 3"


@pytest.mark.unit
def test_the_sweep_can_be_scoped_to_one_source():
    """Without this, a test that commits rewrites every account in the database.

    Running the unscoped bridge against a live database during development
    inserted duplicate vault rows for four real engagement accounts. The `sources`
    filter is what makes the probes above hermetic, so its absence must fail here
    rather than be discovered in the data.
    """
    import inspect
    sig = inspect.signature(bridge.bridge_credential_findings)
    assert "sources" in sig.parameters, \
        "the bridge can no longer be scoped — tests would write to real accounts"
    src = open(os.path.join(REPO, "etl", "credential_bridge.py"),
               encoding="utf-8").read()
    assert "COALESCE(cf.source, 'brutus') = ANY(%s)" in src, \
        "the sources parameter is accepted but not applied to the query"
    probe = open(__file__, encoding="utf-8").read()
    body = probe.split("def test_the_sweep_can_be_scoped_to_one_source", 1)[0]
    for call in ("bridge_credential_findings(cur, dry_run=True)",
                 "bridge_credential_findings(cur, dry_run=False)"):
        assert call not in body, \
            f"an unscoped {call} would sweep every credential in the database"
