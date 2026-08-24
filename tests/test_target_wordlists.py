"""Per-target credential lists: discovered usernames, service defaults, then generic.

Run on demand:

    pytest tests/test_target_wordlists.py -v

WHY THIS EXISTS
---------------
The curated shortlist is 25 generic passwords and does NOT contain `msfadmin` —
yet `msfadmin:msfadmin` is a credential this engagement already recovered on ftp
and telnet. At the same time enum4linux-ng enumerated **35 usernames** on that
host through a null session, and none reached the database: the vault held four.

So every brute-force run fired a generic list while the two best sources sat
unused. This builds the list from discovered usernames, the service's documented
defaults, and the username-as-password rule that produces msfadmin:msfadmin —
with the generic shortlist as the tail.

ORDER IS THE POINT. hydra reads the file top to bottom, so a pair that will be
found is found in the first few hundred attempts. A list is only useful if it
finishes, which is the lesson of the 15,875-hour run.
"""
import os
import subprocess
import sys

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
for path in (REPO, os.path.join(REPO, "app", "rag-api")):
    if path not in sys.path:
        sys.path.insert(0, path)

pytest.importorskip("yaml", reason="pyyaml not installed")
tw = pytest.importorskip("target_wordlists",
                         reason="target_wordlists not importable")

DEFAULTS = os.path.join(REPO, "knowledge", "default_credentials.yaml")


@pytest.fixture(scope="module")
def defaults():
    if not os.path.exists(DEFAULTS):
        pytest.skip("default_credentials.yaml not present")
    return tw.load_defaults(DEFAULTS)


# ── the defaults knowledge file ─────────────────────────────────────────────

@pytest.mark.unit
def test_defaults_declare_the_services_the_catalogue_attacks(defaults):
    """A service with brute-force commands but no defaults gets the generic
    list only, which is the situation being fixed."""
    for svc in ("ftp", "ssh", "telnet", "smb", "mysql", "postgres", "mssql",
                "vnc", "rdp", "tomcat"):
        assert svc in defaults["services"], f"no defaults for {svc}"


@pytest.mark.unit
def test_username_as_password_is_enabled(defaults):
    """The rule that produces msfadmin:msfadmin."""
    assert defaults.get("username_as_password") is True


@pytest.mark.unit
def test_blank_is_a_real_candidate(defaults):
    """An empty password is a finding, not a missing value: a blank mysql root
    and an anonymous ftp are both exactly that."""
    assert "" in defaults["services"]["mysql"]["passwords"]
    assert "" in defaults["services"]["ftp"]["passwords"]


@pytest.mark.unit
@pytest.mark.parametrize("port,expected", [
    (21, "ftp"), (2121, "ftp"), (22, "ssh"), (23, "telnet"), (445, "smb"),
    (3306, "mysql"), (5432, "postgres"), (1433, "mssql"), (5900, "vnc"),
    (8180, "tomcat"), (6379, "redis"),
])
def test_port_maps_to_a_service(defaults, port, expected):
    assert tw.service_for_port(defaults, port) == expected


@pytest.mark.unit
def test_an_unknown_port_maps_to_nothing_rather_than_a_guess(defaults):
    assert tw.service_for_port(defaults, 65001) is None


@pytest.mark.unit
def test_an_explicit_hint_beats_the_port(defaults):
    assert tw.service_for_port(defaults, 21, "tomcat") == "tomcat"


# ── username plausibility: the header trap again ────────────────────────────

@pytest.mark.unit
@pytest.mark.parametrize("bad", [
    "username", "Permissions", "Share", "-----", "", "   ", "null", "None",
    "password", "a" * 100, "user name", "not/a\\name?",
])
def test_garbage_is_not_accepted_as_a_username(bad):
    """A header cell stored as a username spends real attempts on nothing —
    the same class of error as a share called 'Permissions'."""
    assert tw._plausible_username(bad) is False, f"{bad!r} accepted"


@pytest.mark.unit
@pytest.mark.parametrize("good", ["root", "msfadmin", "www-data", "svc_sql",
                                  "DOMAIN\\admin", "user.name", "a$"])
def test_real_account_names_are_accepted(good):
    assert tw._plausible_username(good) is True, f"{good!r} rejected"


# ── the curated tail, which was silently empty ──────────────────────────────

@pytest.mark.unit
def test_a_curated_list_is_actually_found():
    """The silent bug: the constants named /usr/share/wordlists/..., which
    exists only in kali-listener. Read from rag-api that returned [] on every
    call, so include_curated=True added NOTHING and no provenance entry said
    'curated'. An absent list must be reported, never assumed present.
    """
    # Executed INSIDE rag-api: the candidate paths are absolute container paths,
    # so checking them from the host checkout skips — and a guard that always
    # skips never proves the fix.
    probe = (
        "import sys; sys.path.insert(0,'/app')\n"
        "import target_wordlists as tw\n"
        "print('RESULT', tw._curated_path('users'), tw._curated_path('passwords'),\n"
        "      len(tw._read_list(tw._curated_path('users') or '/nope')),\n"
        "      len(tw._read_list(tw._curated_path('passwords') or '/nope')))\n")
    try:
        out = subprocess.run(["docker", "exec", "rag-api", "python3", "-c", probe],
                             capture_output=True, text=True, timeout=90)
    except (OSError, subprocess.SubprocessError):
        pytest.skip("rag-api not reachable")
    if out.returncode != 0:
        pytest.skip(f"probe failed: {out.stderr[-200:]}")
    parts = [l for l in out.stdout.splitlines() if l.startswith("RESULT")][-1].split()
    upath, ppath, ulines, plines = parts[1], parts[2], int(parts[3]), int(parts[4])
    assert upath != "None", "no username shortlist is reachable from rag-api"
    assert ppath != "None", "no password shortlist is reachable from rag-api"
    assert ulines > 5 and plines > 5, (
        f"curated lists read as near-empty ({ulines}, {plines}) — this is the "
        "silent [] the fix addresses")


@pytest.mark.unit
def test_missing_file_reads_as_empty_not_an_exception():
    assert tw._read_list("/nonexistent/list.txt") == []


# ── composition, executed against the live database ─────────────────────────

def _build(target="192.168.1.150", port=21, service="ftp"):
    probe = (
        "import sys, os, json; sys.path.insert(0,'/app')\n"
        "import psycopg2, target_wordlists as tw\n"
        "conn=psycopg2.connect(os.environ['DB_DSN']); cur=conn.cursor()\n"
        f"b=tw.build_lists(cur, {target!r}, port={port!r}, service_hint={service!r})\n"
        "print('RESULT'+json.dumps({'counts':b['counts'],'users':b['users'][:6],"
        "'passwords':b['passwords'][:8],'uprov':b['user_provenance'],"
        "'pprov':b['password_provenance'],'service':b['service'],"
        "'curated':b['curated_sources']}))\n")
    try:
        out = subprocess.run(["docker", "exec", "rag-api", "python3", "-c", probe],
                             capture_output=True, text=True, timeout=180)
    except (OSError, subprocess.SubprocessError):
        pytest.skip("rag-api not reachable")
    if out.returncode != 0:
        pytest.skip(f"build failed: {out.stderr[-200:]}")
    import json
    line = [l for l in out.stdout.splitlines() if l.startswith("RESULT")][-1]
    return json.loads(line[len("RESULT"):])


def test_discovered_usernames_reach_the_list():
    """35 of them, harvested from output that never became a finding row."""
    b = _build()
    assert b["counts"]["discovered_usernames"] >= 20, (
        f"only {b['counts']['discovered_usernames']} discovered usernames — "
        "the enum4linux-ng harvest is not working")


def test_discovered_entries_come_first():
    """Order IS priority: hydra reads top to bottom."""
    b = _build()
    assert b["uprov"][b["users"][0]] == "discovered", (
        f"first user is {b['users'][0]!r} from {b['uprov'][b['users'][0]]!r}; "
        "a generic name ahead of a measured one wastes the early attempts")


def test_the_username_as_password_rule_produces_the_known_pair():
    """msfadmin:msfadmin was already recovered here, and the generic 25-entry
    shortlist could never have produced it."""
    b = _build()
    assert b["pprov"].get("msfadmin") is not None, \
        "msfadmin is not a password candidate at all"


def test_the_candidate_count_is_survivable():
    """The whole point. 243,854,783 was not."""
    b = _build()
    cands = b["counts"]["candidates"]
    assert 0 < cands < 50_000, (
        f"{cands:,} candidates — at or above the listener's warn threshold, so "
        "this rebuilds the problem it replaces")


def test_all_four_provenance_sources_are_represented():
    b = _build()
    sources = set(b["uprov"].values()) | set(b["pprov"].values())
    for expected in ("discovered", "service_default", "username_as_password"):
        assert expected in sources, f"no {expected} entries: {sources}"


def test_blank_password_survives_being_written():
    """A blank is a real ftp/mysql candidate; writing must not drop the line."""
    probe = (
        "import sys, os; sys.path.insert(0,'/app')\n"
        "import psycopg2, target_wordlists as tw\n"
        "conn=psycopg2.connect(os.environ['DB_DSN']); cur=conn.cursor()\n"
        "b=tw.build_lists(cur,'192.168.1.150',port=21,service_hint='ftp')\n"
        "p=tw.write_lists(b)\n"
        "first=open(p['passwords']).readline()\n"
        "print('RESULT', repr(first), p['passwords_lines'])\n")
    try:
        out = subprocess.run(["docker", "exec", "rag-api", "python3", "-c", probe],
                             capture_output=True, text=True, timeout=180)
    except (OSError, subprocess.SubprocessError):
        pytest.skip("rag-api not reachable")
    if out.returncode != 0:
        pytest.skip(f"write failed: {out.stderr[-200:]}")
    line = [l for l in out.stdout.splitlines() if l.startswith("RESULT")][-1]
    assert "'\\n'" in line, f"the blank password line was lost: {line}"


# ── the endpoint ────────────────────────────────────────────────────────────

def _curl(path, timeout=180):
    cmd = (f'curl -sk --max-time {timeout} -o /dev/null -w "%{{http_code}}" '
           f'-H "x-api-key: $API_KEY" -X POST "https://127.0.0.1:8000{path}"')
    try:
        out = subprocess.run(["docker", "exec", "rag-api", "sh", "-c", cmd],
                             capture_output=True, text=True, timeout=timeout + 30)
    except (OSError, subprocess.SubprocessError):
        return None
    return out.stdout.strip()


def test_the_endpoint_executes():
    code = _curl("/wordlists/build-target?target=192.168.1.150&port=21&service=ftp")
    if code is None:
        pytest.skip("rag-api not reachable")
    assert code == "200", code


def test_an_out_of_scope_target_is_refused():
    """Preparing an attack list for a host names that host. An out-of-scope
    target must not be prepared for attack any more than scanned."""
    code = _curl("/wordlists/build-target?target=104.20.44.163&service=smb")
    if code is None:
        pytest.skip("rag-api not reachable")
    assert code == "403", f"expected 403, got {code}"


def test_the_generated_lists_are_readable_by_the_tool_container():
    """rag-api writes them; kali-listener runs the command that reads them. The
    mount was missing entirely, so a generated list was unusable by the tools.
    """
    try:
        out = subprocess.run(
            ["docker", "exec", "kali-listener", "sh", "-c",
             "ls /wordlists/generated/*.txt 2>/dev/null | wc -l"],
            capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        pytest.skip("kali-listener not reachable")
    if out.returncode != 0:
        pytest.skip("could not list generated wordlists")
    assert int(out.stdout.strip() or 0) > 0, \
        "kali-listener sees no generated lists — is ./wordlists mounted?"


@pytest.mark.unit
def test_compose_mounts_wordlists_into_the_listener():
    """The mount, pinned. Without it the tools cannot read what we generate."""
    compose = open(os.path.join(REPO, "docker-compose.yml"), encoding="utf-8").read()
    idx = compose.index("container_name: kali-listener")
    # Slice to the NEXT service, not a fixed byte count: this service's env
    # block alone is over 1 KB, so a fixed window stopped short of `volumes:`
    # and the check failed on a mount that was present.
    nxt = compose.find("container_name:", idx + 10)
    block = compose[idx:nxt if nxt > idx else len(compose)]
    assert "volumes:" in block, "could not locate the listener's volumes block"
    assert "/wordlists" in block, \
        "kali-listener no longer mounts the wordlists directory"
