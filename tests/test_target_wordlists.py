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


# ── substitution: the catalogue -> resolver -> guard chain ──────────────────

CATALOGUE = os.path.join(REPO, "knowledge", "service_tools.yaml")
BRUTE_TOOLS = ("hydra", "medusa", "ncrack", "crowbar", "patator")


@pytest.mark.unit
def test_brute_commands_use_the_list_placeholders():
    """A static path here means the discovered usernames are never used."""
    import re as _re
    src = open(CATALOGUE, encoding="utf-8").read()
    offenders = []
    for ln in src.splitlines():
        m = _re.search(r'command:\s*"([^"]+)"', ln)
        if not m:
            continue
        cmd = m.group(1)
        tool = cmd.split()[0] if cmd.split() else ""
        if tool not in BRUTE_TOOLS:
            continue
        if "shortlist.txt" in cmd or "rockyou" in cmd:
            offenders.append(cmd[:90])
    assert not offenders, (
        f"brute-force command(s) still name a static list: {offenders}")


@pytest.mark.unit
def test_no_online_attack_path_names_rockyou():
    """Cleaning the catalogue was not enough: four more sites in Python code
    hardcoded rockyou — the BFF's fallback command, two operator-facing hints,
    and targeted_recon's wordlist default. Each would rebuild the 15,875-hour
    run on its own.

    OFFLINE cracking is deliberately exempt. hashcat and john work on captured
    hashes at millions of guesses per second with no network rate limit, so
    rockyou's 14.3M entries are minutes of work there, not 15,875 hours. The
    problem is a 14.3M list behind a 256-tries-per-minute network service, not
    the list itself — and conflating the two would delete a correct default.
    """
    OFFLINE = ("hashcat", "john", "HashcatReq", "hash_type", "potfile")
    import re as _re
    bad = []
    for root, _dirs, files in os.walk(REPO):
        if any(skip in root for skip in (".git", "node_modules", "__pycache__",
                                         "/tests", "/Docs", "/wordlists")):
            continue
        for name in files:
            if not name.endswith(".py"):
                continue
            path = os.path.join(root, name)
            lines = open(path, encoding="utf-8", errors="replace").readlines()
            for i, line in enumerate(lines, 1):
                if "rockyou" not in line:
                    continue
                stripped = line.strip()
                # Only a comment or docstring line is exempt. An earlier version
                # skipped anything starting with a single quote character, which
                # silently exempted EVERY string-keyed dict entry — including
                # `"wordlist_passwords": ".../rockyou.txt"`, the exact site this
                # test exists to catch. It passed a sabotage that reintroduced it.
                if stripped.startswith("#") or stripped[:3] in ('"""', "'''"):
                    continue
                # The offline marker is usually on the enclosing class or
                # function, not the same line: hashcat's default wordlist is
                # `wordlist: Optional[str] = ".../rockyou.txt"` inside
                # `class HashcatReq`. A same-line check missed both sites.
                lo, hi = max(0, i - 16), min(len(lines), i + 4)
                context = "".join(lines[lo:hi])
                if any(tok in context for tok in OFFLINE):
                    continue
                if _re.search(r'["\']\S*rockyou\.txt', line):
                    bad.append(f"{os.path.relpath(path, REPO)}:{i}")
    assert not bad, f"rockyou.txt is a live command path again: {bad}"


@pytest.mark.unit
def test_the_static_fallback_is_short_not_rockyou():
    """A fallback that cannot finish is worse than a refusal, because it looks
    like a scan."""
    assert "top-passwords-shortlist" in tw.STATIC_PASSWORD_LIST
    assert "rockyou" not in tw.STATIC_PASSWORD_LIST
    assert "shortlist" in tw.STATIC_USER_LIST


@pytest.mark.unit
def test_needs_lists_detects_both_tokens():
    assert tw.needs_lists("hydra -L {user_list} -P {password_list} ftp://h:21")
    assert tw.needs_lists("hydra -P {password_list} vnc://h:5900")
    assert not tw.needs_lists("nmap -sV h")
    assert not tw.needs_lists("")


def test_resolve_produces_a_command_with_no_placeholder_left():
    """The listener REFUSES an unresolved {placeholder}, so resolution must
    never simply give up."""
    import json
    probe = (
        "import sys, os, json; sys.path.insert(0,'/app')\n"
        "import psycopg2, target_wordlists as tw\n"
        "conn=psycopg2.connect(os.environ['DB_DSN']); cur=conn.cursor()\n"
        "cmd='hydra -I -L {user_list} -P {password_list} ftp://192.168.1.150:21'\n"
        "r=tw.resolve_command(cur, cmd, '192.168.1.150', port=21, service_hint='ftp')\n"
        "print('RESULT'+json.dumps({'command':r['command'],'source':r['source'],"
        "'counts':r['counts']}))\n")
    try:
        out = subprocess.run(["docker", "exec", "rag-api", "python3", "-c", probe],
                             capture_output=True, text=True, timeout=180)
    except (OSError, subprocess.SubprocessError):
        pytest.skip("rag-api not reachable")
    if out.returncode != 0:
        pytest.skip(f"resolve failed: {out.stderr[-200:]}")
    d = json.loads([l for l in out.stdout.splitlines()
                    if l.startswith("RESULT")][-1][len("RESULT"):])
    assert "{user_list}" not in d["command"] and "{password_list}" not in d["command"]
    assert d["source"] == "generated", f"fell back to {d['source']}"
    assert "/wordlists/generated/" in d["command"]
    assert d["counts"]["discovered_usernames"] >= 20


def test_the_resolved_command_passes_the_listener_guard():
    """End of the chain: the listener must be able to READ the generated files
    and judge them survivable. This is what the missing mount broke."""
    import json
    probe = (
        "import importlib.util, json\n"
        "s=importlib.util.spec_from_file_location('kl','/app/listener_service.py')\n"
        "m=importlib.util.module_from_spec(s)\n"
        "try: s.loader.exec_module(m)\n"
        "except SystemExit: pass\n"
        "cmd=('hydra -I -L /wordlists/generated/users_192.168.1.150_ftp.txt '\n"
        "     '-P /wordlists/generated/passwords_192.168.1.150_ftp.txt '\n"
        "     'ftp://192.168.1.150:21')\n"
        "est,detail=m.estimate_candidate_space('hydra',cmd)\n"
        "ref,warn=m.check_candidate_space('hydra',cmd)\n"
        "print('RESULT'+json.dumps({'est':est,'refused':bool(ref),'warned':bool(warn),"
        "'files':{k:v['lines'] for k,v in (detail.get('files') or {}).items()}}))\n")
    try:
        out = subprocess.run(["docker", "exec", "kali-listener", "python3", "-c", probe],
                             capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.SubprocessError):
        pytest.skip("kali-listener not reachable")
    if out.returncode != 0:
        pytest.skip(f"guard probe failed: {out.stderr[-200:]}")
    d = json.loads([l for l in out.stdout.splitlines()
                    if l.startswith("RESULT")][-1][len("RESULT"):])
    assert d["files"], "the listener could not read the generated lists at all"
    assert d["est"] and d["est"] > 100, f"suspiciously small estimate {d['est']}"
    assert d["refused"] is False and d["warned"] is False, \
        f"the generated lists were themselves judged oversized: {d['est']}"


# ── service-aware template choice ───────────────────────────────────────────

@pytest.mark.unit
def test_a_vnc_rerun_does_not_get_the_ssh_template():
    """The real defect: `candidates[0]` was used, and the catalogue lists hydra
    once per service, so a VNC hydra timeout was re-proposed as
    `ssh://192.168.1.150:5900` — an SSH attack aimed at the VNC port. It looked
    right because the tool name matched.
    """
    pr = pytest.importorskip("post_review_agent")
    candidates = [
        "hydra -I -L {user_list} -P {password_list} ssh://{target}:{port}",
        "hydra -I -L {user_list} -P {password_list} ftp://{target}:{port}",
        "hydra -I -P {password_list} vnc://{target}:{port}",
    ]
    row = {"command": "hydra -P /usr/share/wordlists/rockyou.txt vnc://192.168.1.150:5900",
           "service": "vnc", "port": 5900}
    chosen = pr._pick_catalogue_command(candidates, row)
    assert chosen and "vnc://" in chosen, f"chose {chosen!r}"
    assert "ssh://" not in chosen


@pytest.mark.unit
def test_medusa_module_flag_is_matched_case_insensitively():
    """`-M ssh` in a lowercased haystack never matches an uppercase `-M`, which
    silently sent medusa down the verbatim-command path."""
    pr = pytest.importorskip("post_review_agent")
    candidates = [
        "medusa -h {target} -U {user_list} -P {password_list} -M ssh",
        "medusa -h {target} -U {user_list} -P {password_list} -M ftp",
    ]
    row = {"command": "medusa -h 192.168.1.150 -P /x/rockyou.txt -M ftp",
           "service": "", "port": 21}
    chosen = pr._pick_catalogue_command(candidates, row)
    assert chosen and "-M ftp" in chosen, f"chose {chosen!r}"


@pytest.mark.unit
def test_no_match_returns_none_rather_than_guessing():
    pr = pytest.importorskip("post_review_agent")
    candidates = ["hydra -I -P {password_list} vnc://{target}:{port}",
                  "hydra -I -P {password_list} rdp://{target}:{port}"]
    row = {"command": "hydra -P /x/rockyou.txt mysql://h:3306", "service": "",
           "port": None}
    assert pr._pick_catalogue_command(candidates, row) is None


@pytest.mark.unit
def test_a_single_candidate_is_used_directly():
    pr = pytest.importorskip("post_review_agent")
    only = ["ncrack -p {port} --user root -P {password_list} {target}"]
    assert pr._pick_catalogue_command(only, {"command": "ncrack x", "port": 22}) == only[0]


def test_post_review_never_proposes_a_verbatim_credential_attack():
    """The historical command is the one that ran rockyou for 15,875 hours. If
    no current template matches the service it must be WITHHELD and reported,
    not re-run."""
    import json
    cmd = ('curl -sk --max-time 300 -H "x-api-key: $API_KEY" '
           '-X POST "https://127.0.0.1:8000/agent/post-review"')
    try:
        out = subprocess.run(["docker", "exec", "rag-api", "sh", "-c", cmd],
                             capture_output=True, text=True, timeout=360)
    except (OSError, subprocess.SubprocessError):
        pytest.skip("rag-api not reachable")
    if out.returncode != 0 or not out.stdout.strip():
        pytest.skip("post-review did not run")
    d = json.loads(out.stdout)
    proposals = d["reruns"]["proposals"]
    assert not [p for p in proposals if "rockyou" in (p["script"] or "")], \
        "a proposal names rockyou — the oversized attack would be re-run"
    assert not [p for p in proposals
                if "{user_list}" in (p["script"] or "")
                or "{password_list}" in (p["script"] or "")], \
        "a proposal shipped an unresolved list placeholder"
    brute = [p for p in proposals
             if p["tool"] in ("hydra", "medusa", "ncrack")]
    for p in brute:
        assert "/wordlists/generated/" in p["script"], (
            f"{p['tool']} proposal does not use a per-target list: {p['script'][:80]}")
