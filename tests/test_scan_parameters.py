"""Discovered values that influence how a host is tested.

Run on demand:

    pytest tests/test_scan_parameters.py -v

WHY THIS EXISTS
---------------
Four tools already produced parameter-shaped facts, each in a different shape —
`smb_password_policy.params.*`, `ssh_config.banner`, `waf_detection.detected`,
`web_service.webserver` — so nothing could read them generically, and nothing
did. Two of them decide whether a scan can work at all:

  * `Account Lockout Threshold: None` is what makes a 4,100-candidate spray safe
    here. With a threshold of 3 the same list is an account-lockout denial of
    service across every account in the userlist.
  * OpenSSH 4.7p1 offers only legacy MACs while modern hydra offers only SHA2,
    so `hydra ssh://` cannot negotiate with this host at all.

Three layers, and only ONE is stored: observed values stay in findings (a copy
goes stale the moment a re-scan disagrees), declarations go in
`scan_parameters`, and the effective value is resolved from both.
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

VOCAB = os.path.join(REPO, "knowledge", "scan_parameters.yaml")
HOST = "192.168.1.150"


def _psql(sql):
    try:
        out = subprocess.run(
            ["docker", "exec", "rag-postgres", "psql", "-U", "app", "-d", "scans",
             "-v", "ON_ERROR_STOP=1", "-tAc", sql],
            capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return None
    return out.stdout.strip() if out.returncode == 0 else None


def _curl(method, path, body=None, timeout=180):
    cmd = (f'curl -sk --max-time {timeout} -H "x-api-key: $API_KEY" '
           f'-X {method} "https://127.0.0.1:8000{path}"')
    if body is not None:
        cmd += (" -H 'Content-Type: application/json' -d "
                + "'" + json.dumps(body) + "'")
    try:
        out = subprocess.run(["docker", "exec", "rag-api", "sh", "-c", cmd],
                             capture_output=True, text=True, timeout=timeout + 30)
    except (OSError, subprocess.SubprocessError):
        return None
    return out.stdout if out.returncode == 0 else None


# ── the vocabulary ──────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def vocab():
    yaml = pytest.importorskip("yaml")
    if not hasattr(yaml, "safe_load"):
        pytest.skip("the installed yaml module has no safe_load")
    if not os.path.exists(VOCAB):
        pytest.skip("scan_parameters.yaml not present")
    return (yaml.safe_load(open(VOCAB, encoding="utf-8")) or {}).get("parameters") or {}


@pytest.mark.unit
def test_every_parameter_names_what_consumes_it(vocab):
    """A parameter nothing consumes is trivia. Keeping `influences` honest is
    what stops this becoming a junk drawer."""
    assert vocab, "no parameters declared"
    for key, spec in vocab.items():
        assert spec.get("influences"), f"{key} declares no consumer"
        assert spec.get("sources"), f"{key} declares no source"
        assert spec.get("description"), f"{key} has no description"


@pytest.mark.unit
def test_every_source_is_a_kind_the_resolver_understands(vocab):
    known = {"finding", "execution_regex"}
    for key, spec in vocab.items():
        for source in spec["sources"]:
            assert source.get("kind") in known, \
                f"{key}: unknown source kind {source.get('kind')!r}"
            if source["kind"] == "finding":
                assert source.get("finding_type") and source.get("path"), key
            else:
                assert source.get("tool") and source.get("pattern"), key


@pytest.mark.unit
def test_the_rate_aggregates_pessimistically(vocab):
    """Measured rates here were 16, 22, 116 and 256 tries/min. Taking the max
    is what made every estimate the best case."""
    spec = vocab.get("observed_rate_per_min")
    assert spec, "observed_rate_per_min is not declared"
    assert spec.get("aggregate") == "min", \
        "the rate no longer takes the slowest observation"


# ── resolution against the live database ────────────────────────────────────

@pytest.fixture(scope="module")
def live():
    if _psql("SELECT 1") != "1":
        pytest.skip("rag-postgres not reachable")
    body = _curl("GET", f"/assets/{HOST}/parameters", timeout=60)
    if not body or "parameters" not in body:
        pytest.skip("parameter endpoint not deployed")
    return json.loads(body)


def test_values_are_observed_from_real_evidence(live):
    params = live["parameters"]
    observed = {k: v for k, v in params.items() if v["provenance"] == "observed"}
    assert len(observed) >= 6, (
        f"only {len(observed)} parameters resolved from evidence: "
        f"{sorted(observed)}")


def test_every_value_reports_where_it_came_from(live):
    """Provenance is load-bearing. A consumer that cannot tell a measured value
    from a default reads "we never checked" as "no lockout"."""
    for key, v in live["parameters"].items():
        assert v.get("provenance") in ("declared", "observed", "default"), key
        if v["provenance"] == "observed":
            assert v.get("tool"), f"{key} does not name the tool that saw it"
            assert v.get("via"), f"{key} does not record how it was read"


def test_the_smb_lockout_is_resolved(live):
    """The single value that decides whether spraying is safe."""
    v = live["parameters"].get("smb_lockout_threshold")
    assert v and v["provenance"] == "observed", v
    assert v["value"] == "None", f"lockout reads {v['value']!r}"


def test_the_rate_is_the_slowest_measured_not_the_fastest(live):
    """256 was the fastest ever seen here and was hardcoded."""
    v = live["parameters"].get("observed_rate_per_min")
    assert v and v["provenance"] == "observed", v
    assert float(v["value"]) <= 60, (
        f"rate resolved to {v['value']} — the pessimistic aggregate is gone")


def test_a_declaration_overrides_an_observation(live):
    """What no tool can discover: the operator states a value."""
    key = "smb_lockout_threshold"
    body = _curl("POST", f"/assets/{HOST}/parameters",
                 {"key": key, "value": "9", "note": "pytest override"})
    assert body, "declare endpoint returned nothing"
    assert json.loads(body).get("ok") is True
    try:
        after = json.loads(_curl("GET", f"/assets/{HOST}/parameters?keys={key}"))
        v = after["parameters"][key]
        assert v["provenance"] == "declared", v
        assert v["value"] == "9"
        assert (v.get("observed") or {}).get("value") == "None", \
            "the observation was lost rather than layered under"
    finally:
        _psql("DELETE FROM scan_parameters WHERE note = 'pytest override'")


def test_an_undeclared_key_is_refused(live):
    """A key nothing consumes must not be storable, or this becomes a junk
    drawer of values no scan reads."""
    cmd = ('curl -sk -o /dev/null -w "%{http_code}" -H "x-api-key: $API_KEY" '
           "-H 'Content-Type: application/json' "
           f'-X POST "https://127.0.0.1:8000/assets/{HOST}/parameters" '
           """-d '{"key":"totally_made_up","value":"1"}'""")
    out = subprocess.run(["docker", "exec", "rag-api", "sh", "-c", cmd],
                         capture_output=True, text=True, timeout=90)
    assert out.stdout.strip() == "400", out.stdout


def test_observed_values_are_never_written_to_the_table(live):
    """Only declarations are stored. A stored copy of an observation goes stale
    the moment a re-scan disagrees — the trap avoided with has_credential."""
    got = _psql("SELECT count(*) FROM scan_parameters WHERE declared_by IS NULL "
                "AND note IS NULL")
    assert got is not None
    assert int(got) == 0, (
        f"{got} rows with no declarer — observations are leaking into the "
        "declarations table")


# ── the duplicated rate logic, pinned ───────────────────────────────────────

def test_listener_rate_matches_the_parameter_store(live):
    """CLAUDE.md: duplicated logic needs an agreement test.

    The listener cannot import rag-api's scan_parameters (not mounted there), so
    the `observed_rate_per_min` source is expressed twice. Both are read here
    from the REAL deployment rather than a re-typed copy, because two copies of
    a sample agree with each other while the deployed pair has drifted.
    """
    probe = (
        "import importlib.util\n"
        "s=importlib.util.spec_from_file_location('kl','/app/listener_service.py')\n"
        "m=importlib.util.module_from_spec(s)\n"
        "try: s.loader.exec_module(m)\n"
        "except SystemExit: pass\n"
        f"print('RATE', m.observed_rate_per_min({HOST!r}))\n")
    try:
        out = subprocess.run(["docker", "exec", "kali-listener", "python3", "-c", probe],
                             capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.SubprocessError):
        pytest.skip("kali-listener not reachable")
    if out.returncode != 0:
        pytest.skip(f"listener probe failed: {out.stderr[-200:]}")
    listener_rate = [l for l in out.stdout.splitlines()
                     if l.startswith("RATE")][-1].split()[1]
    store = live["parameters"]["observed_rate_per_min"]["value"]
    assert float(listener_rate) == float(store), (
        f"listener says {listener_rate} tries/min, the parameter store says "
        f"{store} — the two copies have drifted")


def test_an_unmeasured_host_does_not_inherit_the_best_case():
    """The old constant was 256, the fastest rate ever seen here."""
    probe = (
        "import importlib.util\n"
        "s=importlib.util.spec_from_file_location('kl','/app/listener_service.py')\n"
        "m=importlib.util.module_from_spec(s)\n"
        "try: s.loader.exec_module(m)\n"
        "except SystemExit: pass\n"
        "print('DEFAULT', m.DEFAULT_RATE_PER_MIN, m.observed_rate_per_min('10.99.99.99'))\n")
    try:
        out = subprocess.run(["docker", "exec", "kali-listener", "python3", "-c", probe],
                             capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.SubprocessError):
        pytest.skip("kali-listener not reachable")
    if out.returncode != 0:
        pytest.skip("listener probe failed")
    parts = [l for l in out.stdout.splitlines() if l.startswith("DEFAULT")][-1].split()
    assert float(parts[1]) < 256, \
        f"the unmeasured default is {parts[1]} — back to the best case"
    assert parts[2] == "None", "an unmeasured host reported a measured rate"


# ── the ssh consumer ────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def sp():
    return pytest.importorskip("scan_parameters",
                               reason="scan_parameters not importable")


def test_the_server_mac_list_is_observed(live):
    """Seven MACs, matching exactly what hydra reported as the server's list."""
    v = live["parameters"].get("ssh_mac_algorithms")
    assert v and v["provenance"] == "observed", v
    macs = v["value"]
    assert isinstance(macs, list) and len(macs) >= 5, macs
    assert "hmac-md5" in macs and "hmac-sha1" in macs, macs


@pytest.mark.unit
def test_a_line_anchored_pattern_matches_every_line(sp):
    """`^\\(mac\\)` found 0 of 7 MAC lines without re.M, so the parameter
    silently fell back to its default.

    Asserted on BEHAVIOUR, not on the source. An earlier version checked that
    the string "re.M" appeared in the function, which the explanatory comment
    above the call satisfied all by itself — it passed a sabotage that removed
    the flag.
    """
    class _Cur:
        def execute(self, *a, **k):
            pass

        def fetchall(self):
            return [("ssh-audit",
                     "(mac) hmac-md5\n(mac) hmac-sha1\n(mac) umac-64\n",
                     None)]

    got = sp._observe_from_executions(
        _Cur(), "h", {"type": "list"},
        {"kind": "execution_regex", "tool": "ssh-audit",
         "pattern": r"^\(mac\)\s+(\S+)"})
    assert got is not None, "a line-anchored pattern matched nothing"
    assert got["value"] == ["hmac-md5", "hmac-sha1", "umac-64"], got["value"]


@pytest.mark.unit
def test_hydra_ssh_is_withheld_when_no_mac_is_shared(sp, monkeypatch):
    """The measured failure: 'kex error : no match for method mac algo'."""
    legacy = {"value": ["hmac-md5", "hmac-sha1", "hmac-ripemd160"],
              "provenance": "observed"}
    monkeypatch.setattr(sp, "effective",
                        lambda *a, **k: {"ssh_mac_algorithms": legacy})
    why = sp.ssh_brute_force_viable(None, "h", "hydra", "hydra -L u -P p ssh://h:22")
    assert why and "cannot negotiate" in why


@pytest.mark.unit
def test_medusa_is_never_withheld(sp, monkeypatch):
    """THE over-reach in the first version of this check.

    It covered medusa and ncrack on the assumption they share hydra's crypto
    constraints. Measured against the same host, medusa completed a full ACCOUNT
    CHECK where hydra died at key exchange — so withholding it would have
    suppressed the one SSH tool that works here.
    """
    legacy = {"value": ["hmac-md5", "hmac-sha1"], "provenance": "observed"}
    monkeypatch.setattr(sp, "effective",
                        lambda *a, **k: {"ssh_mac_algorithms": legacy})
    for tool, cmd in (("medusa", "medusa -h h -U u -P p -M ssh"),
                      ("ncrack", "ncrack -p 22 --user root -P p h")):
        assert sp.ssh_brute_force_viable(None, "h", tool, cmd) is None, \
            f"{tool} was withheld on hydra's measurement"


@pytest.mark.unit
def test_the_refusal_names_a_tool_that_works(sp, monkeypatch):
    legacy = {"value": ["hmac-md5"], "provenance": "observed"}
    monkeypatch.setattr(sp, "effective",
                        lambda *a, **k: {"ssh_mac_algorithms": legacy})
    why = sp.ssh_brute_force_viable(None, "h", "hydra", "hydra ssh://h:22")
    assert "medusa" in why, "the refusal leaves the operator with no alternative"


@pytest.mark.unit
def test_a_shared_mac_means_it_can_connect(sp, monkeypatch):
    modern = {"value": ["hmac-sha2-256", "hmac-md5"], "provenance": "observed"}
    monkeypatch.setattr(sp, "effective",
                        lambda *a, **k: {"ssh_mac_algorithms": modern})
    assert sp.ssh_brute_force_viable(None, "h", "hydra",
                                     "hydra -L u -P p ssh://h:22") is None


@pytest.mark.unit
def test_an_unmeasured_host_is_never_withheld(sp, monkeypatch):
    """Suppressing work we cannot prove futile is the worse error: a withheld
    scan that would have worked is invisible, a failed one shows up."""
    for state in ({"value": [], "provenance": "default"},
                  {"value": None, "provenance": "default"}):
        monkeypatch.setattr(sp, "effective",
                            lambda *a, **k: {"ssh_mac_algorithms": state})
        assert sp.ssh_brute_force_viable(None, "h", "hydra",
                                         "hydra ssh://h:22") is None


@pytest.mark.unit
def test_non_ssh_commands_are_untouched(sp, monkeypatch):
    legacy = {"value": ["hmac-md5"], "provenance": "observed"}
    monkeypatch.setattr(sp, "effective",
                        lambda *a, **k: {"ssh_mac_algorithms": legacy})
    for cmd in ("hydra -L u -P p ftp://h:21", "hydra -L u -P p telnet://h:23"):
        assert sp.ssh_brute_force_viable(None, "h", "hydra", cmd) is None


def test_post_review_withholds_the_ssh_proposal(live):
    """End to end: the proposal list must not offer a run that cannot connect."""
    body = _curl("POST", "/agent/post-review", timeout=600)
    if not body:
        pytest.skip("post-review did not run")
    d = json.loads(body)
    ssh_hydra = [p for p in d["reruns"]["proposals"]
                 if p["tool"] == "hydra" and "ssh://" in (p["script"] or "")]
    assert not ssh_hydra, (
        f"{len(ssh_hydra)} hydra ssh proposal(s) queued against a host whose "
        "MACs hydra cannot negotiate")


# ── consumer: brute_force_safety (account lockout) ─────────────────────────

def _listener(probe):
    try:
        out = subprocess.run(["docker", "exec", "kali-listener", "python3", "-c",
                              "import importlib.util\n"
                              "s=importlib.util.spec_from_file_location('kl','/app/listener_service.py')\n"
                              "m=importlib.util.module_from_spec(s)\n"
                              "try: s.loader.exec_module(m)\n"
                              "except SystemExit: pass\n" + probe],
                             capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.SubprocessError):
        pytest.skip("kali-listener not reachable")
    if out.returncode != 0:
        pytest.skip(f"listener probe failed: {out.stderr[-200:]}")
    return out.stdout


U = "/wordlists/generated/users_192.168.1.150_smb.txt"
P = "/wordlists/generated/passwords_192.168.1.150_smb.txt"


def test_a_spray_that_would_lock_every_account_is_refused():
    """Volume and lockout are DIFFERENT safety questions and only the first was
    ever asked. 50 users x 82 passwords finishes in 16 minutes AND locks out all
    50 accounts against a threshold of 3."""
    out = _listener(
        f"m._lockout_cache={{'192.168.1.150':'3'}}\n"
        f"r,w=m.check_account_lockout('hydra','hydra -L {U} -P {P} smb://192.168.1.150','192.168.1.150')\n"
        "print('REFUSED', bool(r))\n")
    assert "REFUSED True" in out, out


def test_a_threshold_larger_than_the_list_is_allowed():
    out = _listener(
        f"m._lockout_cache={{'192.168.1.150':'200'}}\n"
        f"r,w=m.check_account_lockout('hydra','hydra -L {U} -P {P} smb://192.168.1.150','192.168.1.150')\n"
        "print('REFUSED', bool(r), 'WARNED', bool(w))\n")
    assert "REFUSED False" in out and "WARNED False" in out, out


def test_a_measured_absence_of_lockout_is_allowed():
    """'None' is a measured answer, not a missing one."""
    for value in ("None", "Not Set", "0"):
        out = _listener(
            f"m._lockout_cache={{'192.168.1.150':{value!r}}}\n"
            f"r,w=m.check_account_lockout('hydra','hydra -L {U} -P {P} smb://192.168.1.150','192.168.1.150')\n"
            "print('REFUSED', bool(r), 'WARNED', bool(w))\n")
        assert "REFUSED False" in out and "WARNED False" in out, f"{value}: {out}"


def test_an_unmeasured_policy_warns_rather_than_refusing():
    """Refusing every brute force against a host nobody ran --pass-pol on would
    block real work on a guess. The warning names the command that resolves it."""
    out = _listener(
        "m._lockout_cache={'10.99.99.99': None}\n"
        f"r,w=m.check_account_lockout('hydra','hydra -L {U} -P {P} smb://10.99.99.99','10.99.99.99')\n"
        "print('REFUSED', bool(r), 'WARNED', bool(w))\n"
        "print('MENTIONS', 'pass-pol' in (w or ''))\n")
    assert "REFUSED False" in out and "WARNED True" in out, out
    assert "MENTIONS True" in out, "the warning does not say how to resolve it"


def test_a_non_domain_service_is_not_gated_by_the_domain_policy():
    """ftp and web logins are frequently LOCAL accounts the domain policy never
    touches; gating them would refuse work for no reason."""
    out = _listener(
        "m._lockout_cache={'192.168.1.150':'3'}\n"
        f"r,w=m.check_account_lockout('hydra','hydra -L {U} -P {P} ftp://192.168.1.150:21','192.168.1.150')\n"
        "print('REFUSED', bool(r), 'WARNED', bool(w))\n")
    assert "REFUSED False" in out and "WARNED False" in out, out


def test_force_overrides_the_lockout_gate():
    """Volume and lockout are SUPPRESSION judgements, so force may pass them —
    unlike the scope gate, which runs first and force must never pass."""
    out = _listener(
        "m._lockout_cache={'192.168.1.150':'3'}\n"
        f"r,w=m.check_account_lockout('hydra','hydra -L {U} -P {P} smb://192.168.1.150','192.168.1.150',force=True)\n"
        "print('REFUSED', bool(r))\n")
    assert "REFUSED False" in out, out


def test_listener_lockout_matches_the_parameter_store(live):
    """CLAUDE.md: duplicated logic needs an agreement test. Both sides read from
    the REAL deployment, not a re-typed copy."""
    out = _listener("print('LOCKOUT', repr(m.observed_lockout_threshold('192.168.1.150')))\n")
    listener_value = out.split("LOCKOUT", 1)[1].strip().strip("'\"")
    store = live["parameters"]["smb_lockout_threshold"]["value"]
    assert listener_value == str(store), (
        f"listener says {listener_value!r}, the parameter store says {store!r}")


# ── consumer: wordlist_selection ────────────────────────────────────────────

def test_impossible_passwords_are_dropped_for_a_domain_service(live):
    """A domain enforcing 5 characters cannot have a 1-character password, and
    against a lockout threshold a guaranteed miss still burns an attempt."""
    body = _curl("POST", "/wordlists/build-target?target=192.168.1.150&port=445&service=smb")
    if not body:
        pytest.skip("rag-api not reachable")
    d = json.loads(body)
    assert d["min_password_length"] == 5, d.get("min_password_length_reason")
    assert d["passwords_dropped_below_minimum"] > 0, "nothing was filtered"
    assert min(len(p) for p in d["passwords"]) >= 5, "a short password survived"


def test_a_local_account_service_is_not_filtered(live):
    """THE false positive: an empty password is a real ftp and mysql finding, and
    the domain policy does not govern those accounts."""
    body = _curl("POST", "/wordlists/build-target?target=192.168.1.150&port=21&service=ftp")
    if not body:
        pytest.skip("rag-api not reachable")
    d = json.loads(body)
    assert d["min_password_length"] is None, d["min_password_length_reason"]
    assert d["passwords_dropped_below_minimum"] == 0
    assert "" in d["passwords"], "the blank ftp password was filtered away"


# ── consumer: scan_aggressiveness ───────────────────────────────────────────

@pytest.mark.unit
def test_a_detected_waf_produces_advice(sp, monkeypatch):
    monkeypatch.setattr(sp, "effective", lambda *a, **k: {
        "waf_present": {"value": True, "provenance": "observed"},
        "waf_product": {"value": "Cloudflare", "provenance": "observed"}})
    got = sp.web_scan_advice(None, "h")
    assert got and got["waf"] is True
    assert "Cloudflare" in got["advice"]
    assert got["suggested_threads"] < 10


@pytest.mark.unit
def test_no_waf_produces_no_advice(sp, monkeypatch):
    """192.168.1.150 has no WAF, so silence is the correct output here."""
    monkeypatch.setattr(sp, "effective", lambda *a, **k: {
        "waf_present": {"value": False, "provenance": "observed"}})
    assert sp.web_scan_advice(None, "h") is None


@pytest.mark.unit
def test_an_unmeasured_waf_produces_no_advice(sp, monkeypatch):
    monkeypatch.setattr(sp, "effective", lambda *a, **k: {
        "waf_present": {"value": None, "provenance": "default"}})
    assert sp.web_scan_advice(None, "h") is None


@pytest.mark.unit
def test_the_waf_advice_does_not_rewrite_the_command(sp, monkeypatch):
    """Advisory on purpose: silently changing an operator's thread count makes
    the scan behave differently from the command they read."""
    monkeypatch.setattr(sp, "effective", lambda *a, **k: {
        "waf_present": {"value": True, "provenance": "observed"},
        "waf_product": {"value": "None", "provenance": "observed"}})
    got = sp.web_scan_advice(None, "h")
    assert "command" not in got and "script" not in got


def test_advice_is_surfaced_beside_the_values(live):
    """The operator should see the conclusion and its evidence together."""
    body = _curl("GET", "/assets/192.168.1.150/parameters", timeout=120)
    if not body:
        pytest.skip("rag-api not reachable")
    d = json.loads(body)
    assert "advice" in d
    topics = {a["topic"] for a in d["advice"]}
    assert "wordlist_selection" in topics, d["advice"]
