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
