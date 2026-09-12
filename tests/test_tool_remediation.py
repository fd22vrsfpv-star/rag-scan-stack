"""Fix the tool with an argument the target already told us, before swapping it.

Run on demand:

    pytest tests/test_tool_remediation.py -v

WHY THIS EXISTS
---------------
netexec failed against 192.168.1.150 with

    IncompatiblePeer: Incompatible ssh peer (no acceptable host key)

and hydra failed on the same host with

    kex error : no match for method server host key algo:
    server [ssh-rsa,ssh-dss], client [ssh-ed25519,ecdsa-sha2-nistp256,...]

The platform already knew the answer. `ssh-audit` had run and stored 24 findings
for that host, including `ssh-audit:host-key-ssh-rsa (2048-bit)` and
`ssh-audit:host-key-ssh-dss`. The information needed to fix the failure was
collected BEFORE the failure happened, and nothing read it back — so the
platform kept discovering by trial what it had already measured.

TWO MEASUREMENTS, NOTHING GUESSED
---------------------------------
The option is the intersection of:

  * what the HOST advertises — `etl/target_capabilities.py`, read out of recon
  * what the CLIENT supports — `ssh -Q key`, asked rather than assumed

That second half is load-bearing and was learned the hard way. The host offers
`ssh-rsa,ssh-dss`, and `-oHostKeyAlgorithms=+ssh-rsa,ssh-dss` is rejected
outright — `Bad key types '+ssh-rsa,ssh-dss'` — because modern OpenSSH removed
ssh-dss and will not accept a name it does not know. `+ssh-rsa` alone connects,
verified against the real host.

WHAT IS TYPED AND WHAT IS LEARNED
---------------------------------
`knowledge/tool_options.yaml` records tool SYNTAX — a fact, checkable against a
man page. Whether adding an option fixes a given failure is a judgement, and it
is observed in `tool_remediation_learned`, never written down. Candidates are
ranked by lexical overlap between the error text and the category name and
values, so no protocol vocabulary is needed and a category nobody anticipated
ranks the same way.

SABOTAGE PROOF
--------------
Remove the client intersection and `test_unknown_client_algorithms_are_dropped`
fails with the option that the real ssh rejects. Add "kex" or "ssh" to the
ranking code and `test_ranking_uses_no_protocol_vocabulary` fails.
"""
import ast
import os
import re
import sys

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, REPO)

yaml = pytest.importorskip("yaml", reason="PyYAML needed")
tl = pytest.importorskip("etl.tool_learning", reason="etl/tool_learning.py not importable")
tc = pytest.importorskip("etl.target_capabilities",
                         reason="etl/target_capabilities.py not importable")

def _options_path():
    """The checkout copy, or the mount when running inside a container.

    `knowledge/` is bind-mounted at `/knowledge` in every service image, so a
    test executing from `/app` has the catalogue but not under the repo root.
    Hard-coding the repo path made these tests report "no options configured",
    which is the same symptom as the bug they guard, from the opposite cause.
    """
    for candidate in (os.path.join(REPO, "knowledge", "tool_options.yaml"),
                      "/knowledge/tool_options.yaml"):
        if os.path.exists(candidate):
            return candidate
    pytest.skip("tool_options.yaml not reachable from here")


OPTIONS = None  # resolved per test via _options_path()

# Real captured output.
NETEXEC_ERR = "IncompatiblePeer: Incompatible ssh peer (no acceptable host key)"
HYDRA_ERR = ("[ERROR] could not connect to ssh://192.168.1.150:22 - kex error : "
             "no match for method server host key algo: server [ssh-rsa,ssh-dss], "
             "client [ssh-ed25519,ecdsa-sha2-nistp256]")
HOST_CAPS = {"host-key": ["ssh-rsa", "ssh-dss"],
             "key-exchange": ["diffie-hellman-group1-sha1",
                              "diffie-hellman-group14-sha1"]}


@pytest.fixture(autouse=True)
def _use_repo_catalogue(monkeypatch):
    path = _options_path()
    monkeypatch.setenv("TOOL_OPTIONS_YAML", path)
    monkeypatch.setattr(tl, "TOOL_OPTIONS", path, raising=False)
    tl._probe_cache.clear()


# ── Reading what recon already recorded ────────────────────────────────────

def test_ssh_audit_findings_parse_into_capabilities():
    """Real script names from 192.168.1.150."""
    caps = tc.from_ssh_audit([
        "ssh-audit:host-key-ssh-dss",
        "ssh-audit:host-key-ssh-rsa (2048-bit)",
        "ssh-audit:key-exchange-diffie-hellman-group1-sha1",
        "ssh-audit:mac-algorithm-hmac-md5",
        "ssh-audit:encryption-3des-cbc",
        "not-an-ssh-audit-row",
    ])
    assert caps["host-key"] == ["ssh-dss", "ssh-rsa"], caps
    assert caps["key-exchange"] == ["diffie-hellman-group1-sha1"]
    assert caps["mac-algorithm"] == ["hmac-md5"]
    assert caps["encryption"] == ["3des-cbc"]


def test_the_bit_size_is_stripped_from_the_algorithm_name():
    """`ssh-rsa (2048-bit)` is a finding about a name, not a different name.
    Leaving it on produces `-oHostKeyAlgorithms=+ssh-rsa (2048-bit)`."""
    assert tc.from_ssh_audit(["ssh-audit:host-key-ssh-rsa (2048-bit)"])["host-key"] == ["ssh-rsa"]


def test_mac_algorithm_is_not_shortened_to_mac():
    """Category prefixes overlap; matching the shortest first mislabels them."""
    caps = tc.from_ssh_audit(["ssh-audit:mac-algorithm-hmac-sha1-96"])
    assert "mac-algorithm" in caps and caps["mac-algorithm"] == ["hmac-sha1-96"]


def test_unreachable_store_is_not_an_empty_target():
    """A caller treating "database down" as "this host supports nothing" would
    constrain a tool to an empty list and fail worse than it started."""
    caps = tc.capabilities("")
    assert caps["available"] is False and caps["categories"] == {}


# ── Proposing the option ───────────────────────────────────────────────────

def test_the_option_is_built_from_what_the_host_advertised():
    r = tl.propose_remediations("ssh", HYDRA_ERR, capabilities=HOST_CAPS)
    top = r["candidates"][0]
    assert top["category"] == "host-key", r["candidates"]
    assert top["option"].startswith("-oHostKeyAlgorithms=+")
    assert "ssh-rsa" in top["option"]


def test_unknown_client_algorithms_are_dropped():
    """The half that was learned the hard way.

    `-oHostKeyAlgorithms=+ssh-rsa,ssh-dss` is rejected outright by a modern
    OpenSSH — `Bad key types` — because ssh-dss has been removed. `+ssh-rsa`
    alone connects, verified against the real host.
    """
    tl._probe_cache["ssh:host-key"] = ["ssh-ed25519", "ecdsa-sha2-nistp256", "ssh-rsa"]
    r = tl.propose_remediations("ssh", NETEXEC_ERR, capabilities=HOST_CAPS)
    top = next(c for c in r["candidates"] if c["category"] == "host-key")
    assert top["option"] == "-oHostKeyAlgorithms=+ssh-rsa", top
    assert top["client_verified"] is True
    assert top["host_offers"] == ["ssh-rsa", "ssh-dss"], (
        "the host's full offer is no longer recorded, so a reader cannot see "
        "what was dropped or why")


def test_no_overlap_is_reported_as_its_own_finding():
    """"This client cannot negotiate with this host at all" is a real finding,
    and an empty option would just fail differently."""
    tl._probe_cache["ssh:host-key"] = ["ssh-ed25519", "ecdsa-sha2-nistp256"]
    r = tl.propose_remediations("ssh", NETEXEC_ERR,
                                capabilities={"host-key": ["ssh-dss"]})
    hk = next(c for c in r["candidates"] if c["category"] == "host-key")
    assert hk["option"] is None
    assert "no overlap" in (hk.get("note") or "")


def test_a_tool_with_no_options_proposes_nothing():
    """hydra and netexec take no algorithm flags. The answer is a different
    tool — which next_tool() already provides — and saying so is different from
    having nothing to say."""
    for tool in ("hydra", "netexec"):
        r = tl.propose_remediations(tool, NETEXEC_ERR, capabilities=HOST_CAPS)
        assert r["tool_has_options"] is False, tool
        assert r["candidates"] == [], tool


def test_a_category_with_no_measurement_is_skipped():
    """A template filled from an empty list constrains the tool to nothing."""
    r = tl.propose_remediations("ssh", NETEXEC_ERR, capabilities={"host-key": []})
    assert all(c["category"] != "host-key" for c in r["candidates"]), r["candidates"]


def test_the_error_quoting_the_values_back_ranks_higher():
    """hydra prints `server [ssh-rsa,ssh-dss]` — the tool quoting the host's own
    algorithms at us is the strongest signal there is."""
    tl._probe_cache["ssh:host-key"] = ["ssh-rsa"]
    quoted = tl.propose_remediations("ssh", HYDRA_ERR, capabilities=HOST_CAPS)
    plain = tl.propose_remediations("ssh", NETEXEC_ERR, capabilities=HOST_CAPS)
    q = next(c for c in quoted["candidates"] if c["category"] == "host-key")
    p = next(c for c in plain["candidates"] if c["category"] == "host-key")
    assert q["score"] > p["score"], (q["score"], p["score"])


def test_ranking_uses_no_protocol_vocabulary():
    """A typed `if "kex" in error` rule is the thing this replaces. The ranking
    must work for a category nobody anticipated."""
    with open(os.path.join(REPO, "etl", "tool_learning.py"), encoding="utf-8") as fh:
        src = fh.read()
    tree = ast.parse(src)
    fn = ""
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "_category_relevance":
            node.body = node.body[1:] or [ast.Pass()]
            fn = ast.unparse(node)
    assert fn, "_category_relevance is gone"
    for banned in ("kex", "ssh", "host-key", "cipher", "algo", "rsa", "dss"):
        assert banned not in fn.lower(), (
            f"_category_relevance names {banned!r} — that is a typed rule again")


# ── The catalogue is syntax, not judgement ─────────────────────────────────

def test_tools_without_options_are_recorded_explicitly():
    """Without these rows a reader cannot tell "no option exists" from "nobody
    filled this in yet"."""
    with open(_options_path(), encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    for tool in ("hydra", "netexec"):
        assert tool in data["tools"], f"{tool} is not recorded at all"
        assert (data["tools"][tool] or {}).get("note"), (
            f"{tool} has no options and no explanation")


def test_every_template_has_the_values_placeholder():
    with open(_options_path(), encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    for tool, opts in (data["tools"] or {}).items():
        for cat, template in (opts or {}).items():
            if cat in ("note", "probe"):
                continue
            assert "{values}" in template, f"{tool}/{cat}: {template!r}"


# ── Learning whether it worked ─────────────────────────────────────────────

@pytest.fixture
def store():
    if not tl.available():
        pytest.skip("learning store unreachable")
    import uuid
    svc = f"__pytest_{uuid.uuid4().hex[:8]}"
    yield svc
    try:
        import psycopg2
        with psycopg2.connect(tl.DB_DSN) as conn, conn.cursor() as cur:
            cur.execute("DELETE FROM public.tool_remediation_learned WHERE service=%s",
                        (svc,))
    except Exception:
        pass


def test_a_remediation_that_worked_becomes_active(store):
    sig, phrase = tl.error_signature(NETEXEC_ERR)
    assert tl.best_remediation("ssh", sig, service=store) is None

    r = tl.record_remediation("ssh", sig, "-oHostKeyAlgorithms=+ssh-rsa",
                              category="host-key", service=store, phrase=phrase,
                              worked=True, emit=False)
    assert r and r["status"] == "active", r
    best = tl.best_remediation("ssh", sig, service=store)
    assert best and best["option_template"] == "-oHostKeyAlgorithms=+ssh-rsa"


def test_a_remediation_that_never_helps_is_recorded_too(store):
    """Learning only the successes leaves the platform re-adding a useless flag
    forever."""
    sig, _ = tl.error_signature(NETEXEC_ERR)
    for _ in range(3):
        tl.record_remediation("ssh", sig, "-oCiphers=+arcfour", category="encryption",
                              service=store, worked=False, emit=False)
    rows = [r for r in tl.remediations_for("ssh", sig, service=store)
            if r["option_template"] == "-oCiphers=+arcfour"]
    assert rows and rows[0]["successes"] == 0 and rows[0]["attempts"] >= 3
    assert rows[0]["status"] == "proposed"
    assert tl.best_remediation("ssh", sig, service=store) is None


def test_an_operator_rejection_is_durable(store):
    import psycopg2
    sig, _ = tl.error_signature(NETEXEC_ERR)
    tl.record_remediation("ssh", sig, "-oHostKeyAlgorithms=+ssh-rsa",
                          category="host-key", service=store, worked=True, emit=False)
    with psycopg2.connect(tl.DB_DSN) as conn, conn.cursor() as cur:
        cur.execute("UPDATE public.tool_remediation_learned SET status='rejected', "
                    "reviewed_by='pytest' WHERE service=%s", (store,))
    tl.record_remediation("ssh", sig, "-oHostKeyAlgorithms=+ssh-rsa",
                          category="host-key", service=store, worked=True, emit=False)
    rows = tl.remediations_for("ssh", sig, service=store)
    assert rows and rows[0]["status"] == "rejected", rows
    assert tl.best_remediation("ssh", sig, service=store) is None


def test_a_learned_remediation_outranks_a_lexical_guess(store):
    sig, _ = tl.error_signature(NETEXEC_ERR)
    tl._probe_cache["ssh:host-key"] = ["ssh-rsa"]
    tl._probe_cache["ssh:key-exchange"] = ["diffie-hellman-group1-sha1"]
    tl.record_remediation("ssh", sig,
                          "-oKexAlgorithms=+diffie-hellman-group1-sha1",
                          category="key-exchange", service=store, worked=True,
                          emit=False)
    r = tl.propose_remediations("ssh", NETEXEC_ERR, service=store,
                                capabilities=HOST_CAPS)
    assert r["candidates"][0]["category"] == "key-exchange", (
        "an option already observed to work did not outrank a lexical score")


# ── Derived before the failure, not after ──────────────────────────────────

def test_settings_are_derived_from_both_measurements():
    """The whole point: the option is the intersection of what the host
    advertised and what the client supports, and neither is guessed."""
    tl._probe_cache["ssh:host-key"] = ["ssh-ed25519", "ecdsa-sha2-nistp256", "ssh-rsa"]
    d = tc.derive_tool_settings("h", tools=["ssh"], caps={
        "available": True, "categories": {"host-key": ["ssh-rsa", "ssh-dss"]}})
    hk = next(s for s in d["settings"] if s["category"] == "host-key")
    assert hk["option"] == "-oHostKeyAlgorithms=+ssh-rsa", hk
    assert hk["client_verified"] is True
    assert hk["host_offers"] == ["ssh-rsa", "ssh-dss"], (
        "what the host offered is no longer recorded, so nobody can see what "
        "was dropped in the intersection or why")


def test_a_tool_with_no_options_is_skipped_with_a_reason():
    """"no flag exists for this" and "nobody derived anything" look identical
    as an absent row."""
    d = tc.derive_tool_settings("h", tools=["hydra"], caps={
        "available": True, "categories": {"host-key": ["ssh-rsa"]}})
    assert d["settings"] == []
    assert any(s["tool"] == "hydra" and "different tool" in s["reason"]
               for s in d["skipped"]), d["skipped"]


def test_no_overlap_is_skipped_with_both_sides_recorded():
    tl._probe_cache["ssh:host-key"] = ["ssh-ed25519"]
    d = tc.derive_tool_settings("h", tools=["ssh"], caps={
        "available": True, "categories": {"host-key": ["ssh-dss"]}})
    skipped = next(s for s in d["skipped"] if s.get("category") == "host-key")
    assert skipped["host_offers"] == ["ssh-dss"]
    assert skipped["client_supports"] == ["ssh-ed25519"]
    assert "no overlap" in skipped["reason"]


def test_an_unavailable_store_derives_nothing():
    """"The database is down" must not read as "this host supports nothing" —
    that would constrain a tool to an empty list."""
    d = tc.derive_tool_settings("h", caps={"available": False, "categories": {}})
    assert d["available"] is False and d["settings"] == []


def test_the_dispatcher_applies_them_before_the_first_attempt():
    bff = os.path.join(REPO, "dashboard", "bff", "routers", "assets.py")
    if not os.path.exists(bff):
        pytest.skip("BFF not present")
    with open(bff, encoding="utf-8") as fh:
        src = fh.read()
    assert "def _with_derived_settings" in src, (
        "derived settings are no longer applied at dispatch, so a tool has to "
        "fail before it is told what the host supports")
    assert "_with_derived_settings(command, scanner, rec)" in src
    assert "settings_for" in src


def test_options_go_after_the_tool_not_after_the_target():
    """Plenty of tools stop parsing options at the first positional argument."""
    bff = os.path.join(REPO, "dashboard", "bff", "routers", "assets.py")
    if not os.path.exists(bff):
        pytest.skip("BFF not present")
    with open(bff, encoding="utf-8") as fh:
        src = fh.read()
    fn = src[src.index("def _with_derived_settings"):]
    fn = fn[:fn.index("def _secrets_in")]
    assert 'command.split(" ", 1)' in fn, (
        "the options are appended rather than inserted after the tool name")


def test_ssh_is_allowed_and_installed():
    """The derived fix is worthless if the tool is not there — which is exactly
    why `ssh` was off the allow-list in the first place."""
    listener = os.path.join(REPO, "kali_listener", "listener_service.py")
    dockerfile = os.path.join(REPO, "kali_listener", "Dockerfile")
    for path in (listener, dockerfile):
        if not os.path.exists(path):
            pytest.skip(f"{path} not present")
    with open(listener, encoding="utf-8") as fh:
        src = fh.read()
    block = src[src.index("_FALLBACK_ALLOWED_TOOLS = {"):]
    block = block[:block.index("}")]
    assert '"ssh"' in block, "ssh is not allow-listed"
    assert '"sshpass"' in block, (
        "sshpass is not allow-listed — ssh cannot take a password "
        "non-interactively, so a credential follow-up has nothing to offer")
    with open(dockerfile, encoding="utf-8") as fh:
        df = fh.read()
    assert "openssh-client" in df and "sshpass" in df, (
        "the image does not install them, so allow-listing them is a promise "
        "the container cannot keep")
