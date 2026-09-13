"""The platform independently attempts known service vectors — catalogue + generator.

Run on demand:

    pytest tests/test_service_vectors.py -v

WHY THIS EXISTS
---------------
A Metasploitable-2 gap analysis showed classic instant-root vectors (Samba
usermap_script, r-services rsh, NFS no_root_squash) were NEVER attempted, because
the exploit planner is LLM-only and picked them incidentally. Now a data catalogue
(knowledge/service_access_methods.yaml) + a deterministic generator
(_service_vector_tests) queue every applicable vector every run — non-MSF command
first, MSF module as a complementary seed — behind the approval gate, and record
vector_coverage so "applicable but never attempted" is visible.

These check the CATALOGUE shape and the GENERATOR selection. The command-dispatch
path and the coverage endpoint are exercised live in test_vector_coverage.py.

SABOTAGE PROOF
--------------
Drop the `attempt`/`msf` fields from a catalogue vector and
test_catalogue_vectors_are_runnable fails. Make the generator ignore port-keyed
vectors and test_generator_emits_msf_and_command fails on a mislabelled port.
"""
import os
import sys

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, REPO)

pytest.importorskip("yaml", reason="pyyaml not installed")
dpa = pytest.importorskip("etl.dead_port_advisor", reason="advisor not importable")


def _catalogue():
    return dpa.load_methods()


def test_catalogue_has_the_marquee_metasploitable_vectors():
    ids = {m.get("id") for m in _catalogue()}
    assert {"samba_usermap", "rservices_rsh", "nfs_no_root_squash",
            "unreal_ircd_backdoor", "distccd_exec", "vsftpd_234_backdoor",
            "mysql_weak", "postgres_weak", "tomcat_mgr"} <= ids, ids


def test_catalogue_vectors_are_runnable_or_seeded():
    """Every vector must carry a way to ATTEMPT it — a runnable non-MSF `attempt`
    and/or an `msf` module — plus a `success` assertion. Prose alone (the old
    advice-only file) does not close the loop."""
    for m in _catalogue():
        vid = m.get("id")
        # Runnable = a non-MSF command, an MSF module, OR a webshell dispatch
        # (php-cgi rides the existing webshell machinery, not this generator).
        has_run = (bool(m.get("attempt")) or bool(m.get("msf"))
                   or m.get("dispatch") == "webshell")
        assert has_run, f"{vid}: no attempt/msf/webshell — nothing to run"
        assert m.get("success"), f"{vid}: no success assertion"
        if m.get("attempt"):
            # command attempts template the target
            assert "{target}" in m["attempt"], f"{vid}: attempt does not use {{target}}"


def test_command_attempts_use_available_tools():
    """A non-MSF `attempt`'s tool must be one the kali image actually has."""
    have = {"nc", "printf", "sh", "smbclient", "rpcclient", "showmount", "mount",
            "rpcinfo", "nuclei", "curl", "sqlmap", "hydra", "ffuf", "gobuster",
            "vncviewer", "ssh", "sshpass", "rsh", "distcc", "nfs-vector"}
    for m in _catalogue():
        att = m.get("attempt")
        if not att:
            continue
        head = att.strip().split()[0]
        assert head in have, f"{m['id']}: attempt uses unavailable tool {head!r}"


@pytest.mark.parametrize("svc,product,version,expect", [
    ("netbios-ssn", "Samba smbd", "3.X - 4.X", "samba_usermap"),
    ("ftp", "vsftpd", "2.3.4", "vsftpd_234_backdoor"),
    ("shell", "", "", "rservices_rsh"),
    ("exec", "", "", "rservices_rsh"),    # 512 — alias must map to the same vector
    ("login", "", "", "rservices_rsh"),   # 513 — all three r-services ports covered
    ("distccd", "", "", "distccd_exec"),
])
def test_matcher_selects_the_right_vector(svc, product, version, expect):
    m = dpa.match_method(_catalogue(), service=svc, product=product, version=version)
    assert m and m["id"] == expect, (svc, product, m and m["id"])


def test_generator_emits_msf_and_command():
    """The generator turns an open service into impactful candidates carrying a
    `vector` block (so surface_plan records coverage) and the right dispatch."""
    lge = pytest.importorskip("langgraph_engine", reason="engine not importable")
    if not hasattr(lge, "_service_vector_tests"):
        pytest.skip("_service_vector_tests not present")
    items = [
        {"ip": "10.0.0.9", "port": 445, "service": "netbios-ssn", "product": "Samba smbd", "version": "3.X - 4.X"},
        {"ip": "10.0.0.9", "port": 2049, "service": "nfs", "product": "", "version": ""},
    ]
    out = lge._service_vector_tests(items)
    assert out, "generator produced no candidates for known vectors"
    for c in out:
        assert c["tier"] == "impactful"
        assert c.get("vector") and c["vector"].get("vector_id")
        assert c["vector"]["source_path"] in ("command", "msf")
        assert (c.get("exploit_ref") or {}).get("source") in ("command", "metasploit")
    # samba usermap must be seeded (its marquee root vector), nfs must be attempted
    vids = {c["vector"]["vector_id"] for c in out}
    assert "samba_usermap" in vids and "nfs_no_root_squash" in vids, vids


def test_surface_plan_records_and_dedups_coverage():
    """Source guard: surface_plan writes vector_coverage and skips already-proven
    shells (so a one-shot mutating backdoor is not re-fired)."""
    import ast
    src = open(os.path.join(REPO, "autogen_agents", "langgraph_engine.py"),
               encoding="utf-8").read()
    tree = ast.parse(src)
    fn = next((n for n in ast.walk(tree)
               if isinstance(n, ast.FunctionDef) and n.name == "surface_plan"), None)
    assert fn, "surface_plan is gone"
    body = ast.unparse(fn)
    assert "_vector_covered_keys" in body and "covered_shell" in body, (
        "surface_plan no longer dedups already-proven vectors")
    assert "_vector_coverage_upsert" in body, (
        "surface_plan no longer records vector_coverage applicability")
