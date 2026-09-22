"""The service-vector catalogue maps discovered services to their known exploits.

The always-on sweeper (exploit_watcher.process_service_vectors) drives every
discovered service through the SAME deterministic catalogue LangGraph uses
(knowledge/service_access_methods.yaml via etl.dead_port_advisor.match_method), so
a raw scan's actionable results get their known exploit queued — matched by service
alone, no version required (that requirement is why java-rmi / unrealircd / the 1524
bindshell were being skipped).

    pytest tests/test_service_vector_sweep.py
"""
import sys
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "etl"))

dpa = pytest.importorskip("etl.dead_port_advisor")


def _methods():
    m = dpa.load_methods()
    if not m:
        pytest.skip("service_access_methods.yaml not found")
    return m


@pytest.mark.parametrize("service,product,expect_module_substr", [
    ("distccd", "distccd", "distcc_exec"),
    ("netbios-ssn", "Samba smbd", "usermap_script"),
    ("java-rmi", "GNU Classpath grmiregistry", "java_rmi_server"),
    # drb is deliberately absent: exploit/linux/misc/drb_remote_codeexec was
    # removed from Metasploit on 2020-11-02, so the vector was dropped rather
    # than left declaring a module that cannot load. See
    # test_no_vector_declares_an_absent_module below.
])
def test_known_services_map_to_their_exploit(service, product, expect_module_substr):
    m = _methods()
    got = dpa.match_method(m, service=service, product=product)
    assert got is not None, f"no vector for service {service!r}"
    assert got.get("msf"), f"vector for {service!r} has no msf module: {got}"
    assert expect_module_substr in got["msf"], f"{service} -> {got['msf']}"


def test_match_works_without_version():
    # No version at all (java-rmi / unrealircd often have none) still matches by
    # service — the fix for the version-required skip.
    m = _methods()
    got = dpa.match_method(m, service="distccd", product="", version="")
    assert got is not None and "distcc_exec" in (got.get("msf") or "")


def test_unknown_service_has_no_vector():
    m = _methods()
    assert dpa.match_method(m, service="totally-unknown-svc", product="") is None


def test_no_vector_declares_an_absent_module():
    """A vector's `msf` module must be one Metasploit can actually load.

    `drb_remote_codeexec` was declared in three places while being absent from
    this install AND from upstream (Rapid7 removed it on 2020-11-02). The vector
    sweep auto-approves and auto-fires what it queues, so a module that cannot
    load becomes a row that can only fail — which is what the "synthetic module
    ids" item was really about.

    This pins the KNOWN-REMOVED ones. It cannot check the live roster (that needs
    a running MSF and is `tests/test_msf_resolve.py`'s job), but it stops a name
    Metasploit has deleted from being reintroduced by hand.
    """
    removed = {"drb_remote_codeexec", "metasploitable_root_shell_1524"}
    offenders = []
    for m in _methods():
        mod = (m.get("msf") or "")
        for bad in removed:
            if bad in mod:
                offenders.append(f"{m.get('id')} -> {mod}")
    assert not offenders, (
        "these vectors declare an MSF module that no longer exists in "
        f"Metasploit, so they can only queue rows that fail: {offenders}")
