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
    ("drb", "Ruby DRb", "drb_remote_codeexec"),
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
