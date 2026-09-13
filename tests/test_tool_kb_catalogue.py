"""HIGH_VALUE_PORTS derives from the service-vector catalogue (no silo).

Run on demand:

    pytest tests/test_tool_kb_catalogue.py -v

WHY THIS EXISTS
---------------
`scan_recommender/tool_kb.py` used to carry TWO hand-maintained catalogues of
what-is-exploitable-where — `HIGH_VALUE_PORTS` and `METASPLOITABLE2_VULNS` — that
the exploit pipeline's own catalogue (knowledge/service_access_methods.yaml) never
knew about. They drifted: the YAML gained ftp/samba/php-cgi vectors the recommender
never prioritised. Now `HIGH_VALUE_PORTS` is BUILT from the YAML merged with a
shrinking curated supplement, and `METASPLOITABLE2_VULNS` (dead) is gone.

SABOTAGE PROOF
--------------
Make _build_high_value_ports ignore the catalogue and
test_catalogue_ports_are_high_value fails. Re-add METASPLOITABLE2_VULNS and
test_dead_silo_is_gone fails.
"""
import os
import sys
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

REPO = Path(__file__).parent.parent
SR_DIR = REPO / "scan_recommender"
sys.path.insert(0, str(SR_DIR))
os.environ.setdefault(
    "SERVICE_VECTORS_YAML", str(REPO / "knowledge" / "service_access_methods.yaml"))

tool_kb = pytest.importorskip("tool_kb", reason="scan_recommender/tool_kb not importable")


def _catalogue():
    path = REPO / "knowledge" / "service_access_methods.yaml"
    if not path.exists():
        pytest.skip("catalogue yaml not present")
    return (yaml.safe_load(open(path, encoding="utf-8")) or {}).get("methods") or []


def test_dead_silo_is_gone():
    """METASPLOITABLE2_VULNS and its accessors were unused — a second source of
    truth that could only drift. They must stay deleted."""
    assert not hasattr(tool_kb, "METASPLOITABLE2_VULNS")
    for name in ("get_msf2_vuln_info", "get_msf2_vulns_by_port",
                 "get_critical_msf2_vulns"):
        assert not hasattr(tool_kb, name), f"{name} is dead code — should be deleted"


def test_catalogue_ports_are_high_value():
    """Every catalogue vector with an int port AND an msf module must surface in
    HIGH_VALUE_PORTS with that module — otherwise the recommender still can't see
    a vector the exploit pipeline knows."""
    hv = tool_kb.HIGH_VALUE_PORTS
    missing = []
    for m in _catalogue():
        port, msf = m.get("port"), m.get("msf")
        if isinstance(port, int) and msf:
            info = hv.get(port)
            if not info or not info.get("msf"):
                missing.append((port, m.get("id"), msf))
    assert not missing, f"catalogue vectors not reflected in HIGH_VALUE_PORTS: {missing}"


def test_curated_supplement_is_preserved():
    """Ports the catalogue has no vector for (e.g. 8009 ghostcat, 6697 irc-ssl)
    still come through from the curated supplement — the merge, not a replace."""
    hv = tool_kb.HIGH_VALUE_PORTS
    for port in (8009, 6697):
        assert port in hv and hv[port].get("msf"), (port, hv.get(port))


def test_accessor_still_serves_the_consumer():
    """scan_recommender._append_high_value_port_recs reads get_high_value_port_info;
    it must keep returning the {service, msf, vulns, note} shape."""
    info = tool_kb.get_high_value_port_info(3632)  # distcc, in both sources
    assert info and info.get("msf") and "service" in info, info
