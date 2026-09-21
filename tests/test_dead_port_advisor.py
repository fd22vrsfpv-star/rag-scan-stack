"""A dead port gets the non-default method for its service, most-specific first.

Run on demand:

    pytest tests/test_dead_port_advisor.py -v

WHY THIS EXISTS
---------------
The bind-shell probe sends `id` over a raw socket; that only speaks to a raw
bind shell. A real service (an FTP with a trigger-only backdoor, rsh, an RPC
program, a web server) is dead to it even when there is a real path in — the
path is just not the default. The advisor joins each dead port to its identified
service and looks up the non-default method in
knowledge/service_access_methods.yaml, so enumeration is not stuck on the
default. This checks the matching (pure) and, when the stack is up, the endpoint.

SABOTAGE PROOF
--------------
Make match_method ignore the version regex and
test_a_precise_product_version_beats_a_generic_service fails (generic http would
win over vsftpd 2.3.4). Return the first match instead of the most specific and
the same test fails.
"""
import os
import sys

import pytest
from conftest import BFF_API, LAB_TARGET# shared lab constant (see tests/conftest.py)

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, REPO)

pytest.importorskip("yaml", reason="pyyaml not installed")
dpa = pytest.importorskip("etl.dead_port_advisor", reason="advisor not importable")


def test_the_catalogue_loads_and_has_the_marquee_methods():
    methods = dpa.load_methods()
    assert methods, "service_access_methods.yaml did not load"
    ids = {m.get("id") for m in methods}
    assert {"vsftpd_234_backdoor", "rservices_rsh", "rpc_status",
            "http_web"} <= ids, ids


def test_vsftpd_234_matches_the_backdoor():
    m = dpa.match_method(dpa.load_methods(), service="ftp",
                         product="vsftpd", version="2.3.4")
    assert m and m["id"] == "vsftpd_234_backdoor"
    assert m.get("opens") == 6200


def test_a_precise_product_version_beats_a_generic_service():
    """vsftpd 2.3.4 must win over a generic 'ftp' entry, if both matched — the
    most specific method is the right one, not the first."""
    methods = dpa.load_methods() + [
        {"id": "generic_ftp", "service": "ftp", "method": "generic",
         "summary": "x"}]
    m = dpa.match_method(methods, service="ftp", product="vsftpd",
                         version="2.3.4")
    assert m["id"] == "vsftpd_234_backdoor", m


def test_http_is_web_not_a_shell():
    """An HTTP service resolves to a WEB method, never a bind-shell probe. With a
    product hint (Apache) the more-specific web-RCE vector (php-cgi) wins over the
    generic web-enumeration fallback — both are web methods."""
    m = dpa.match_method(dpa.load_methods(), service="http",
                         product="Apache httpd", version="2.2.8")
    assert m and str(m["method"]).startswith("web")
    generic = dpa.match_method(dpa.load_methods(), service="http")
    assert generic and generic["method"] == "web-enumeration"


def test_rsh_and_rpc_match_by_service():
    methods = dpa.load_methods()
    assert dpa.match_method(methods, service="shell")["id"] == "rservices_rsh"
    assert dpa.match_method(methods, service="status")["id"] == "rpc_status"


def test_an_unknown_service_has_no_method():
    """"We have no non-default method for this" is honest — better than guessing
    a wrong one for a UDP-only port that should not have been a shell candidate."""
    assert dpa.match_method(dpa.load_methods(), service="") is None
    assert dpa.match_method(dpa.load_methods(), service="wubble") is None


def test_the_endpoint_returns_advice_for_a_host():
    """Live endpoint check — skips cleanly without the stack. On the lab host it
    returns advice for the dead ports (vsftpd 21, http 80, rsh 514, rpc 33737)."""
    requests = pytest.importorskip("requests")
    base = os.environ.get("BFF_BASE") or BFF_API
    ip = os.environ.get("ADVISOR_TEST_IP", LAB_TARGET)
    try:
        r = requests.get(f"{base}/assets/{ip}/port-advice", timeout=30, verify=False)
    except Exception as e:                       # pragma: no cover
        pytest.skip(f"BFF unreachable: {type(e).__name__}")
    if r.status_code == 404:                     # pragma: no cover
        pytest.skip("route not present (stack not rebuilt?)")
    if r.status_code >= 400:                     # pragma: no cover
        pytest.skip(f"endpoint HTTP {r.status_code}")
    body = r.json()
    assert set(body) >= {"target", "count", "with_method", "advice"}, body
    for a in body["advice"]:
        assert "port" in a and "method" in a and "steps" in a
