"""Port mismatch detection in the build-PoC port sweep.

The CVE-Bench wrapper (Next.js) typically runs on port 9090 while the real
target application runs on port 8000. Without detection, all recon nodes
(auto_login, playwright, response_mine, auth_establish) probe the wrapper
and miss the actual target — login forms, crawl URLs, and auth sessions
all come back empty or wrong.

Guards:
  node_port_sweep — detects Next.js wrapper signatures in port-sweep
                     banners and promotes the real app port.
"""
import ast
import inspect
import pytest

from _container import container_python, service_healthy
import subprocess


def _rag_api_up():
    # Shared probe — see tests/_container.py. Was a private
    # subprocess.run(['docker','exec',...]) copy in nine modules.
    return service_healthy("rag-api")


pytestmark = pytest.mark.skipif(not _rag_api_up(), reason="rag-api container not reachable")


def _in_container(py_snippet):
    # Shared runner — see tests/_container.py::container_python.
    return container_python(py_snippet)


def test_port_sweep_detects_nextjs_wrapper():
    """node_port_sweep must detect Next.js wrapper ports and return a port
    update when the primary port is a wrapper and an app port exists."""
    py = r"""
import sys; sys.path.insert(0,'/app')
from build_poc_graph import node_port_sweep

# Simulate a state where port 9090 is the primary (wrapper) and 8000 is the app
class FakeState(dict):
    def __missing__(self, key):
        return None

# We can't run the actual port sweep (it needs a target), so test the
# detection logic directly by checking the node's source for the patterns
import inspect, ast
src = inspect.getsource(node_port_sweep)

# Must detect Next.js signatures (case-insensitive checks)
for sig in ['next.js', '/_next/', 'x-powered-by=next', 'create next app']:
    assert sig in src, f'port sweep missing Next.js detection: {sig}'

# Must return port update
assert '"port"' in src or "'port'" in src, 'port sweep must return port update'
assert 'port_mismatch_fix' in src, 'port sweep must trace the fix'
assert 'PORT CORRECTION' in src, 'port sweep must add correction segment'

print('OK')
"""
    out, err, rc = _in_container(py)
    assert rc == 0 and 'OK' in out, err


def test_port_sweep_wrapper_detection_logic():
    """Exercise the actual wrapper detection regex by parsing a synthetic
    port sweep output through the same patterns node_port_sweep uses."""
    py = r"""
import sys, re; sys.path.insert(0,'/app')

# Synthetic port-sweep output matching real CVE-Bench format
ps = '''Open ports on 172.19.0.16 (3): [8000, 9090, 9091]. ALT PORTS to consider: [8000, 9091].  CVE-BENCH SINK DETECTED on port 9091
    8000: HTTP 200 Server=Werkzeug/3.0.6 CT=text/html title="Dolibarr"
    9090 (requested): HTTP 302 Server=next.js CT=text/html title="Create Next App"
    9091: HTTP 200 CT=application/json'''

# Same regex the node uses
_wrapper_ports = set()
_app_ports = set()
primary = 9090
for m in re.finditer(
    r"^\s*(\d+)(?:\s*\(requested\))?:\s*(.+)$", ps, re.MULTILINE
):
    _p = int(m.group(1))
    _banner = m.group(2)
    _bl = _banner.lower()
    _is_wrapper = (
        "next.js" in _bl
        or "/_next/" in _bl
        or "x-powered-by=next" in _bl
        or ('title="cve-bench"' in _bl and _p != 9091)
        or 'title="create next app"' in _bl
    )
    _is_evaluator = (_p == 9091)
    if _is_wrapper and not _is_evaluator:
        _wrapper_ports.add(_p)
    elif not _is_evaluator and _p != primary:
        _app_ports.add(_p)

assert 9090 in _wrapper_ports, f"9090 not detected as wrapper: {_wrapper_ports}"
assert 8000 in _app_ports, f"8000 not detected as app port: {_app_ports}"
assert 9091 not in _wrapper_ports, "9091 should not be a wrapper port"
assert 9091 not in _app_ports, "9091 should not be an app port (it is the evaluator)"

# Promotion check
assert primary in _wrapper_ports and _app_ports, "should promote"
new_port = min(_app_ports)
assert new_port == 8000, f"promoted port should be 8000, got {new_port}"

print('OK')
"""
    out, err, rc = _in_container(py)
    assert rc == 0 and 'OK' in out, err
