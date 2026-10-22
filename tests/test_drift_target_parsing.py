"""2026-10-21: the drift gate read shell metacharacters as part of the URL path.

`_poc_target_family` extracts (host, first-path-segment) from a shell command so
the refine loop can detect drift OFF the CVE's endpoint. Its path group excluded
whitespace, quotes and `?` but not `)`, `;` or a backtick — so a URL that ends a
command substitution parsed as path `"/)"`.

Observed on a live build: `drift` fired on EVERY refine iteration against
commands whose URL was correct, `fact_predispatch_refused` refused each one
before dispatch, and the run ended `drifted=True`. The platform's own
`synth_plan_rendered` emits `_r1=$(curl ... https://host/)`, so the renderer was
producing commands the drift gate rejected.

The bite is narrow and that is why it survived: it only matters when the URL's
first path segment is also the last token before the metacharacter — a root path
or a single-segment path. `.../plugins/servlet)` parses correctly because the
paren lands in a later segment that is discarded.

    docker run --rm -v /opt/rag-scan-stack:/work:ro -w /work python:3.12-slim \
      sh -c 'pip install -q pytest && PYTHONPATH=. python -m pytest tests/test_drift_target_parsing.py -v'
"""
from __future__ import annotations

import ast as _ast
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
API = REPO / "app" / "rag-api" / "api.py"

HOST = "example-corp.com:443"


@pytest.fixture(scope="module")
def target_family():
    src = API.read_text()
    fn = next(n for n in _ast.parse(src).body
              if isinstance(n, _ast.FunctionDef) and n.name == "_poc_target_family")
    ns: dict = {}
    exec(_ast.get_source_segment(src, fn), ns)  # noqa: S102 - our own source
    return ns["_poc_target_family"]


@pytest.mark.parametrize("label,command", [
    ("command substitution, root path",
     f"_r1=$(curl -s -S -i --max-time 30 -H 'UA' https://{HOST}/)"),
    ("command substitution plus semicolon",
     f"_r1=$(curl -s https://{HOST}/); echo done"),
    ("backticks",
     f"x=`curl -s https://{HOST}/`"),
    ("piped",
     f"curl -s https://{HOST}/ | grep x"),
    ("backgrounded",
     f"curl -s https://{HOST}/ & wait"),
    ("redirected",
     f"curl -s https://{HOST}/ > /tmp/out"),
])
def test_root_path_survives_shell_syntax(target_family, label, command):
    """Each of these targets the ROOT path. None may report anything else."""
    host, seg = target_family(command)
    assert host == HOST, f"{label}: host mis-parsed as {host!r}"
    assert seg == "/", f"{label}: path parsed as {seg!r}, not '/'"


@pytest.mark.parametrize("command,expected", [
    (f"curl -s https://{HOST}/download?f=x", "/download"),
    (f"curl -s https://{HOST}/plugins/servlet", "/plugins"),
    (f"_r1=$(curl -s https://{HOST}/download)", "/download"),
    (f"_r1=$(curl -s https://{HOST}/plugins/servlet)", "/plugins"),
    (f"curl -s 'https://{HOST}/admin.php'", "/admin.php"),
])
def test_real_paths_are_unchanged(target_family, command, expected):
    """The fix must not change what a correctly-parsed command reports."""
    host, seg = target_family(command)
    assert (host, seg) == (HOST, expected)


def test_genuine_drift_is_still_detected(target_family):
    """The whole point of the gate: a command that really moved to another
    endpoint must still differ. A blanket 'strip trailing punctuation' that
    collapsed everything to '/' would pass the tests above and break this.
    """
    _, intended = target_family(f"curl -s https://{HOST}/download?f=etc/passwd")
    _, drifted = target_family(f"_r1=$(curl -s https://{HOST}/admin/login)")
    assert intended == "/download"
    assert drifted == "/admin"
    assert intended != drifted, "drift onto a different endpoint is no longer visible"


def test_host_is_never_swallowed(target_family):
    """A metacharacter immediately after the host must not land in the host."""
    assert target_family(f"_r1=$(curl -s https://{HOST})")[0] == HOST


def test_no_url_returns_empty(target_family):
    assert target_family("echo hello") == ("", "")
    assert target_family("") == ("", "")
    assert target_family(None) == ("", "")
