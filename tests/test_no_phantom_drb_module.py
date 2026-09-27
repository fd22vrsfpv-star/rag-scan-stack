"""The DRb (`drb_remote_codeexec`) MSF module must not be DECLARED anywhere.

WHY THIS EXISTS
---------------
`exploit/linux/misc/drb_remote_codeexec` was removed from Metasploit by Rapid7 on
2020-11-02 and is in neither the current upstream module tree nor this install.
It was nonetheless declared in two places that feed the auto-firing vector sweep:

  * `knowledge/service_access_methods.yaml` — as a vector's `msf:`/`tool:` value
  * `scan_recommender/tool_kb.py`           — as a port-hint dict `"msf"` value

`exploit_watcher._queue_vector_exploit` reads the module straight from that
catalogue and queues it WITHOUT resolving, so a declared-but-absent module became
a `source=metasploit` row that could only ever fail. Both declarations were
removed; this guard stops either from being reintroduced by hand.

WHAT IT CHECKS (and what it deliberately does not)
--------------------------------------------------
It scans only *declarations*, never comments:
  * the YAML is parsed with PyYAML, so only real field VALUES are inspected — the
    explanatory `# ... drb_remote_codeexec was REMOVED ...` comments that document
    the removal are invisible to `yaml.safe_load` and are allowed to remain.
  * `tool_kb.py` is parsed with `ast`, so only string *literals* are inspected —
    Python `#` comments are not `ast` nodes and are likewise allowed.

Sabotage check: re-add `msf: "exploit/linux/misc/drb_remote_codeexec"` to the YAML
(or `"msf": "exploit/linux/misc/drb_remote_codeexec"` to the tool_kb dict) -> RED.

Companion guards: `tests/test_service_vector_sweep.py::test_no_vector_declares_an_absent_module`
(same class, checked through the loaded catalogue) and `tests/test_msf_resolve.py`
(the live-roster resolve gate).
"""
import ast
import os

import pytest

yaml = pytest.importorskip("yaml")

BAD = "drb_remote_codeexec"

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
YAML_DECL = os.path.join(REPO, "knowledge", "service_access_methods.yaml")
PY_DECL = os.path.join(REPO, "scan_recommender", "tool_kb.py")


def _string_values(obj):
    """Yield every string VALUE reachable in a parsed YAML structure."""
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from _string_values(v)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            yield from _string_values(v)


def test_yaml_declares_no_phantom_drb_module():
    if not os.path.exists(YAML_DECL):
        pytest.skip("service_access_methods.yaml not present")
    data = yaml.safe_load(open(YAML_DECL, encoding="utf-8"))
    offenders = [s for s in _string_values(data) if BAD in s]
    assert not offenders, (
        f"{YAML_DECL} declares the removed MSF module {BAD!r} as a real value "
        f"(not a comment): {offenders}. It is absent from this Metasploit, so the "
        "vector could only queue rows that fail. Remove the declaration; a "
        "documenting comment is fine."
    )


def test_tool_kb_declares_no_phantom_drb_module():
    if not os.path.exists(PY_DECL):
        pytest.skip("scan_recommender/tool_kb.py not present")
    tree = ast.parse(open(PY_DECL, encoding="utf-8").read())
    offenders = [
        n.value
        for n in ast.walk(tree)
        if isinstance(n, ast.Constant) and isinstance(n.value, str) and BAD in n.value
    ]
    assert not offenders, (
        f"{PY_DECL} declares the removed MSF module {BAD!r} as a string literal "
        f"(not a comment): {offenders}. Remove it; a documenting comment is fine."
    )
