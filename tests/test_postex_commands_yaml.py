"""Post-ex command sets are DATA (knowledge/postex_commands.yaml), and the YAML
AGREES with the hardcoded fallback still in langgraph_engine.py.

WHY THIS EXISTS
---------------
The baseline post-exploitation info commands and the per-service local-database
probes were Python literals in autogen_agents/langgraph_engine.py, so "also
enumerate X on a foothold" needed a code change. They are now loaded from
knowledge/postex_commands.yaml, with the literals kept only as a fallback for
when the file is unreadable. If the YAML and the fallback drift, a foothold
enumerates one set of things when the file loads and a different set when it
does not — a silent behaviour change nobody can see. This pins them together.

WHAT IS PROVEN
--------------
  * The YAML parses into the shape the consumers expect: info_commands as
    (id, title, command) with UNIQUE ids, and the load-bearing `shadow` id
    present (_harvest_shell_loot keys on it).
  * Every local_database_probe has ports, procs and commands.
  * The YAML content EQUALS the _POSTEX_INFO_COMMANDS_FALLBACK and
    _LOCAL_DB_PROBES_FALLBACK literals in the engine (read via ast, so this runs
    on a bare checkout without importing langgraph/pyautogen).

SABOTAGE PROOF
--------------
Change any command in the YAML (or the fallback) and test_yaml_matches_fallback
fails. Rename the `shadow` info command and test_shadow_id_present fails.

Run on demand:

    pytest tests/test_postex_commands_yaml.py -v
"""
import ast
import os

import pytest

yaml = pytest.importorskip("yaml")

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
YAML_PATH = os.path.join(REPO, "knowledge", "postex_commands.yaml")
ENGINE = os.path.join(REPO, "autogen_agents", "langgraph_engine.py")


def _load_yaml():
    if not os.path.exists(YAML_PATH):
        pytest.skip("postex_commands.yaml not present")
    with open(YAML_PATH, encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def _yaml_info(data):
    return [(c["id"], c.get("title", c["id"]), c["command"])
            for c in (data.get("info_commands") or [])]


def _yaml_probes(data):
    out = {}
    for svc, spec in (data.get("local_database_probes") or {}).items():
        out[svc] = {
            "ports": {int(p) for p in (spec.get("ports") or [])},
            "procs": tuple(spec.get("procs") or []),
            "cmds": [(c["id"], c.get("title", c["id"]), c["command"])
                     for c in (spec.get("commands") or [])],
        }
    return out


def _engine_literal(name):
    if not os.path.exists(ENGINE):
        pytest.skip("langgraph_engine.py not present")
    with open(ENGINE, encoding="utf-8") as fh:
        tree = ast.parse(fh.read())
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id == name:
                    return ast.literal_eval(node.value)
    pytest.fail(f"{name} literal not found in langgraph_engine.py")


def test_yaml_parses_into_expected_shape():
    data = _load_yaml()
    info = _yaml_info(data)
    assert info, "no info_commands parsed"
    ids = [i[0] for i in info]
    assert len(ids) == len(set(ids)), f"duplicate info_command ids: {ids}"
    probes = _yaml_probes(data)
    assert probes, "no local_database_probes parsed"
    for svc, spec in probes.items():
        assert spec["ports"], f"{svc} has no ports"
        assert spec["cmds"], f"{svc} has no commands"


def test_shadow_id_present():
    # _harvest_shell_loot reads the output of the step whose id is `shadow`.
    ids = {i[0] for i in _yaml_info(_load_yaml())}
    assert "shadow" in ids, "the load-bearing `shadow` info command id is missing"


def test_yaml_matches_fallback():
    data = _load_yaml()
    # tuples become lists through ast/yaml round-trips; normalise before compare.
    def _norm_info(seq):
        return [tuple(x) for x in seq]

    assert _norm_info(_yaml_info(data)) == _norm_info(
        _engine_literal("_POSTEX_INFO_COMMANDS_FALLBACK"))

    def _norm_probes(p):
        return {svc: {"ports": set(spec["ports"]),
                      "procs": tuple(spec["procs"]),
                      "cmds": [tuple(c) for c in spec["cmds"]]}
                for svc, spec in p.items()}

    assert _norm_probes(_yaml_probes(data)) == _norm_probes(
        _engine_literal("_LOCAL_DB_PROBES_FALLBACK"))
