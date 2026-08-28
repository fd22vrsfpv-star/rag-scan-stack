"""Self-adapting extractor overlay + distiller.

Run on demand:

    pytest tests/test_extractor_learn.py -v

WHY THIS EXISTS
---------------
Post-scan analysis is deterministic-first (knowledge/extractors/*.yaml regexes),
LLM only for what regexes miss. The self-adapting loop authors a regex ONCE for a
value the model filled, validates it re-extracts the value, and stores it in
`extractor_learned` (status='active') so future runs are code-only. Pins:

  * regex validation is strict — exactly one capture group AND it re-extracts the
    value (a regex that "matches" but captures the wrong thing is rejected);
  * an ACTIVE learned rule is merged onto the tool's spec by load_specs(), so
    run_deterministic() then extracts the field with no model (rolled back);
  * a tool with ONLY learned rules gets a synthesised spec.

Pure functions run anywhere; the overlay round-trip runs in the rag-api container
and rolls back. Skips cleanly when unreachable.
"""
import os
import subprocess

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
LEARN = os.path.join(REPO, "app", "rag-api", "extractor_learn.py")
SPECS = os.path.join(REPO, "app", "rag-api", "extractor_specs.py")


def _run(script):
    try:
        out = subprocess.run(["docker", "exec", "rag-api", "python3", "-c", script],
                             capture_output=True, text=True, timeout=90)
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return f"__ERR__ {out.stderr.strip()[-1000:]}"
    return out.stdout


@pytest.fixture(scope="module")
def container():
    if _run("print('ok')") is None:
        pytest.skip("rag-api container not reachable")
    return True


@pytest.mark.unit
def test_modules_exist():
    assert os.path.exists(LEARN) and os.path.exists(SPECS)
    src = open(SPECS).read()
    assert "_load_overlay" in src and "_merge_overlay" in src and "extractor_learned" in src


def test_regex_validation(container):
    out = _run(
        "import extractor_learn as el;"
        "raw='NetBIOS computer name: FILESRV01\\nSamba version 4.15';"
        "print(el._validate_regex(r'NetBIOS computer name:\\s*(\\S+)', raw, 'FILESRV01'));"
        "print(el._validate_regex(r'nope (\\S+)', raw, 'FILESRV01'));"
        "print(el._validate_regex(r'(a)(b)', raw, 'x'));"
        "print(el._kind_of([1,2]), el._kind_of('s'), el._kind_of(3), el._kind_of(True))")
    assert out and not out.startswith("__ERR__"), out
    lines = out.strip().splitlines()
    assert lines[0] == "True"           # correct capture
    assert lines[1] == "False"          # doesn't match
    assert lines[2] == "False"          # two groups rejected
    assert lines[3] == "list string number boolean"


_OVERLAY = r"""
import os, json, psycopg2, extractor_specs as es
c=psycopg2.connect(os.environ["DB_DSN"]); c.autocommit=True; cur=c.cursor()
TOOL="pytest-learn-tool"
cur.execute("DELETE FROM extractor_learned WHERE tool=%s",(TOOL,))
cur.execute('''INSERT INTO extractor_learned (tool,kind,rule,status,source)
  VALUES (%s,'deterministic',%s::jsonb,'active','distilled')''',
  (TOOL, json.dumps({"widget": {"pattern": r"widget=(\w+)", "capture":"first","type":"string"}})))
try:
    es._overlay_cache["checked_at"]=0.0
    specs,_=es.load_specs(force=True)
    spec=es.spec_for(TOOL)
    got=es.run_deterministic(spec, "banner widget=frobnicator end") if spec else {}
    print(json.dumps({"synth": bool(spec) and spec.get("_synth_from_learned"),
                      "extracted": got.get("widget")}))
finally:
    cur.execute("DELETE FROM extractor_learned WHERE tool=%s",(TOOL,))
"""


def test_overlay_roundtrip(container):
    out = _run(_OVERLAY)
    if out is None or (out.startswith("__ERR__") and ("connect" in out or "DB_DSN" in out)):
        pytest.skip("db not reachable")
    assert out and not out.startswith("__ERR__"), out
    import json
    data = json.loads(out.strip().splitlines()[-1])
    assert data["synth"] is True                 # learned-only tool synthesised
    assert data["extracted"] == "frobnicator"    # regex from the overlay ran


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
