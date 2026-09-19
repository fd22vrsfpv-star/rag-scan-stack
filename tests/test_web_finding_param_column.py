"""web_findings.param is a first-class column, fed by ZAP and read by deepen.

Run on demand:

    pytest tests/test_web_finding_param_column.py -v

WHY THIS EXISTS
---------------
ZAP reports the vulnerable parameter (alert.param), but parse_zap stored only
`evidence OR param` in the single `evidence` column, so the parameter was lost
whenever ZAP also returned evidence text. The deepen tier (and any future bulk
"evaluate every discovered parameter" pass) then had no reliable parameter to
target. `web_findings.param` is now its own column: parse_zap writes alert.param
to it, and the deepen fact reads COALESCE(param, evidence) so pre-column rows
still resolve.

SABOTAGE PROOF
--------------
- Remove the `param` column from db_init/ensure_all_tables.sql and
  test_schema_declares_param_column fails.
- Drop `alert.get("param")` / the `param` column from the parse_zap INSERT and
  test_parse_zap_stores_param fails.
- Drop `COALESCE(wf.param` from the deepen SELECTs and
  test_deepen_reads_param fails.
"""
import os
import re

import pytest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DDL = os.path.join(REPO, "db_init", "ensure_all_tables.sql")
PARSE_ZAP = os.path.join(REPO, "etl", "parse_zap.py")
POSTENUM = os.path.join(REPO, "etl", "post_enumeration.py")


def _src(p):
    if not os.path.exists(p):
        pytest.skip(f"{p} missing")
    return open(p, encoding="utf-8").read()


def test_schema_declares_param_column():
    s = _src(DDL)
    # in the CREATE TABLE and as an idempotent ALTER (for existing DBs)
    wf = s[s.index("CREATE TABLE IF NOT EXISTS public.web_findings"):]
    wf_create = wf[:wf.index(");")]
    assert re.search(r"\n\s*param\s+text", wf_create), "web_findings CREATE must declare param"
    assert "web_findings ADD COLUMN IF NOT EXISTS param text" in s, \
        "an idempotent ALTER must add param for existing databases"


def test_parse_zap_stores_param():
    s = _src(PARSE_ZAP)
    ins = s[s.index("INSERT INTO web_findings"):]
    ins = ins[:ins.index("ON CONFLICT")] if "ON CONFLICT" in ins else ins[:1500]
    assert re.search(r"method,\s*param,\s*payload", ins), \
        "parse_zap INSERT column list must include param (between method and payload)"
    assert 'alert.get("param")' in s, "parse_zap must store alert.param into the param column"


def test_deepen_reads_param():
    s = _src(POSTENUM)
    assert s.count("COALESCE(wf.param, wf.evidence") >= 2, \
        "both deepen SELECTs (auto + manual) must read COALESCE(param, evidence)"
    # the fact must carry param through to the router
    assert '"param": param' in s, "the deepen fact must include param"
