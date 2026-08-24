"""Per-tool extraction specs: the loader, the predicates, and the safety rules.

Run on demand:

    pytest tests/test_extractor_specs.py -v

WHY THIS EXISTS
---------------
94.2% of `recon_findings` (98 of 104 rows, 17 tools) are generic dumps —
`finding_type='tool_output'` or `'tool_table_row'` with `key_values` EMPTY. The
text is captured and nothing says what it MEANS. One enum4linux-ng run discloses
35 usernames through a null session, SMB1-only dialects and signing not
required; 47 such runs, none interpreted.

Two real bugs in the first version of this loader are pinned below, because both
failed SILENTLY in the way that matters — the feature appeared to work and
simply produced fewer findings:

  * `remaining_hours > 24` did not parse, because the grammar had `len(x) > n`
    but no plain numeric comparison. hydra's "this run could never finish" rule
    never fired. Only the loader's problem list revealed it.
  * a `boolean` field whose regex has NO capture group matched, then evaluated
    its own matched sentence against a truthy-word list and yielded False. The
    null-session finding — the highest-severity fact in the run — was lost.

SAFETY
------
`knowledge/` is an operator-editable bind mount. `eval()` on a `when:`
expression there would be arbitrary code execution from a data file, so
predicates go through a restricted parser that understands a fixed grammar and
nothing else. That is tested directly.
"""
import os
import sys

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
for path in (REPO, os.path.join(REPO, "app", "rag-api")):
    if path not in sys.path:
        sys.path.insert(0, path)

pytest.importorskip("yaml", reason="pyyaml not installed")
es = pytest.importorskip("extractor_specs", reason="extractor_specs not importable")

SPEC_DIR = os.path.join(REPO, "knowledge", "extractors")


# ── the specs actually on disk ──────────────────────────────────────────────

@pytest.mark.unit
def test_the_shipped_specs_all_load_without_problems():
    """A spec error must be visible. This is the check that caught the
    unparsable `remaining_hours > 24`."""
    specs, problems = es.load_specs(SPEC_DIR, force=True)
    assert not problems, f"spec problems: {problems}"
    assert specs, "no specs loaded at all"


@pytest.mark.unit
def test_both_tools_resolve_including_aliases():
    es.load_specs(SPEC_DIR, force=True)
    assert es.spec_for("enum4linux-ng", SPEC_DIR)
    assert es.spec_for("hydra", SPEC_DIR)
    assert es.spec_for("MEDUSA", SPEC_DIR), "aliases must resolve, case-insensitively"


@pytest.mark.unit
def test_every_notable_rule_uses_a_known_severity():
    """CLAUDE.md: one severity scale. A spec inventing 'severe' sorts as unknown."""
    from etl.severity import severity_rank
    specs, _ = es.load_specs(SPEC_DIR, force=True)
    for spec in set(id(s) for s in specs.values()) and specs.values():
        for rule in spec.get("notable") or []:
            assert severity_rank(rule["severity"]) > 0, (
                f"{spec['_source_file']} rule {rule['id']} uses unknown severity "
                f"{rule['severity']!r}")


@pytest.mark.unit
def test_every_notable_predicate_references_a_schema_field():
    """A rule watching a field the schema never produces can never fire."""
    specs, _ = es.load_specs(SPEC_DIR, force=True)
    for spec in specs.values():
        fields = set(spec.get("schema") or {})
        for rule in spec.get("notable") or []:
            parsed = es._parse_predicate(rule["when"])
            assert parsed, f"{rule['id']}: unparsable {rule['when']!r}"
            field = parsed[1]["f"].split(".")[0]
            assert field in fields, (
                f"{spec['_source_file']} rule {rule['id']} watches {field!r}, "
                f"which is not in its schema")


# ── the predicate grammar ───────────────────────────────────────────────────

@pytest.mark.unit
@pytest.mark.parametrize("expr,data,expected", [
    ("null_session == true", {"null_session": True}, True),
    ("null_session == true", {"null_session": False}, False),
    ("signing_required == false", {"signing_required": False}, True),
    ("len(users) > 0", {"users": ["a"]}, True),
    ("len(users) > 0", {"users": []}, False),
    ("len(users) >= 2", {"users": ["a", "b"]}, True),
    ("remaining_hours > 24", {"remaining_hours": 15875}, True),
    ("remaining_hours > 24", {"remaining_hours": 2}, False),
    ("rate_per_min <= 300", {"rate_per_min": 256.0}, True),
    ("restore_file_written", {"restore_file_written": True}, True),
    ("not restore_file_written", {"restore_file_written": False}, True),
    ("service != 'ssh'", {"service": "ftp"}, True),
])
def test_predicate_forms(expr, data, expected):
    assert es.evaluate_predicate(expr, data) is expected


@pytest.mark.unit
def test_numeric_comparison_parses_at_all():
    """The exact omission that silenced hydra's 'cannot finish' rule."""
    assert es._parse_predicate("remaining_hours > 24") is not None


@pytest.mark.unit
def test_a_missing_field_never_matches():
    """A predicate on an absent field must be False, not an exception and not
    an accidental truthy."""
    for expr in ("remaining_hours > 24", "len(users) > 0", "null_session == true",
                 "restore_file_written"):
        assert es.evaluate_predicate(expr, {}) is False, expr


@pytest.mark.unit
def test_predicates_do_not_execute_code():
    """The injection guard. `knowledge/` is operator-editable, so an expression
    there must never reach an interpreter."""
    marker = os.path.join(REPO, ".pytest-extractor-injection-probe")
    hostile = f"__import__('pathlib').Path({marker!r}).write_text('pwned')"
    assert es._parse_predicate(hostile) is None, \
        "a code expression parsed as a predicate"
    assert es.evaluate_predicate(hostile, {}) is False
    assert not os.path.exists(marker), "the predicate evaluator EXECUTED code"


@pytest.mark.unit
def test_an_unparsable_predicate_is_a_reported_spec_error():
    problems = es._validate_spec(
        {"tool": "x", "prompt": "p", "schema": {"a": {"type": "list"}},
         "notable": [{"id": "r", "when": "a ~= 3", "severity": "high",
                      "title": "t"}]}, "bad.yaml")
    assert any("unparsable" in p for p in problems), problems


# ── the deterministic pre-pass ──────────────────────────────────────────────

E4L = """[+] Got domain/workgroup name: WORKGROUP
SMB1 only: true
SMB signing required: false
NetBIOS computer name: METASPLOITABLE
DNS domain: localdomain
FQDN: metasploitable.localdomain
[+] Server allows authentication via username '' and password ''
OS: Linux/Unix (Samba 3.0.20-Debian)
[+] After merging user results we have 3 user(s) total:
'1000':
  username: root
  name: root
'1002':
  username: daemon
'1004':
  username: bin
"""


@pytest.mark.unit
def test_presence_pattern_with_no_capture_group_means_true():
    """The second silent bug. Without this, null_session came back False on
    output that plainly states the null session was accepted."""
    spec = es.spec_for("enum4linux-ng", SPEC_DIR)
    got = es.run_deterministic(spec, E4L)
    assert got.get("null_session") is True, \
        "a presence pattern evaluated its own matched text and yielded False"


@pytest.mark.unit
def test_users_are_collected_as_a_list():
    spec = es.spec_for("enum4linux-ng", SPEC_DIR)
    got = es.run_deterministic(spec, E4L)
    assert got["users"] == ["root", "daemon", "bin"], got.get("users")
    assert got["user_count"] == 3


@pytest.mark.unit
def test_declared_booleans_read_their_captured_value():
    spec = es.spec_for("enum4linux-ng", SPEC_DIR)
    got = es.run_deterministic(spec, E4L)
    assert got["smb1_only"] is True
    assert got["signing_required"] is False, \
        "'false' in the text must not become True"


@pytest.mark.unit
def test_the_null_session_finding_fires_on_real_output():
    spec = es.spec_for("enum4linux-ng", SPEC_DIR)
    notable = es.notable_from(spec, es.run_deterministic(spec, E4L))
    ids = {n["id"] for n in notable}
    assert "e4l_null_session" in ids, ids
    assert "e4l_users_enumerated" in ids
    high = [n for n in notable if n["severity"] == "high"]
    assert high, "the null session must be high severity"


@pytest.mark.unit
def test_title_interpolation_uses_the_count_not_the_list():
    spec = es.spec_for("enum4linux-ng", SPEC_DIR)
    notable = es.notable_from(spec, es.run_deterministic(spec, E4L))
    users = [n for n in notable if n["id"] == "e4l_users_enumerated"][0]
    assert users["title"].startswith("3 usernames"), users["title"]


HYDRA = """[DATA] max 16 tasks per 1 server, overall 16 tasks, 243854783 login tries (l:17/p:14344399), ~15240924 tries per task
[STATUS] 256.00 tries/min, 256 tries in 00:01h, 243854527 to do in 15875:57h, 16 active
0 of 1 target completed, 0 valid password found
[INFO] Writing restore file because 2 server scans could not be completed
"""


@pytest.mark.unit
def test_hydra_run_that_could_never_finish_is_flagged():
    spec = es.spec_for("hydra", SPEC_DIR)
    got = es.run_deterministic(spec, HYDRA)
    assert got["remaining_hours"] == 15875
    assert got["total_tries"] == 243854783
    assert got["restore_file_written"] is True
    ids = {n["id"] for n in es.notable_from(spec, got)}
    assert "hydra_run_cannot_finish" in ids, ids
    assert "hydra_restore_file_left" in ids
    assert "hydra_credentials_recovered" not in ids, \
        "0 valid passwords must not report a recovered credential"


# ── result validation ───────────────────────────────────────────────────────

@pytest.mark.unit
def test_a_wrong_typed_field_is_dropped_not_coerced():
    """Coercing `users: "35"` into `["35"]` would store a confident lie."""
    spec = {"schema": {"users": {"type": "list"}}}
    cleaned, problems = es.validate_result(spec, {"users": "35"})
    assert "users" not in cleaned
    assert any("should be list" in p for p in problems), problems


@pytest.mark.unit
def test_an_unknown_field_is_reported_and_dropped():
    spec = {"schema": {"users": {"type": "list"}}}
    cleaned, problems = es.validate_result(spec, {"invented": 1})
    assert cleaned == {}
    assert any("unexpected field" in p for p in problems)


@pytest.mark.unit
def test_a_correctly_typed_field_survives():
    spec = {"schema": {"users": {"type": "list"}, "os": {"type": "string"}}}
    cleaned, problems = es.validate_result(spec, {"users": ["a"], "os": "Linux"})
    assert cleaned == {"users": ["a"], "os": "Linux"}
    assert not problems


@pytest.mark.unit
def test_a_non_object_result_is_rejected():
    cleaned, problems = es.validate_result({"schema": {}}, ["not", "a", "dict"])
    assert cleaned == {} and problems


# ── loader robustness ───────────────────────────────────────────────────────

@pytest.mark.unit
def test_a_missing_spec_dir_returns_empty_not_an_exception():
    specs, problems = es.load_specs("/nonexistent/extractors", force=True)
    assert specs == {}


@pytest.mark.unit
def test_signature_is_content_based_not_mtime():
    """A bind mount can rewrite a file without changing mtime, and a copy can
    change mtime without changing a byte. mtime answers the wrong question."""
    import inspect
    src = inspect.getsource(es.signature)
    assert "st_mtime" not in src and "getmtime" not in src, \
        "the spec signature is back to using mtime"


@pytest.mark.unit
def test_deterministic_fields_are_marked_settled_in_the_prompt():
    """The model must not be invited to contradict a regex that read the text."""
    spec = es.spec_for("enum4linux-ng", SPEC_DIR)
    prompt = es.build_prompt(spec, "enum4linux-ng", "192.168.1.150", 445,
                             "enum4linux-ng -A h", "output here",
                             already={"users": ["root"]})
    assert "settled" in prompt.lower()
    assert "root" in prompt
