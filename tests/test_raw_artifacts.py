"""Native JSON output selection and the raw-artifact archive.

Run on demand:

    pytest tests/test_raw_artifacts.py -v

Two features are covered, because they are two halves of the same problem:
nothing downstream can analyse output that was either mangled on the way in or
never kept at all.

1. NATIVE JSON. Inferring structure from CLI text goes wrong badly — the table
   strategy read crackmapexec's whitespace-aligned SMB banner as a header row,
   so the DATA became the COLUMN NAMES. Where a tool can emit JSON itself, that
   is authoritative. Every flag asserted here was read off `--help` inside the
   kali-listener image, not assumed.

2. THE ARCHIVE. Output used to be lossy in three places at once: only the kali
   path wrote tool_executions.output at all, native JSON files were read then
   UNLINKED, and the parser keeps 8 KB per finding. The artifact store is the
   source of truth those derive from, and carries the LLM processing queue.

DB tests skip cleanly when no rag-postgres is reachable.
"""
import hashlib
import os
import sys
import uuid

import pytest

_LISTENER = os.path.join(os.path.dirname(__file__), "..", "kali_listener",
                         "listener_service.py")


def _load_json_output():
    """Extract apply_json_output from source rather than importing the module.

    Importing listener_service drags in fastapi and the rest of the service, so
    a plain `pytest tests/` on a laptop skipped all of this silently. The flag
    logic is self-contained, so lifting just that segment keeps these runnable
    anywhere — which is the point of saving them.
    """
    if not os.path.exists(_LISTENER):           # pragma: no cover
        pytest.skip("listener_service.py not present")
    src = open(_LISTENER).read()
    try:
        seg = src[src.index("JSON_CAPABLE = {"):src.index("async def execute_tool")]
    except ValueError:                          # pragma: no cover
        pytest.skip("apply_json_output not found in listener_service.py")
    ns = {"uuid": uuid}
    exec(seg, ns)
    return ns["apply_json_output"]


def _apply(tool, cmd):
    return _load_json_output()(tool, cmd)


def test_nuclei_uses_stdout_jsonl():
    """nuclei is the ONLY one of these that writes JSON to stdout."""
    cmd, path = _apply("nuclei", "nuclei -u http://x")
    assert "-jsonl" in cmd
    assert path is None, "nuclei streams to stdout; no file should be expected"


@pytest.mark.parametrize("tool,flag", [
    ("whatweb", "--log-json="),
    ("enum4linux-ng", "-oJ "),
    ("dnsrecon", "--json "),
    ("sqlmap", "--report-json="),
])
def test_file_mode_tools_get_a_path(tool, flag):
    """These write to a FILE, so a path must come back to be read and archived."""
    cmd, path = _apply(tool, f"{tool} target")
    assert flag in cmd, f"{tool} missing {flag}: {cmd}"
    assert path, f"{tool} must return a path for the caller to read back"


def test_enum4linux_ng_path_accounts_for_appended_suffix():
    """enum4linux-ng appends .json itself. Expecting the bare path would mean
    the file is never found and the native JSON silently lost."""
    cmd, path = _apply("enum4linux-ng", "enum4linux-ng -A 10.0.0.1")
    assert path.endswith(".json")
    bare = path[:-len(".json")]
    assert f"-oJ {bare}" in cmd


def test_tool_without_json_support_is_untouched():
    """crackmapexec/netexec/nikto have no JSON option in this image. Appending
    an unsupported flag would fail the whole run — worse than parsing text."""
    for tool in ("crackmapexec", "netexec", "nikto"):
        cmd, path = _apply(tool, f"{tool} smb 10.0.0.1")
        assert cmd == f"{tool} smb 10.0.0.1"
        assert path is None


def test_explicit_json_choice_is_respected():
    """An operator who already asked for JSON must not get a second flag."""
    cmd, path = _apply("whatweb", "whatweb --log-json=/tmp/mine.json http://x")
    assert cmd.count("--log-json") == 1
    assert path is None


def test_paths_are_unique_per_invocation():
    """Two concurrent runs of the same tool must not share an output file."""
    _, a = _apply("whatweb", "whatweb http://x")
    _, b = _apply("whatweb", "whatweb http://x")
    assert a != b


# ── 2. Content format detection ───────────────────────────────────────────

def _detect(text):
    import importlib.util
    api = os.path.join(os.path.dirname(__file__), "..", "app", "rag-api", "api.py")
    if not os.path.exists(api):                 # pragma: no cover
        pytest.skip("api.py not present")
    import json as _json
    import re
    src = open(api).read()
    m = re.search(r"def _detect_content_format\(text: str\) -> str:.*?\n    return \"text\"\n",
                  src, re.S)
    if not m:                                   # pragma: no cover
        pytest.skip("_detect_content_format not found")
    ns = {"json": _json}
    exec("def _detect_content_format(text):\n" + m.group(0).split("\n", 1)[1], ns)
    return ns["_detect_content_format"](text)


@pytest.mark.parametrize("text,expected", [
    ('{"a": 1}', "json"),
    ('[{"a": 1}]', "json"),
    ('{"a":1}\n{"b":2}', "jsonl"),          # nuclei -jsonl
    ('<?xml version="1.0"?><root/>', "xml"),
    ("SMB 10.0.0.1 445 HOST [*] Unix", "text"),
    ("", "empty"),
])
def test_content_format_detection(text, expected):
    assert _detect(text) == expected


def test_jsonl_is_checked_before_plain_json():
    """A stream of per-line objects is not valid JSON as a whole. Classifying it
    as text would hide from the LLM that the payload is machine-readable."""
    assert _detect('{"template-id":"a"}\n{"template-id":"b"}') == "jsonl"


# ── 3. Archive + queue (needs a live database) ────────────────────────────

DSN = os.environ.get(
    "TEST_DB_DSN",
    os.environ.get("DB_DSN", "postgresql://app:app@localhost:5433/scans"),
)


@pytest.fixture(scope="module")
def conn():
    psycopg2 = pytest.importorskip("psycopg2")
    try:
        c = psycopg2.connect(DSN, connect_timeout=3)
    except Exception as e:                      # pragma: no cover
        pytest.skip(f"no database at {DSN}: {type(e).__name__}")
    c.autocommit = True
    yield c
    c.close()


@pytest.fixture
def cleanup(conn):
    made = []
    yield made
    with conn.cursor() as cur:
        for tool in made:
            cur.execute("DELETE FROM raw_artifacts WHERE tool = %s", (tool,))


def _store(conn, tool, content, target="10.0.0.1", native=False):
    sha = hashlib.sha256(content.encode()).hexdigest()
    with conn.cursor() as cur:
        cur.execute("""
            INSERT INTO raw_artifacts (tool, target, content, content_sha256,
                                       byte_size, native_json, source)
            VALUES (%s,%s,%s,%s,%s,%s,'test')
            ON CONFLICT (tool, COALESCE(target,''), content_sha256) DO UPDATE
               SET last_seen = now(), occurrences = raw_artifacts.occurrences + 1
            RETURNING id, (xmax = 0), occurrences
        """, (tool, target, content, sha, len(content), native))
        return cur.fetchone()


def test_table_and_queue_index_exist(conn):
    with conn.cursor() as cur:
        cur.execute("SELECT to_regclass('public.raw_artifacts')")
        assert cur.fetchone()[0] is not None, "raw_artifacts missing"
        cur.execute("SELECT indexname FROM pg_indexes WHERE tablename='raw_artifacts'")
        idx = {r[0] for r in cur.fetchall()}
    assert "uq_raw_artifacts_identity" in idx, "ON CONFLICT upsert would RAISE"
    assert "idx_raw_artifacts_llm_status" in idx, "queue scan would be unindexed"


def test_content_is_stored_untruncated(conn, cleanup):
    """The whole point: no 8 KB or 200 KB ceiling on the source of truth."""
    tool = f"t_{uuid.uuid4().hex[:8]}"
    cleanup.append(tool)
    big = "A" * 500_000
    _store(conn, tool, big)
    with conn.cursor() as cur:
        cur.execute("SELECT length(content), byte_size FROM raw_artifacts WHERE tool=%s", (tool,))
        length, size = cur.fetchone()
    assert length == 500_000, f"content truncated to {length}"
    assert size == 500_000


def test_identical_output_dedupes_and_counts(conn, cleanup):
    """Re-running an unchanged scan must not re-queue identical bytes."""
    tool = f"t_{uuid.uuid4().hex[:8]}"
    cleanup.append(tool)
    id1, new1, occ1 = _store(conn, tool, "same output")
    id2, new2, occ2 = _store(conn, tool, "same output")
    assert id1 == id2 and new1 and not new2
    assert (occ1, occ2) == (1, 2)


def test_different_targets_are_separate_artifacts(conn, cleanup):
    """Identical output from two hosts is two findings' worth of evidence."""
    tool = f"t_{uuid.uuid4().hex[:8]}"
    cleanup.append(tool)
    id1, _, _ = _store(conn, tool, "open", target="10.0.0.1")
    id2, _, _ = _store(conn, tool, "open", target="10.0.0.2")
    assert id1 != id2


def test_stdout_and_native_json_both_kept(conn, cleanup):
    """Different bytes → two rows. stdout carries warnings/timing the JSON omits."""
    tool = f"t_{uuid.uuid4().hex[:8]}"
    cleanup.append(tool)
    _store(conn, tool, "\x1b[1mApache\x1b[0m[2.2.8]", native=False)
    _store(conn, tool, '[{"plugins":{"Apache":{}}}]', native=True)
    with conn.cursor() as cur:
        cur.execute("SELECT count(*), count(*) FILTER (WHERE native_json) "
                    "FROM raw_artifacts WHERE tool=%s", (tool,))
        total, native = cur.fetchone()
    assert (total, native) == (2, 1)


def test_new_artifacts_enter_the_queue_pending(conn, cleanup):
    tool = f"t_{uuid.uuid4().hex[:8]}"
    cleanup.append(tool)
    _store(conn, tool, "fresh output")
    with conn.cursor() as cur:
        cur.execute("SELECT llm_status, llm_attempts FROM raw_artifacts WHERE tool=%s", (tool,))
        assert cur.fetchone() == ("pending", 0)


def test_repeat_does_not_reset_processed_state(conn, cleanup):
    """Already analysed bytes must not be re-queued — that is paid-for waste."""
    tool = f"t_{uuid.uuid4().hex[:8]}"
    cleanup.append(tool)
    _store(conn, tool, "output")
    with conn.cursor() as cur:
        cur.execute("UPDATE raw_artifacts SET llm_status='done' WHERE tool=%s", (tool,))
    _store(conn, tool, "output")
    with conn.cursor() as cur:
        cur.execute("SELECT llm_status, occurrences FROM raw_artifacts WHERE tool=%s", (tool,))
        assert cur.fetchone() == ("done", 2)


def test_claim_is_atomic_across_workers(conn, cleanup):
    """FOR UPDATE SKIP LOCKED: two workers take disjoint batches."""
    tool = f"t_{uuid.uuid4().hex[:8]}"
    cleanup.append(tool)
    for i in range(4):
        _store(conn, tool, f"output {i}")
    claim = """
        UPDATE raw_artifacts SET llm_status='processing', llm_attempts=llm_attempts+1
         WHERE id IN (SELECT id FROM raw_artifacts
                       WHERE llm_status='pending' AND tool=%s
                       ORDER BY created_at LIMIT 2 FOR UPDATE SKIP LOCKED)
        RETURNING id"""
    with conn.cursor() as cur:
        cur.execute(claim, (tool,))
        first = {r[0] for r in cur.fetchall()}
        cur.execute(claim, (tool,))
        second = {r[0] for r in cur.fetchall()}
    assert len(first) == 2 and len(second) == 2
    assert not (first & second), "same artifact claimed twice"
    with conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM raw_artifacts WHERE tool=%s AND llm_status='pending'", (tool,))
        assert cur.fetchone()[0] == 0


def test_llm_status_is_constrained(conn, cleanup):
    """A typo'd status must fail loudly, not create a state nothing polls."""
    psycopg2 = pytest.importorskip("psycopg2")
    tool = f"t_{uuid.uuid4().hex[:8]}"
    cleanup.append(tool)
    _store(conn, tool, "output")
    with pytest.raises(psycopg2.errors.CheckViolation):
        with conn.cursor() as cur:
            cur.execute("UPDATE raw_artifacts SET llm_status='finshed' WHERE tool=%s", (tool,))


def test_llm_result_round_trips_as_jsonb(conn, cleanup):
    tool = f"t_{uuid.uuid4().hex[:8]}"
    cleanup.append(tool)
    _store(conn, tool, "output")
    with conn.cursor() as cur:
        cur.execute("""UPDATE raw_artifacts
                          SET llm_status='done', llm_result=%s::jsonb, llm_processed_at=now()
                        WHERE tool=%s""", ('{"severity":"high","cves":["CVE-2007-2447"]}', tool))
        cur.execute("SELECT llm_result->>'severity', llm_result->'cves'->>0 "
                    "FROM raw_artifacts WHERE tool=%s", (tool,))
        assert cur.fetchone() == ("high", "CVE-2007-2447")


# ── Retention ─────────────────────────────────────────────────────────────

def test_retention_keeps_unprocessed_by_default(conn, cleanup):
    """Pruning by age alone would discard work the LLM queue was about to do.

    That loss would be invisible: the artifact simply stops existing. So the
    default keeps anything still pending or processing — which also means an
    idle queue prevents pruning entirely, the interaction /cleanup/artifacts
    reports in its response.
    """
    tool = f"t_{uuid.uuid4().hex[:8]}"
    cleanup.append(tool)
    with conn.cursor() as cur:
        for status, age in (("pending", 400), ("done", 400)):
            cur.execute("""
                INSERT INTO raw_artifacts (tool, target, content, content_sha256,
                                           byte_size, source, llm_status, created_at)
                VALUES (%s,'10.0.0.1',%s,%s,10,'test',%s, now() - interval '%s days')
            """, (tool, f"c-{status}", hashlib.sha256(status.encode()).hexdigest(),
                  status, age))
        # The query the endpoint runs, with keep_unprocessed on.
        cur.execute("""
            SELECT llm_status FROM raw_artifacts
             WHERE tool = %s AND created_at < now() - interval '90 days'
               AND llm_status <> 'pending' AND llm_status <> 'processing'
        """, (tool,))
        prunable = [r[0] for r in cur.fetchall()]
    assert prunable == ["done"], f"expected only the processed one to be prunable, got {prunable}"


def test_retention_spares_artifacts_cited_by_a_recommendation(conn, cleanup):
    """A cited artifact is the evidence behind a finding.

    Deleting it turns a cited finding into an unverifiable claim, so the age
    filter must not reach it.
    """
    from psycopg2.extras import Json
    tool = f"t_{uuid.uuid4().hex[:8]}"
    cleanup.append(tool)
    with conn.cursor() as cur:
        cur.execute("""
            INSERT INTO raw_artifacts (tool, target, content, content_sha256, byte_size,
                                       source, llm_status, created_at)
            VALUES (%s,'10.0.0.1','cited',%s,5,'test','done', now() - interval '400 days')
            RETURNING id
        """, (tool, hashlib.sha256(b"cited").hexdigest()))
        art_id = cur.fetchone()[0]
        cur.execute("""
            INSERT INTO scan_recommendations (ip, scanner, action, source, status, extra)
            VALUES ('10.0.0.1','nmap','cited-by-test','artifact','pending', %s)
        """, (Json({"artifact_id": str(art_id)}),))
        cur.execute("""
            SELECT count(*) FROM raw_artifacts
             WHERE id = %s AND created_at < now() - interval '90 days'
               AND NOT EXISTS (SELECT 1 FROM scan_recommendations r
                                WHERE r.extra->>'artifact_id' = raw_artifacts.id::text)
        """, (art_id,))
        prunable = cur.fetchone()[0]
        cur.execute("DELETE FROM scan_recommendations WHERE action = 'cited-by-test'")
    assert prunable == 0, "an artifact cited as evidence was eligible for pruning"
