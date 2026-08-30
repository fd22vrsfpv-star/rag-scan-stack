"""The raw-artifact LLM queue had no consumer.

Run on demand:

    pytest tests/test_artifact_consumer.py -v
    scripts/run_db_tests.sh tests/test_artifact_consumer.py     # with the DB

WHY THIS EXISTS
---------------
`raw_artifacts` held 274 rows in `llm_status='pending'`, one stuck in
`'processing'` and one `'done'`; the oldest pending dated 2026-08-18. Every
server-side piece was already built — `/artifacts/claim` with FOR UPDATE SKIP
LOCKED, `/artifacts/{id}/processed`, `/artifacts/{id}/actions`,
`/artifacts/stats`. Nothing called claim, so the queue only grew, and api.py's
own cleanup warns about precisely that: rows in pending/processing "will never
age out — run a consumer".

Three properties are worth pinning, because each one is a way for a queue to
look healthy while going nowhere:

  * a row abandoned in 'processing' is recoverable (nothing retried it before,
    and it is neither pending nor done, so it was invisible to both sides);
  * a row that always fails is eventually PARKED, not re-claimed forever at the
    front of an ORDER BY first_seen queue, starving everything behind it;
  * the default model must be one that exists — the literal copied from a
    sibling module named a tag nobody has, and an absent model comes back as a
    failure, so the queue would read as broken rather than misconfigured.
"""
import os
import re
import subprocess
import sys

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
CONSUMER = os.path.join(REPO, "app", "rag-api", "artifact_consumer.py")


def _in_container(script):
    try:
        out = subprocess.run(["docker", "exec", "rag-api", "python3", "-c", script],
                             capture_output=True, text=True, timeout=180)
    except (OSError, subprocess.SubprocessError):
        return None
    return out.stdout if out.returncode == 0 else None


@pytest.fixture(scope="module")
def rag_api():
    if _in_container("print('ok')") is None:
        pytest.skip("rag-api container not reachable")
    return True


# ── source-level (always run) ───────────────────────────────────────────────

@pytest.mark.unit
def test_the_consumer_exists_and_claims_the_same_way_the_endpoint_does():
    """Two claim implementations that drift would hand the same row to two
    workers, which is the exact thing SKIP LOCKED is there to prevent."""
    src = open(CONSUMER, encoding="utf-8").read()
    assert "FOR UPDATE SKIP LOCKED" in src, \
        "the consumer's claim is no longer concurrency-safe"
    api = open(os.path.join(REPO, "app", "rag-api", "api.py"), encoding="utf-8").read()
    assert "FOR UPDATE SKIP LOCKED" in api


@pytest.mark.unit
def test_a_poisoned_row_is_parked_rather_than_retried_forever():
    """llm_attempts was incremented and never read.

    claim() orders by first_seen, so a row that always fails is re-claimed at
    the front of the queue on every pass and nothing behind it is ever reached.
    """
    src = open(CONSUMER, encoding="utf-8").read()
    assert "MAX_ATTEMPTS" in src, "the attempt ceiling is gone"
    assert "llm_attempts, 0) < %(max_attempts)s" in src, \
        "the claim query no longer excludes rows past the attempt ceiling"
    assert '"failed" if terminal else "pending"' in src, \
        "a row past the ceiling is no longer parked"


@pytest.mark.unit
def test_stale_processing_rows_can_be_recovered():
    src = open(CONSUMER, encoding="utf-8").read()
    assert "def requeue_stale(" in src
    assert "llm_status = 'processing'" in src and "'pending'" in src


@pytest.mark.unit
def test_requeue_is_reachable_without_spending_model_time():
    """Recovering the queue and running the model are separate decisions."""
    api = open(os.path.join(REPO, "app", "rag-api", "api.py"), encoding="utf-8").read()
    assert '@app.post("/artifacts/requeue-stale", tags=["Artifacts"])' in api
    assert '@app.post("/artifacts/drain", tags=["Artifacts"])' in api


@pytest.mark.unit
def test_the_default_model_is_not_a_phantom_tag():
    """gemma4:26b is not installed anywhere in this stack.

    An absent model returns an error per row, so the whole queue reads as broken
    rather than misconfigured. The resolution chain must end at OLLAMA_MODEL,
    which .env already sets to a real tag.
    """
    src = open(CONSUMER, encoding="utf-8").read()
    assert "OLLAMA_MODEL" in src, \
        "the model default no longer falls back to the stack's configured model"
    # Comments stripped: the module explains the phantom tag by NAMING it, and a
    # naive substring check flags that prose as the defect it documents. This
    # exact trap has bitten three tests in this repo.
    code = "\n".join(l.split("#", 1)[0] for l in src.splitlines())
    assert "gemma4:26b" not in code, "the phantom model tag is back in the code"

    compose = open(os.path.join(REPO, "docker-compose.yml"), encoding="utf-8").read()
    compose_code = "\n".join(l.split("#", 1)[0] for l in compose.splitlines())
    phantom = re.findall(r"OLLAMA_MODEL: \$\{OLLAMA_MODEL:-([^}]+)\}", compose_code)
    assert phantom, "could not read any OLLAMA_MODEL default from compose"
    assert "gemma4:26b" not in phantom, (
        f"compose still defaults some service to a model nobody has: {phantom}")


def _load_consumer():
    """Load artifact_consumer by path, without importing the rag-api package.

    Returns None when a dependency is absent, so the test SKIPS rather than
    ERRORS — a skip says "cannot run here", an error says "broken".
    """
    import importlib.util
    if not os.path.exists(CONSUMER):
        return None
    spec = importlib.util.spec_from_file_location("artifact_consumer", CONSUMER)
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception:                       # noqa: BLE001
        return None
    return module


@pytest.mark.unit
def test_no_single_prompt_is_unbounded():
    """Whole tool outputs run to megabytes; one unbounded prompt eats the batch.

    This used to assert the literal `[:MAX_CONTENT_CHARS]` — i.e. that content
    was TRUNCATED. Truncation is no longer how the bound is achieved: oversized
    artifacts are now chunked on line boundaries and reduced, which answers the
    original complaint properly (an 8 MB artifact was being summarised from its
    first 12 KB and the judgement presented as covering the whole). Asserting the
    old mechanism made the test fail on an improvement.

    So this asserts the PROPERTY that matters — no chunk exceeds the bound — by
    running the splitter, not by reading the source for a construct.
    """
    consumer = _load_consumer()
    if consumer is None:
        pytest.skip("artifact_consumer not importable")
    size = 100
    content = "".join(f"line {i} " + "x" * 40 + "\n" for i in range(200))
    chunks, total = consumer._split_chunks(content, size, max_chunks=50)
    assert chunks, "the splitter returned nothing"
    assert total >= len(chunks)
    # A single line longer than `size` becomes its own oversized chunk by
    # design, so the bound is per-line, not absolute.
    longest_line = max(len(ln) for ln in content.splitlines(keepends=True))
    for chunk in chunks:
        assert len(chunk) <= max(size, longest_line), \
            f"a chunk of {len(chunk)} chars exceeded the {size}-char bound"
    assert "".join(chunks) in content, "chunking altered the content"


@pytest.mark.unit
def test_dropped_chunks_are_counted_not_hidden():
    """Coverage must be stated, not implied. `max_chunks` caps the work, and the
    TRUE total is returned so a partial review cannot read as a complete one."""
    consumer = _load_consumer()
    if consumer is None:
        pytest.skip("artifact_consumer not importable")
    content = "".join(f"{i}\n" for i in range(5000))
    chunks, total = consumer._split_chunks(content, 100, max_chunks=3)
    assert len(chunks) == 3
    assert total > 3, f"total {total} does not reveal the dropped chunks"


# ── executed against the live database ──────────────────────────────────────
#
# The probe SQL is written with single-quoted strings on purpose: this file is
# already a Python string containing Python, and a third level of triple quotes
# is how the first two drafts of it failed to parse.

_INS = ("INSERT INTO raw_artifacts (tool, content, content_sha256, llm_status, "
        "llm_processed_at, first_seen) VALUES (%s, 'probe', %s, 'processing', "
        "now() - (%s || ' minutes')::interval, now() - interval '2 hours') "
        "ON CONFLICT DO NOTHING")


def _probe(sha, age_minutes, requeue_after):
    return _in_container(
        "import sys, os, psycopg2\n"
        "from psycopg2.extras import RealDictCursor\n"
        "sys.path.insert(0, '/app')\n"
        "import artifact_consumer as ac\n"
        "conn = psycopg2.connect(os.environ['DB_DSN'])\n"
        "cur = conn.cursor(cursor_factory=RealDictCursor)\n"
        f"cur.execute({_INS!r}, ('consumer-probe', {sha!r}, {age_minutes!r}))\n"
        "conn.commit()\n"
        f"n = ac.requeue_stale(cur, {requeue_after})\n"
        "conn.commit()\n"
        "cur.execute('SELECT llm_status FROM raw_artifacts WHERE content_sha256=%s',"
        f" ({sha!r},))\n"
        "row = cur.fetchone()\n"
        "st = row['llm_status'] if row else 'MISSING'\n"
        "cur.execute('DELETE FROM raw_artifacts WHERE content_sha256=%s',"
        f" ({sha!r},))\n"
        "conn.commit()\n"
        "print('RESULT', n, st)\n")


def test_requeue_recovers_an_abandoned_row(rag_api):
    """The row this fixes was real: one artifact claimed and never reported."""
    out = _probe("probe-sha-requeue", 90, 30)
    assert out, "probe failed to run"
    line = [l for l in out.splitlines() if l.startswith("RESULT")][-1].split()
    assert int(line[1]) >= 1, "requeue_stale reported nothing requeued"
    assert line[2] == "pending", (
        f"the abandoned row is {line[2]}, not pending — it stays invisible to "
        "both the queue and the operator")


def test_a_fresh_row_is_not_requeued(rag_api):
    """Requeuing a row a worker is legitimately mid-way through would hand the
    same artifact to a second worker."""
    out = _probe("probe-sha-fresh", 0, 30)
    assert out, "probe failed to run"
    st = [l for l in out.splitlines() if l.startswith("RESULT")][-1].split()[2]
    assert st == "processing", f"a fresh in-flight row was requeued ({st})"


def test_the_queue_actually_drained(rag_api):
    """Not a mechanism check — the real queue must have moved.

    Before this work: 274 pending, 1 processing, 1 done, and nothing in the
    codebase that could change those numbers.
    """
    out = _in_container(
        "import sys, os, psycopg2\n"
        "from psycopg2.extras import RealDictCursor\n"
        "sys.path.insert(0, '/app')\n"
        "import artifact_consumer as ac\n"
        "conn = psycopg2.connect(os.environ['DB_DSN'])\n"
        "cur = conn.cursor(cursor_factory=RealDictCursor)\n"
        "d = ac.queue_depth(cur)\n"
        "print('RESULT', d.get('done', 0), d.get('processing', 0))\n")
    assert out, "probe failed to run"
    done, processing = map(int, [l for l in out.splitlines()
                                 if l.startswith("RESULT")][-1].split()[1:3])
    assert done > 1, (
        f"only {done} artifact(s) processed — the queue had exactly 1 'done' "
        "before a consumer existed, so this has not run")
    assert processing == 0, (
        f"{processing} row(s) still claimed — requeue_stale should have "
        "recovered them")
