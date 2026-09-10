"""The default webhooks must survive being registered before the schema exists.

Run on demand:

    pytest tests/test_webhook_registration.py -v

WHY THIS EXISTS
---------------
Found by the first rehearsal of install phases 6-10. `post-install-check.sh`
reported

    [FAIL] Webhook: event-log not registered
    [FAIL] Webhook: dashboard-bff not registered

on a completed fresh install, even though `ensure_default_webhook()` creates
both. The ordering is the whole story:

* phase 6 starts the services, so rag-api runs its startup hook;
* phase 7 creates the `webhooks` table.

So the one and only registration attempt happened while the table did not
exist. `ensure_default_webhook()` caught the exception, logged it, returned
nothing, and was never called again — so neither webhook existed for the life
of the install. Every `POST /webhooks/emit` was then answered **200 and
discarded** (the event types are an allow-list held in the webhook row), so
`webhook_events` stayed empty and so did the Agent Activity timeline. Nothing
in the running system reports that state; only the post-install check does.

The fix is a bounded background retry, and these are the two properties that
make it work: the function has to report failure instead of swallowing it, and
the caller has to retry rather than assume one attempt is enough.

Static — reads the source, no rag-api import (it needs fastapi and the app
package) and no database.
"""
import ast
import os
import re

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
ROUTER = os.path.join(REPO, "app", "rag-api", "webhooks", "router.py")
API = os.path.join(REPO, "app", "rag-api", "api.py")


def _read(path):
    if not os.path.exists(path):
        pytest.skip(f"{os.path.relpath(path, REPO)} not present")
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def _function_source(text, name):
    """Source of a top-level def, from its line to the next top-level one.

    `async def` included: the startup/shutdown hooks and the retry loop are all
    coroutines, and a matcher that only knew `def` reported them as MISSING —
    which these guards correctly treat as a failure rather than passing
    vacuously.
    """
    m = re.search(rf"^(?:async )?def {re.escape(name)}\(", text, re.M)
    assert m, f"{name}() not found — this guard would pass vacuously"
    nxt = re.search(r"^(?:async def |def |class |@app\.)", text[m.end():], re.M)
    return text[m.start():m.end() + (nxt.start() if nxt else len(text))]


def test_registration_reports_failure_instead_of_swallowing_it():
    """A caller cannot retry what it is not told about.

    The original `except Exception: log.error(...)` returned None on both the
    success and failure paths, so the startup hook could not tell "registered"
    from "the table does not exist yet".
    """
    body = _function_source(_read(ROUTER), "ensure_default_webhook")
    assert "return False" in body, (
        "ensure_default_webhook() does not return False on failure, so its "
        "caller cannot know to retry"
    )
    assert "return True" in body, (
        "ensure_default_webhook() does not return True on success, so a caller "
        "that checks the result would retry forever"
    )
    # The failure path must not be the last word.
    tail = body[body.index("except"):]
    assert "return False" in tail, (
        "the exception handler does not return False — the failure is still "
        "being swallowed"
    )


def test_startup_retries_when_registration_cannot_succeed_yet():
    """On a fresh install the first attempt necessarily fails: rag-api starts in
    phase 6 and the webhooks table is created in phase 7."""
    text = _read(API)
    startup = _function_source(text, "startup_event")
    assert "ensure_default_webhook()" in startup, (
        "startup_event no longer registers the default webhooks"
    )
    assert re.search(r"if\s+ensure_default_webhook\(\)", startup) or \
           re.search(r"if\s+not\s+ensure_default_webhook\(\)", startup), (
        "startup_event calls ensure_default_webhook() and ignores its result, "
        "so a first attempt that fails is the only attempt — exactly the "
        "defect this file exists for"
    )
    assert "_retry_default_webhooks" in startup, (
        "no retry is scheduled when registration fails"
    )

    retry = _function_source(text, "_retry_default_webhooks")
    assert "ensure_default_webhook()" in retry, (
        "_retry_default_webhooks does not call ensure_default_webhook()"
    )
    assert "return" in retry, "the retry loop never stops on success"
    assert "log.error" in retry, (
        "giving up is not logged as an error. At that point events really are "
        "being accepted and discarded, which is worse than a noisy log"
    )


def test_the_retry_is_bounded():
    """An unbounded retry loop is a leak, and it hides a genuinely broken
    schema behind a log line that never comes."""
    retry = _function_source(_read(API), "_retry_default_webhooks")
    assert not re.search(r"while\s+True", retry), (
        "_retry_default_webhooks loops forever; it must give up and say so"
    )
    m = re.search(r"attempts:\s*int\s*=\s*(\d+),\s*delay:\s*float\s*=\s*([\d.]+)", retry)
    assert m, "no bounded (attempts, delay) signature on _retry_default_webhooks"
    attempts, delay = int(m.group(1)), float(m.group(2))
    window = attempts * delay
    # Phase 6 -> phase 7 is a container start plus a schema apply. Two minutes
    # is comfortably longer than that; a 20-second window would expire first
    # and reintroduce the defect with extra steps.
    assert window >= 120, (
        f"the retry window is only {window:.0f}s ({attempts} x {delay:.0f}s), "
        "which can expire before phase 7 creates the webhooks table"
    )


def test_the_retry_task_is_cancelled_on_shutdown():
    """A task left sleeping through shutdown logs its give-up error into a
    process that is already gone."""
    text = _read(API)
    shutdown = _function_source(text, "shutdown_event")
    assert "_webhook_registration_task" in shutdown, (
        "shutdown_event does not cancel the webhook-registration retry task"
    )
    assert ".cancel()" in shutdown


def test_the_task_global_is_declared():
    """`global X` inside the hook does not create the module attribute; without
    a module-level binding the first read raises NameError at startup."""
    text = _read(API)
    assert re.search(r"^_webhook_registration_task\s*=\s*None", text, re.M), (
        "_webhook_registration_task has no module-level declaration"
    )

# ── The event-log sink must filter NOTHING ─────────────────────────────────
#
# dispatcher.emit_webhook:
#
#     if webhook["event_types"] and event_type not in webhook["event_types"]:
#         continue
#
# So an EMPTY event_types matches everything. The `event-log` webhook is the
# internal audit sink and is supposed to be exactly that — its own docstring
# says "catch-all" — but ensure_default_webhook used to write a hand-maintained
# 44-entry list into it, which made it an ALLOW-LIST.
#
# A repo-wide scan on 2026-09-09 found **113** literal event types that were
# emitted and not on that list: agent_scan_completed, artifacts_pruned,
# bulk_check_completed, credential_bridge_completed and 109 more. Every one was
# accepted with HTTP 200 and discarded — nothing in webhook_events, nothing on
# the Agent Activity timeline, no error. Two sessions have chased an empty
# timeline caused by it.
#
# Completing the list would have worked until the next emitter was written, so
# the list is gone. These pin the property that replaces it.
def test_the_event_log_webhook_filters_nothing():
    src = _read(ROUTER)
    assert "_ALL_EVENT_TYPES" not in src, (
        "the event-type allow-list is back. It cannot be kept correct by hand: "
        "the last attempt left 113 emitted event types silently dropped"
    )
    # Created with no filter. Scoped to ensure_default_webhook(): a loose
    # search matched the generic create-webhook endpoint's INSERT 14,000
    # characters earlier and asserted nothing about this one.
    fn = _function_source(src, "ensure_default_webhook")
    assert "(_DEFAULT_WEBHOOK_NAME, _SELF_SINK_URL)" in fn, (
        "the event-log INSERT still passes an event_types argument; it takes "
        "the name and URL only, so the column stays NULL and the sink records "
        "every event type"
    )
    assert "VALUES (%s, %s, NULL, true, NULL, NULL, NULL, 0, 3000)" in fn, (
        "the event-log row is not created with a NULL event_types column"
    )
    # ...and any filter on an existing row is cleared, because deployments that
    # already ran the old code carry the stale 44-entry array.
    assert re.search(r"UPDATE webhooks SET event_types = NULL\s+WHERE name = %s",
                     src), (
        "ensure_default_webhook does not clear a stale event_types filter, so "
        "existing installs keep dropping what the old list did not name"
    )


def test_the_bff_webhook_keeps_its_filter():
    """The catch-all change must not leak into the operator-facing webhooks.

    The dashboard pushes a deliberately small set to the browser over its
    WebSocket; making THAT a catch-all would flood the UI. Filtering belongs on
    configured webhooks, recording belongs on the sink.
    """
    src = _read(ROUTER)
    m = re.search(r"_BFF_EVENT_TYPES\s*=\s*\[(.*?)\]", src, re.S)
    assert m, "_BFF_EVENT_TYPES is gone — the dashboard webhook now has no filter"
    types = re.findall(r'"([a-z0-9_]+)"', m.group(1))
    assert 2 <= len(types) <= 12, (
        f"the BFF webhook filters {len(types)} event types; that list is meant "
        "to stay small and deliberate"
    )


def test_the_rag_backfill_emits_its_own_event():
    """A backfill rewrites a shared corpus. CLAUDE.md wants that on the
    timeline, and the emit has to name a type the allow-list carries."""
    tool = os.path.join(REPO, "etl", "backfill_rag_documents.py")
    if not os.path.exists(tool):
        pytest.skip("etl/backfill_rag_documents.py not present")
    src = _read(tool)
    assert "webhooks/emit" in src, (
        "the backfill does not emit a webhook event, so a corpus rewrite leaves "
        "no audit trail"
    )
    assert "maintenance_rag_backfilled" in src, (
        "the backfill emits some other event type than the allow-listed one"
    )


def test_the_rag_backfill_does_not_embed_in_process():
    """No container in this stack has BOTH sentence_transformers and psycopg2 —
    the embedder image has the model and no driver, everything else has the
    driver and no model. That is why the predecessor could not run anywhere."""
    tool = os.path.join(REPO, "etl", "backfill_rag_documents.py")
    if not os.path.exists(tool):
        pytest.skip("etl/backfill_rag_documents.py not present")
    # Parsed, not grepped: this file's own docstring NAMES
    # sentence_transformers while explaining why it does not use it, and a
    # text scan failed on that immediately. Comments and docstrings must never
    # be able to trip a guard — the same trap this session hit three times.
    tree = ast.parse(_read(tool))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert "sentence_transformers" not in imported, (
        "the backfill imports sentence_transformers, i.e. loads the embedding "
        "model in-process. It must POST to the embedder service, which is also "
        "the only place the model version is defined"
    )
    calls = {getattr(n.func, "id", None) or getattr(n.func, "attr", None)
             for n in ast.walk(tree) if isinstance(n, ast.Call)}
    assert "SentenceTransformer" not in calls, (
        "the backfill instantiates SentenceTransformer directly"
    )
    assert "/embed" in _read(tool), "the backfill does not call the embedder service"


def test_the_rag_backfill_is_idempotent():
    """The predecessor appended chunks, so a second run doubled the corpus."""
    tool = os.path.join(REPO, "etl", "backfill_rag_documents.py")
    if not os.path.exists(tool):
        pytest.skip("etl/backfill_rag_documents.py not present")
    src = _read(tool)
    assert re.search(r"DELETE FROM public\.rag_documents", src), (
        "no delete before insert — re-running would append a second copy of "
        "every chunk"
    )
    assert "row_id" in src and "'source'" in src, (
        "the delete is not keyed on (source, row_id), so it cannot target just "
        "the rows being rewritten"
    )
