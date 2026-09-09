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
