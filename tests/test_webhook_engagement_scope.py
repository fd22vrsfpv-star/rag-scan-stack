"""An engagement-scoped webhook must only fire for its engagement's events.

Run on demand:

    pytest tests/test_webhook_engagement_scope.py -v

WHY THIS EXISTS
---------------
Webhooks had no engagement scoping: every subscription fired for every
engagement's events, so a per-client Slack/n8n webhook received another
client's findings, and the event log wasn't stamped with the engagement. A
webhook may now be scoped to one engagement (fires only for its events; NULL =
platform-wide), and emit_webhook resolves the event's engagement, filters
scoped webhooks, and stamps webhook_events.engagement_id. Fail closed: a scoped
webhook never fires for an unattributed event.

SABOTAGE PROOF
--------------
Remove the engagement filter in dispatcher.emit_webhook (or the engagement_id
column from the create INSERT) and the matching case fails.
"""
import ast
import os

import pytest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DISP = os.path.join(REPO, "app", "rag-api", "webhooks", "dispatcher.py")
ROUTER = os.path.join(REPO, "app", "rag-api", "webhooks", "router.py")
MODELS = os.path.join(REPO, "app", "rag-api", "webhooks", "models.py")


def _src(path):
    if not os.path.exists(path):
        pytest.skip(f"{path} not present")
    return open(path, encoding="utf-8").read()


def _func(path, name):
    src = _src(path)
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return ast.get_source_segment(src, node)
    return None


def test_dispatcher_filters_and_stamps_engagement():
    body = _func(DISP, "emit_webhook")
    assert body, "emit_webhook not found"
    # Resolves the event's engagement …
    assert 'data.get("engagement_id")' in body, "emit_webhook must resolve the event engagement"
    # … routes engagement-scoped webhooks (skip when the webhook is scoped and
    #    the event's engagement does not match, incl. an unattributed event) …
    assert 'webhook.get("engagement_id")' in body and "continue" in body, (
        "emit_webhook must skip a scoped webhook whose engagement != the event's")
    # … and stamps the event row.
    assert "engagement_id" in body and "INSERT INTO webhook_events" in body, (
        "webhook_events must be stamped with the engagement")


def test_create_persists_engagement_id():
    body = _func(ROUTER, "create_webhook")
    assert body and "engagement_id" in body and "webhook.engagement_id" in body, (
        "create_webhook must persist the webhook's engagement_id")


def test_emit_endpoint_passes_engagement():
    body = _func(ROUTER, "emit_webhook_event")
    assert body and "engagement_id=req.engagement_id" in body, (
        "the /emit endpoint must pass engagement_id through to the dispatcher")


def test_models_carry_engagement_id():
    src = _src(MODELS)
    # Both the config create model and the internal emit model expose it.
    assert src.count("engagement_id") >= 2, "webhook models must expose engagement_id"
