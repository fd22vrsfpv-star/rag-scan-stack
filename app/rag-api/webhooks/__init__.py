"""
Webhook notification system for RAG-Scan-Stack.

This module provides webhook functionality for alerting external systems
when scans complete or high/critical severity findings are detected.
"""

from .router import router as webhook_router, ensure_default_webhook
from .dispatcher import emit_webhook, start_retry_worker, stop_retry_worker
from .models import (
    WebhookCreate,
    WebhookUpdate,
    WebhookResponse,
    WebhookEventResponse,
    EventType,
)

__all__ = [
    "webhook_router",
    "ensure_default_webhook",
    "emit_webhook",
    "start_retry_worker",
    "stop_retry_worker",
    "WebhookCreate",
    "WebhookUpdate",
    "WebhookResponse",
    "WebhookEventResponse",
    "EventType",
]
