import logging
from fastapi import APIRouter, Request
from ws_hub import hub

log = logging.getLogger("webhook_receiver")
router = APIRouter()


@router.post("/api/webhooks/receive")
async def receive_webhook(request: Request):
    """Receive webhook events from RAG API and broadcast to WS clients."""
    body = await request.json()
    event_type = body.get("event_type", "unknown")
    severity = body.get("severity", "info")
    data = body.get("data", {})
    source = body.get("source", "unknown")

    log.info("Webhook received: %s from %s (severity=%s)", event_type, source, severity)

    await hub.broadcast(event_type, {"source": source, "severity": severity, **data})

    if event_type == "finding_high" or severity in ("critical", "high"):
        await hub.broadcast("finding_critical", {"source": source, **data})

    return {"ok": True}
