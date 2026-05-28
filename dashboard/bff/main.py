import asyncio
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from ws_hub import hub
from polling import poll_loop
from webhook_receiver import router as webhook_router
from routers.health import router as health_router
from routers.assets import router as assets_router
from routers.findings import router as findings_router
from routers.scans import router as scans_router
from routers.exploits import router as exploits_router
from routers.reports import router as reports_router
from routers.chat import router as chat_router
from routers.feedback import router as feedback_router
from routers.maintenance import router as maintenance_router
from routers.agent_sessions import router as agent_sessions_router
from routers.kb import router as kb_router
from routers.scope import router as scope_router
from routers.scope_classify import router as scope_classify_router
from routers.zap_addons import router as zap_addons_router
from routers.nodes import router as nodes_router
from routers.wordlists import router as wordlists_router
from routers.settings import router as settings_router
from routers.engagements import router as engagements_router
from routers.evidence import router as evidence_router
from routers.credentials import router as credentials_router
from routers.identities import router as identities_router
from routers.opsec import router as opsec_router
from routers.followups import router as followups_router
from routers.api_tester import router as api_tester_router
from routers.about import router as about_router
from routers.delta import router as delta_router
from routers.cloud_suggestor import router as cloud_suggestor_router
from routers.sync import router as sync_router
from routers.content_analysis import router as content_analysis_router
from routers.burp import router as burp_router
from routers.targeted_recon import router as targeted_recon_router
from routers.recon_agent import router as recon_agent_router
from routers.agents import router as agents_router
from routers.news import router as news_router
from routers.chat_presets import router as chat_presets_router
from services.recon_agent import start_agent as start_recon_agent, stop_agent as stop_recon_agent

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)-18s %(levelname)-5s %(message)s",
)
log = logging.getLogger("bff")


@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("BFF starting up")
    poll_task = asyncio.create_task(poll_loop())
    await start_recon_agent()
    yield
    log.info("BFF shutting down")
    await stop_recon_agent()
    poll_task.cancel()
    try:
        await poll_task
    except asyncio.CancelledError:
        pass


app = FastAPI(title="Pentest Dashboard BFF", lifespan=lifespan)

# ── Engagement context (Option B / Phase 7 audit fix) ──
# Captures `X-Engagement-Id` from every incoming request into a
# request-scoped contextvar.  BFF routes that proxy to rag-api must spread
# `engagement_headers()` into their outgoing httpx `headers={...}` so the
# rag-api middleware sees the header and stamps INSERTs with the active
# engagement.  Without this, scans launched via the dashboard would fall
# through unstamped (engagement_id = NULL) -- exactly the gap caught in
# the audit.
from engagement import engagement_middleware  # noqa: E402
app.middleware("http")(engagement_middleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register all routers
app.include_router(health_router)
app.include_router(assets_router)
app.include_router(findings_router)
app.include_router(scans_router)
app.include_router(exploits_router)
app.include_router(reports_router)
app.include_router(chat_router)
app.include_router(feedback_router)
app.include_router(webhook_router)
app.include_router(maintenance_router)
app.include_router(agent_sessions_router)
app.include_router(kb_router)
app.include_router(scope_router)
app.include_router(scope_classify_router)
app.include_router(zap_addons_router)
app.include_router(nodes_router)
app.include_router(wordlists_router)
app.include_router(settings_router)
app.include_router(engagements_router)
app.include_router(evidence_router)
app.include_router(credentials_router)
app.include_router(identities_router)
app.include_router(opsec_router)
app.include_router(followups_router)
app.include_router(api_tester_router)
app.include_router(about_router)
app.include_router(delta_router)
app.include_router(cloud_suggestor_router)
app.include_router(sync_router)
app.include_router(content_analysis_router)
app.include_router(burp_router)
app.include_router(targeted_recon_router)
app.include_router(recon_agent_router)
app.include_router(agents_router)
app.include_router(news_router)
app.include_router(chat_presets_router)


@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await hub.connect(ws)
    try:
        while True:
            # Keep connection alive, handle pings
            data = await ws.receive_text()
            if data == "ping":
                await ws.send_text("pong")
    except WebSocketDisconnect:
        pass
    finally:
        await hub.disconnect(ws)
