"""BFF proxy routes for multi-node sync."""
import httpx
import logging
from fastapi import APIRouter, Query, Request
from config import get_settings
from utils import safe_json

router = APIRouter(prefix="/api/sync", tags=["sync"])
TIMEOUT = 60.0
log = logging.getLogger("sync")


def _api(path: str) -> str:
    return f"{get_settings().rag_api_url}{path}"


def _headers() -> dict:
    return {"x-api-key": get_settings().api_key}


@router.post("/register-node")
async def register_node(node_id: str = Query(...), node_name: str = Query(...), owner: str = Query(None)):
    params = {"node_id": node_id, "node_name": node_name}
    if owner:
        params["owner"] = owner
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT) as c:
        r = await c.post(_api("/sync/register-node"), params=params, headers=_headers())
    return r.json()


@router.get("/nodes")
async def list_nodes():
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT) as c:
        r = await c.get(_api("/sync/nodes"), headers=_headers())
    return r.json()


@router.get("/status")
async def sync_status(node_id: str = Query("local")):
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT) as c:
        r = await c.get(_api("/sync/status"), params={"node_id": node_id}, headers=_headers())
    return r.json()


@router.get("/changes")
async def get_changes(since_lsn: int = Query(0), limit: int = Query(1000), table: str = Query(None)):
    params = {"since_lsn": since_lsn, "limit": limit}
    if table:
        params["table"] = table
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT) as c:
        r = await c.get(_api("/sync/changes"), params=params, headers=_headers())
    return r.json()


@router.post("/apply")
async def apply_changes(
    request: Request,
    node_id: str = Query(...),
    strategy: str = Query("last_write_wins"),
):
    body = await request.json()
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT) as c:
        r = await c.post(
            _api("/sync/apply"),
            params={"node_id": node_id, "strategy": strategy},
            json=body,
            headers=_headers(),
        )
    return r.json()


@router.post("/push")
async def push_changes(node_id: str = Query(...)):
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT) as c:
        r = await c.post(_api("/sync/push"), params={"node_id": node_id}, headers=_headers())
    return r.json()


@router.get("/conflicts")
async def list_conflicts(status: str = Query("pending"), limit: int = Query(50)):
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT) as c:
        r = await c.get(_api("/sync/conflicts"), params={"status": status, "limit": limit}, headers=_headers())
    return r.json()


@router.patch("/conflicts/{conflict_id}")
async def resolve_conflict(conflict_id: str, resolution: str = Query(...), resolved_by: str = Query("user")):
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT) as c:
        r = await c.patch(
            _api(f"/sync/conflicts/{conflict_id}"),
            params={"resolution": resolution, "resolved_by": resolved_by},
            headers=_headers(),
        )
    return r.json()


@router.post("/snapshot")
async def create_snapshot(node_id: str = Query(...), tables: str = Query(None)):
    params = {"node_id": node_id}
    if tables:
        params["tables"] = tables
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT) as c:
        r = await c.post(_api("/sync/snapshot"), params=params, headers=_headers())
    return r.json()


# ── Full sync via SSH tunnel ─────────────────────────────────────────

async def _get_remote_api_url() -> str | None:
    """Get the remote rag-api URL via the SSH tunnel.

    The tunnel container forwards to the remote VPS postgres on :5432,
    but we need the remote rag-api on :8000. We create a separate
    port-forward via container-logs, or connect directly if in remote mode.
    """
    # When in remote mode, rag-api IS already talking to the remote DB.
    # But we need a separate local rag-api instance connected to the remote.
    # For now, we'll use the container-logs service to proxy the request.
    return None  # Handled differently — see below


@router.post("/sync-schema")
async def sync_schema():
    """Apply local schema (DDL) to the remote database via the tunnel."""
    s = get_settings()
    try:
        async with httpx.AsyncClient(verify=False, timeout=300) as c:
            resp = await c.post(f"{s.container_logs_url}/db/sync-schema", timeout=280)
            if resp.status_code >= 400:
                return {"ok": False, "error": f"Schema sync failed: HTTP {resp.status_code}: {resp.text[:200]}"}
            return safe_json(resp)
    except Exception as e:
        log.exception("sync-schema failed")
        return {"ok": False, "error": str(e)}


@router.post("/push-to-remote")
async def push_to_remote(
    node_id: str = Query("local"),
    strategy: str = Query("last_write_wins"),
):
    """Full push: collect local changes → apply to remote DB via the tunnel.

    Since the remote DB is accessible when the SSH tunnel is active
    (rag-postgres alias points to tunnel), we:
    1. Collect local changes from the local rag-api
    2. Switch rag-api connection to remote (via the tunnel)
    3. Apply changes there
    4. Update local push watermark

    Simpler approach: We just apply changes to whichever DB rag-api is
    currently connected to. If in remote mode, this pushes to remote.
    If in local mode, we need the tunnel up.
    """
    s = get_settings()
    h = _headers()

    try:
        async with httpx.AsyncClient(verify=False, timeout=10) as c:
            try:
                mode_resp = await c.get(f"{s.container_logs_url}/db/config")
                mode = mode_resp.json().get("mode", "local")
            except Exception:
                mode = "local"

        # Delegate to container-logs service which has psycopg2 and Docker SDK
        # It connects directly to both local postgres and remote via tunnel
        async with httpx.AsyncClient(verify=False, timeout=300) as c:
            resp = await c.post(
                f"{s.container_logs_url}/db/sync-push",
                timeout=280,
            )
            if resp.status_code >= 400:
                return {"ok": False, "error": f"Sync push failed: HTTP {resp.status_code}: {resp.text[:200]}"}
            return safe_json(resp)

    except Exception as e:
        log.exception("push-to-remote failed")
        return {"ok": False, "error": str(e)}


@router.post("/pull-from-remote")
async def pull_from_remote(
    node_id: str = Query("local"),
    strategy: str = Query("last_write_wins"),
    since_lsn: int = Query(0),
):
    """Pull changes from remote and apply to local.

    Only works when NOT in remote mode (local rag-api is on local DB).
    Requires the SSH tunnel to be up to reach the remote rag-api.
    """
    s = get_settings()
    h = _headers()

    try:
        # Check mode
        async with httpx.AsyncClient(verify=False, timeout=10) as c:
            try:
                mode_resp = await c.get(f"{s.container_logs_url}/db/config")
                mode = mode_resp.json().get("mode", "local")
            except Exception:
                mode = "local"

        if mode == "remote":
            return {
                "ok": False,
                "error": "Already in remote mode — rag-api is connected to remote DB. "
                         "Switch to local first to pull remote changes into local DB.",
            }

        # In local mode: rag-api is on local DB.
        # We need remote changes — but we can't reach remote rag-api easily.
        # The pull is better handled via the CLI script for now.
        return {
            "ok": False,
            "error": "Pull from remote requires the remote rag-api to be accessible. "
                     "Use: ./scripts/sync-pull.sh",
        }

    except Exception as e:
        return {"ok": False, "error": str(e)}


@router.post("/reset-watermark")
async def reset_watermark(node_id: str = Query("local")):
    """Reset sync watermark to current max LSN (e.g., after a full pg_dump migration).

    This marks all existing changes as 'already synced' so only new changes
    after this point will be pushed.
    """
    s = get_settings()
    h = _headers()

    try:
        async with httpx.AsyncClient(verify=False, timeout=30) as c:
            # Get current max LSN
            status_resp = await c.get(
                _api("/sync/status"), params={"node_id": node_id}, headers=h,
            )
            status_data = status_resp.json()
            max_lsn = status_data.get("max_lsn", 0)

            if max_lsn == 0:
                return {"ok": True, "message": "No changes to reset", "max_lsn": 0}

            # Push with the node to advance the watermark
            push_resp = await c.post(
                _api("/sync/push"), params={"node_id": node_id}, headers=h,
            )
            push_data = push_resp.json()

            return {
                "ok": True,
                "message": f"Watermark reset to LSN {push_data.get('max_lsn', max_lsn)}. "
                           f"Skipped {push_data.get('count', 0)} pre-existing changes.",
                "max_lsn": push_data.get("max_lsn", max_lsn),
                "skipped": push_data.get("count", 0),
            }
    except Exception as e:
        return {"ok": False, "error": str(e)}
