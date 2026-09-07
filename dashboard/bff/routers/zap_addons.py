import logging
from utils import safe_json

import httpx
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from config import get_settings

router = APIRouter()
log = logging.getLogger("bff.zap_addons")


def _zap_base(s=None):
    s = s or get_settings()
    return s.zap_url


def _zap_params(s=None):
    s = s or get_settings()
    return {"apikey": s.zap_api_key}


@router.get("/api/zap/status")
async def zap_status():
    """What ZAP is actually doing right now: spider and active-scan progress.

    WHY THIS EXISTS: the pipeline's ZAP stage is its slowest by a wide margin, and
    there was NO way to tell a slow scan from a wedged one — the stack exposed
    add-ons, reports and ingest, but nothing about scan state. A pipeline sitting
    at `zap_running` looked identical whether ZAP was grinding through an active
    scan or idle with no scans at all.

    That distinction is not hypothetical: two pipelines were reported as stuck in
    `zap_running` when ZAP in fact held ZERO scans — the container had been
    recreated underneath them and every scan id was gone. This endpoint answers
    that in one call.

    `reachable=false` means ZAP itself is down, which is NOT the same as idle —
    the two must never collapse into one state (see tests/_container.py for the
    same distinction elsewhere in this stack).
    """
    s = get_settings()
    base, params = _zap_base(s), _zap_params(s)

    async def _view(path):
        async with httpx.AsyncClient(timeout=15) as c:
            r = await c.get(f"{base}/JSON/{path}/", params=params)
            r.raise_for_status()
            return r.json()

    try:
        version = (await _view("core/view/version")).get("version")
    except Exception as exc:                                   # noqa: BLE001
        log.warning("zap unreachable: %s", exc)
        return {"reachable": False, "error": str(exc)[:200],
                "detail": "ZAP is not answering — this is NOT the same as idle"}

    out = {"reachable": True, "version": version, "spider": [], "active_scan": []}

    # Session size is the number that predicts the failure. An unbounded session
    # (2.2 GB / 91% of the container's memory was measured here) makes ZAP go
    # selectively deaf: cheap views still answer, everything touching the session
    # store hangs. If this view itself times out, that IS the symptom.
    try:
        out["messages"] = int((await _view("core/view/numberOfMessages")).get("numberOfMessages", 0))
    except Exception as exc:                                       # noqa: BLE001
        out["messages"] = None
        out["session_warning"] = (
            f"numberOfMessages did not answer ({str(exc)[:80]}) — the session store is "
            "already too large to query. ZAP's context API will hang; restart it or "
            "start a new session.")
    for key, path in (("spider", "spider/view/scans"),
                      ("active_scan", "ascan/view/scans")):
        try:
            scans = (await _view(path)).get("scans") or []
        except Exception as exc:                               # noqa: BLE001
            out[key] = []
            out[f"{key}_error"] = str(exc)[:160]
            continue
        out[key] = [
            {"id": sc.get("id"), "progress": sc.get("progress"),
             "state": sc.get("state"), "url": sc.get("url")}
            for sc in scans
        ]

    running = [sc for sc in out["spider"] + out["active_scan"]
               if str(sc.get("state", "")).upper() == "RUNNING"]
    out["busy"] = bool(running)
    out["running_count"] = len(running)
    # The signal the operator actually wants: a pipeline stage claiming to wait on
    # ZAP while ZAP holds nothing is waiting on something that no longer exists.
    out["idle_but_expected_busy_hint"] = (
        "ZAP holds no scans. If a pipeline reports zap_running, its scan is gone "
        "(ZAP restarted or the scan was never started) — it will not progress."
        if not running else None
    )
    return out


@router.get("/api/zap/addons")
async def list_addons():
    """Return installed and available (marketplace) add-ons from ZAP."""
    s = get_settings()
    base = _zap_base(s)
    params = _zap_params(s)

    try:
        async with httpx.AsyncClient(timeout=30) as c:
            installed_resp = await c.get(
                f"{base}/JSON/autoupdate/view/installedAddons/",
                params=params,
            )
            installed_resp.raise_for_status()

            marketplace_resp = await c.get(
                f"{base}/JSON/autoupdate/view/marketplaceAddons/",
                params=params,
            )
            marketplace_resp.raise_for_status()
    except httpx.HTTPError as exc:
        log.error("ZAP API error: %s", exc)
        raise HTTPException(502, f"ZAP API unreachable: {exc}")

    installed = installed_resp.json().get("installedAddons", [])
    marketplace = marketplace_resp.json().get("marketplaceAddons", [])

    # Build set of installed IDs for quick lookup
    installed_ids = {a.get("id") for a in installed}

    # Filter marketplace to only those NOT already installed
    available = [a for a in marketplace if a.get("id") not in installed_ids]

    return {
        "installed": installed,
        "available": available,
        "installed_count": len(installed),
        "available_count": len(available),
    }


class AddonAction(BaseModel):
    addon_id: str


@router.post("/api/zap/addons/install")
async def install_addon(body: AddonAction):
    """Install a ZAP add-on from the marketplace."""
    s = get_settings()
    base = _zap_base(s)
    params = {**_zap_params(s), "id": body.addon_id}

    try:
        async with httpx.AsyncClient(timeout=120) as c:
            resp = await c.get(
                f"{base}/JSON/autoupdate/action/installAddon/",
                params=params,
            )
            resp.raise_for_status()
    except httpx.HTTPError as exc:
        log.error("ZAP install error for %s: %s", body.addon_id, exc)
        raise HTTPException(502, f"ZAP install failed: {exc}")

    data = resp.json()
    if data.get("Result") != "OK":
        raise HTTPException(400, f"ZAP refused install: {data}")

    log.info("Installed ZAP add-on: %s", body.addon_id)
    return {"ok": True, "addon_id": body.addon_id}


@router.post("/api/zap/addons/uninstall")
async def uninstall_addon(body: AddonAction):
    """Uninstall a ZAP add-on."""
    s = get_settings()
    base = _zap_base(s)
    params = {**_zap_params(s), "id": body.addon_id}

    try:
        async with httpx.AsyncClient(timeout=60) as c:
            resp = await c.get(
                f"{base}/JSON/autoupdate/action/uninstallAddon/",
                params=params,
            )
            resp.raise_for_status()
    except httpx.HTTPError as exc:
        log.error("ZAP uninstall error for %s: %s", body.addon_id, exc)
        raise HTTPException(502, f"ZAP uninstall failed: {exc}")

    data = resp.json()
    if data.get("Result") != "OK":
        raise HTTPException(400, f"ZAP refused uninstall: {data}")

    log.info("Uninstalled ZAP add-on: %s", body.addon_id)
    return {"ok": True, "addon_id": body.addon_id}
