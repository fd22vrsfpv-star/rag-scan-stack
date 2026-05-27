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


@router.get("/api/zap/addons")
async def list_addons():
    """Return installed and available (marketplace) add-ons from ZAP."""
    s = get_settings()
    base = _zap_base(s)
    params = _zap_params(s)

    try:
        async with httpx.AsyncClient(verify=False, timeout=30) as c:
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
        async with httpx.AsyncClient(verify=False, timeout=120) as c:
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
        async with httpx.AsyncClient(verify=False, timeout=60) as c:
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
