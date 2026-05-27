"""Collection CRUD + import + common params."""

import os
import tempfile
import httpx as httpx_lib
from fastapi import APIRouter, HTTPException, Query, UploadFile, File
from typing import Optional

router = APIRouter()


def _get_store():
    from backend.main import store
    return store


@router.get("/api-collections")
def list_collections():
    return {"collections": _get_store().list_collections()}


@router.get("/api-collections/{cid}")
def get_collection(cid: str):
    coll = _get_store().get_collection(cid)
    if not coll:
        raise HTTPException(404, "Collection not found")
    c = {k: v for k, v in coll.items() if k != "endpoints"}
    c["endpoint_count"] = len(coll.get("endpoints", []))
    return c


@router.delete("/api-collections/{cid}")
def delete_collection(cid: str):
    if not _get_store().delete_collection(cid):
        raise HTTPException(404, "Collection not found")
    return {"ok": True}


@router.get("/api-collections/{cid}/endpoints")
def list_endpoints(
    cid: str,
    method: Optional[str] = Query(None),
    tag: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
):
    eps = _get_store().get_endpoints(cid, method=method, tag=tag, search=search)
    return {"endpoints": eps, "total": len(eps)}


@router.post("/api-collections/import")
async def import_file(file: UploadFile = File(...)):
    from backend.parser import parse_swagger
    store = _get_store()

    # Save uploaded file to swagger dir
    dest = store.data_dir / "swagger" / (file.filename or "upload.json")
    content = await file.read()
    dest.write_bytes(content)

    try:
        parsed = parse_swagger(str(dest))
    except Exception as e:
        raise HTTPException(400, f"Failed to parse: {e}")

    cid = store.upsert_collection_by_source(parsed)
    return {"ok": True, "collection_id": cid, "endpoints": len(parsed.get("endpoints", []))}


@router.post("/api-collections/import-dir")
def import_dir():
    from backend.parser import parse_swagger
    store = _get_store()
    swagger_dir = store.data_dir / "swagger"
    imported = []
    for fname in sorted(os.listdir(swagger_dir)):
        if not fname.endswith(".json"):
            continue
        try:
            parsed = parse_swagger(str(swagger_dir / fname))
            cid = store.upsert_collection_by_source(parsed)
            imported.append({"name": parsed["name"], "id": cid, "endpoints": len(parsed["endpoints"])})
        except Exception as e:
            imported.append({"name": fname, "error": str(e)})
    return {"ok": True, "imported": imported, "total": len(imported)}


@router.post("/api-collections/import-url")
async def import_url(body: dict):
    from backend.parser import parse_swagger
    store = _get_store()
    url = body.get("url", "").strip()
    if not url:
        raise HTTPException(400, "url is required")

    try:
        async with httpx_lib.AsyncClient(timeout=30, verify=False, follow_redirects=True) as c:
            resp = await c.get(url)
            resp.raise_for_status()
            spec_data = resp.json()
    except Exception as e:
        raise HTTPException(400, f"Failed to fetch: {e}")

    # Save to swagger dir
    fname = url.rstrip("/").rsplit("/", 1)[-1]
    if not fname.endswith(".json"):
        fname = fname.replace(".", "_") + ".json"
    dest = store.data_dir / "swagger" / fname
    dest.write_text(resp.text)

    try:
        parsed = parse_swagger(str(dest))
        parsed["source_url"] = body.get("url", "")
    except Exception as e:
        raise HTTPException(400, f"Failed to parse: {e}")

    cid = store.upsert_collection_by_source(parsed)
    return {"ok": True, "collection_id": cid, "endpoints": len(parsed["endpoints"]), "message": f"Imported {parsed['name']}"}


@router.get("/api-collections/{cid}/common-params")
def get_common_params(cid: str):
    store = _get_store()
    endpoints = store.get_endpoints(cid)
    param_map: dict[str, dict] = {}

    for ep in endpoints:
        ep_label = f"{ep['method']} {ep['path']}"
        for p in (ep.get("parameters") or []):
            name = p.get("name", "")
            if not name:
                continue
            key = f"{p.get('in', 'query')}:{name}"
            if key not in param_map:
                param_map[key] = {
                    "name": name, "in": p.get("in", "query"),
                    "type": p.get("type", "string"), "format": p.get("format", ""),
                    "required": p.get("required", False),
                    "description": p.get("description", ""), "used_in": [],
                }
            param_map[key]["used_in"].append(ep_label)
            if p.get("required"):
                param_map[key]["required"] = True

        rb = ep.get("request_body")
        if rb and isinstance(rb, dict):
            for field in (rb.get("fields") or []):
                fname = field.get("name", "")
                if not fname:
                    continue
                key = f"body:{fname}"
                if key not in param_map:
                    param_map[key] = {
                        "name": fname, "in": "body",
                        "type": field.get("type", "string"), "format": "",
                        "required": field.get("required", False),
                        "description": field.get("description", ""), "used_in": [],
                    }
                param_map[key]["used_in"].append(ep_label)

    params = sorted(param_map.values(), key=lambda p: (-int(p["required"]), -len(p["used_in"]), p["name"]))
    return {"collection_id": cid, "params": params, "total": len(params)}
