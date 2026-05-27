"""Test execution — single endpoint + run-all."""

import json
import time
import httpx
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from typing import Optional

router = APIRouter()


def _get_store():
    from backend.main import store
    return store


class TestExecute(BaseModel):
    session_id: str
    endpoint_id: str
    params: Optional[dict] = None
    body: Optional[dict] = None
    headers: Optional[dict] = None


class RunAll(BaseModel):
    session_id: str
    collection_id: str
    variables: Optional[dict] = None
    headers: Optional[dict] = None


def _execute_one(session: dict, endpoint: dict, base_url: str,
                 params_dict: dict, body_data: dict | None,
                 extra_headers: dict | None) -> dict:
    """Execute a single HTTP request and return result dict."""
    path = endpoint["path"]
    for pname, pval in params_dict.items():
        path = path.replace(f"{{{pname}}}", str(pval))

    url = f"{base_url.rstrip('/')}{path}"

    query_params = {}
    for p in (endpoint.get("parameters") or []):
        if p.get("in") == "query" and p["name"] in params_dict:
            query_params[p["name"]] = params_dict[p["name"]]

    req_headers = {}
    if session.get("jwt_token"):
        req_headers["Authorization"] = f"Bearer {session['jwt_token']}"
    for p in (endpoint.get("parameters") or []):
        if p.get("in") == "header" and p["name"] in params_dict:
            req_headers[p["name"]] = params_dict[p["name"]]
    if extra_headers:
        req_headers.update(extra_headers)

    req_body = None
    if body_data and endpoint["method"] in ("POST", "PUT", "PATCH"):
        req_body = json.dumps(body_data)
        req_headers.setdefault("Content-Type", "application/json")

    proxy_url = session.get("proxy_url")
    error_msg = None
    status_code = None
    response_headers = {}
    response_body = ""
    start = time.time()

    try:
        client_kwargs = {"timeout": 30.0, "verify": False}
        if proxy_url:
            client_kwargs["proxy"] = proxy_url
        with httpx.Client(**client_kwargs) as client:
            resp = client.request(
                method=endpoint["method"], url=url,
                params=query_params or None, headers=req_headers, content=req_body,
            )
            status_code = resp.status_code
            response_headers = dict(resp.headers)
            response_body = resp.text[:50000]
    except Exception as e:
        error_msg = str(e)

    duration_ms = int((time.time() - start) * 1000)

    return {
        "session_id": session["id"],
        "endpoint_id": endpoint["id"],
        "method": endpoint["method"],
        "url": url,
        "request_headers": req_headers,
        "request_body": req_body,
        "status_code": status_code,
        "response_headers": response_headers,
        "response_body": response_body,
        "duration_ms": duration_ms,
        "error": error_msg,
    }


@router.post("/api-test/execute")
def execute_test(body: TestExecute):
    store = _get_store()
    session = store.get_session(body.session_id)
    if not session:
        raise HTTPException(404, "Session not found")

    ep_coll = store.get_endpoint_with_collection(body.endpoint_id)
    if not ep_coll:
        raise HTTPException(404, "Endpoint not found")
    endpoint, coll = ep_coll
    base_url = coll.get("base_url", "")

    result = _execute_one(session, endpoint, base_url, body.params or {}, body.body, body.headers)
    saved = store.add_result(body.session_id, result)
    return {"ok": True, "result": saved}


@router.get("/api-test/sessions/{sid}/history")
def get_history(sid: str, endpoint_id: Optional[str] = Query(None), limit: int = Query(50)):
    return {"history": _get_store().get_history(sid, endpoint_id=endpoint_id, limit=limit)}


@router.delete("/api-test/sessions/{sid}/history")
def clear_history(sid: str):
    deleted = _get_store().clear_history(sid)
    return {"ok": True, "deleted": deleted}


@router.post("/api-test/run-all")
def run_all(body: RunAll):
    store = _get_store()
    session = store.get_session(body.session_id)
    if not session:
        raise HTTPException(404, "Session not found")

    coll = store.get_collection(body.collection_id)
    if not coll:
        raise HTTPException(404, "Collection not found")

    base_url = coll.get("base_url", "")
    variables = body.variables or {}
    endpoints = coll.get("endpoints", [])
    results = []

    for ep in endpoints:
        # Build params from variables
        params_dict = {}
        for p in (ep.get("parameters") or []):
            if p["name"] in variables:
                params_dict[p["name"]] = variables[p["name"]]

        # Check required params
        missing = [p["name"] for p in (ep.get("parameters") or [])
                   if p.get("required") and p.get("in") == "path" and p["name"] not in params_dict]
        if missing:
            results.append({
                "endpoint_id": ep["id"], "method": ep["method"], "path": ep["path"],
                "status": "skipped", "reason": f"Missing required: {', '.join(missing)}",
            })
            continue

        # Build body from variables
        body_data = None
        rb = ep.get("request_body")
        if rb and isinstance(rb, dict):
            body_fields = {}
            for f in (rb.get("fields") or []):
                if f["name"] in variables:
                    body_fields[f["name"]] = variables[f["name"]]
            if body_fields:
                body_data = body_fields

        result = _execute_one(session, ep, base_url, params_dict, body_data, body.headers)
        store.add_result(body.session_id, result)
        results.append({
            "endpoint_id": ep["id"], "method": ep["method"], "path": ep["path"],
            "url": result["url"], "status": "ok",
            "status_code": result["status_code"], "duration_ms": result["duration_ms"],
            "error": result.get("error"), "result_id": result["id"],
        })

    executed = sum(1 for r in results if r["status"] == "ok")
    skipped = sum(1 for r in results if r["status"] == "skipped")
    return {"ok": True, "total": len(results), "executed": executed, "skipped": skipped, "results": results}
