"""Scan report import — upload a file produced by another tool.

Thin proxy to rag-api's /ingest/* endpoints, which own the parsers (they run in
the container where ./etl is mounted). The BFF's job here is auth, engagement
scoping, and giving the UI one endpoint that figures out which scanner produced
a file rather than making the operator pick.
"""
import logging
from typing import Optional

import httpx
from fastapi import APIRouter, Body, File, HTTPException, Query, UploadFile
from utils import safe_json

from config import get_settings
from engagement import engagement_headers

router = APIRouter()
log = logging.getLogger("bff.imports")

# Tools whose reports /api/import/web-scan can ingest. Mirrors the dispatch in
# rag-api's ingest_web_scan; kept here so the UI can render the accepted list
# without a round trip.
SUPPORTED_WEB_TOOLS = {
    "zap":    {"label": "OWASP ZAP", "formats": ["JSON", "XML"]},
    "nikto":  {"label": "Nikto",     "formats": ["XML", "JSON"]},
    "burp":   {"label": "Burp Suite", "formats": ["XML"]},
    "nuclei": {"label": "Nuclei",    "formats": ["JSONL"]},
}

# Reports are text; this bounds memory and gives a clear error instead of an
# opaque failure deep in a parser.
MAX_IMPORT_BYTES = int(50 * 1024 * 1024)


@router.get("/api/import/web-scan/formats")
async def list_supported_web_formats():
    """Which web scan report formats can be imported."""
    return {
        "tools": [
            {"id": tid, "label": meta["label"], "formats": meta["formats"]}
            for tid, meta in SUPPORTED_WEB_TOOLS.items()
        ],
        "max_bytes": MAX_IMPORT_BYTES,
    }


@router.post("/api/import/web-scan")
async def import_web_scan(
    file: UploadFile = File(...),
    tool: Optional[str] = Query(
        None,
        description="Force a parser (zap|nikto|burp|nuclei). Omit to auto-detect.",
    ),
):
    """Import a web scan report, auto-detecting the tool that produced it."""
    if tool and tool.lower() not in SUPPORTED_WEB_TOOLS:
        raise HTTPException(
            400,
            f"Unsupported tool {tool!r}. Supported: {', '.join(sorted(SUPPORTED_WEB_TOOLS))}.",
        )

    content = await file.read()
    if not content:
        raise HTTPException(400, "Uploaded file is empty")
    if len(content) > MAX_IMPORT_BYTES:
        raise HTTPException(
            413,
            f"Report is {len(content) // (1024 * 1024)}MB; the limit is "
            f"{MAX_IMPORT_BYTES // (1024 * 1024)}MB.",
        )

    s = get_settings()
    params = {"tool": tool.lower()} if tool else {}
    try:
        # Parsing a large report is DB-bound; allow well past the normal timeout.
        async with httpx.AsyncClient(timeout=300) as c:
            resp = await c.post(
                f"{s.rag_api_url}/ingest/web-scan",
                params=params,
                files={"file": (file.filename or "report", content, "application/octet-stream")},
                headers={"x-api-key": s.api_key, **engagement_headers()},
            )
    except httpx.TimeoutException:
        raise HTTPException(504, "Import timed out — the report may be very large.")
    except httpx.HTTPError as e:
        raise HTTPException(502, f"Import service unreachable: {e}")

    if resp.status_code >= 400:
        # Surface the parser's own message (e.g. "does not look like a ZAP
        # report"), which tells the operator what to fix. Unwrap the upstream
        # JSON envelope first — passing resp.text straight through would
        # double-encode it and render as escaped JSON inside the UI's error box.
        detail = resp.text
        try:
            body = resp.json()
            if isinstance(body, dict) and "detail" in body:
                detail = body["detail"]
        except Exception:
            pass
        raise HTTPException(resp.status_code, detail)

    result = safe_json(resp)
    log.info("Imported %s via %s: %s", file.filename,
             (result or {}).get("tool"), (result or {}).get("stats", {}).get("inserted"))
    return result


@router.post("/api/ingest/raw-artifact")
async def ingest_raw_artifact(body: dict = Body(...)):
    """Store one manually-uploaded artifact verbatim (operator supplies tool +
    an optional note). The UI reads the file client-side and posts its text, so
    this is a JSON passthrough to rag-api's /ingest/raw-artifact — the stored row
    then behaves like any other: Extract & Learn, drain, follow-on actions."""
    if not (body.get("tool") or "").strip():
        raise HTTPException(400, "tool is required")
    if not (body.get("content") or "").strip():
        raise HTTPException(400, "content is empty")
    body.setdefault("source", "manual-upload")
    s = get_settings()
    try:
        async with httpx.AsyncClient(timeout=300) as c:
            resp = await c.post(
                f"{s.rag_api_url}/ingest/raw-artifact", json=body,
                headers={"x-api-key": s.api_key, **engagement_headers()})
    except httpx.HTTPError as e:
        raise HTTPException(502, f"Ingest service unreachable: {e}")
    if resp.status_code >= 400:
        detail = resp.text
        try:
            jb = resp.json()
            if isinstance(jb, dict) and "detail" in jb:
                detail = jb["detail"]
        except Exception:
            pass
        raise HTTPException(resp.status_code, detail)
    return safe_json(resp)
