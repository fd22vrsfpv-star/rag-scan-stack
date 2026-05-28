from typing import Optional
import httpx
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from config import get_settings
from engagement import engagement_headers
from services.report_renderer import render_pdf
import io
from utils import safe_json

router = APIRouter()


@router.get("/api/reports/summary")
async def report_summary(session_id: Optional[str] = None):
    s = get_settings()
    params = {}
    if session_id:
        params["session_id"] = session_id
    async with httpx.AsyncClient(verify=False, timeout=60) as c:
        resp = await c.get(
            f"{s.autogen_url}/reports/summary",
            params=params,
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.get("/api/reports/full")
async def report_full(
    target: Optional[str] = None,
    format: str = "markdown",
    session_id: Optional[str] = None,
    scope_name: Optional[str] = None,
):
    s = get_settings()

    async with httpx.AsyncClient(verify=False, timeout=120) as c:
        # Try autogen report endpoint first (uses tool_executions table)
        autogen_ok = False
        try:
            params: dict = {"format": format}
            if target:
                params["target"] = target
            if session_id:
                params["session_id"] = session_id
            resp = await c.get(
                f"{s.autogen_url}/reports/full",
                params=params,
                headers={"x-api-key": s.api_key, **engagement_headers()},
            )
            if resp.status_code == 200:
                data = resp.json()
                # Check if report has actual content
                vulns = data.get("vulnerabilities", {})
                has_content = any(len(v) > 0 for v in vulns.values()) if isinstance(vulns, dict) else bool(vulns)
                if has_content:
                    return data
        except Exception:
            pass

        # Fallback: build report from web_findings/recon_findings via RAG API
        findings_params: dict = {"limit": 500}
        if target:
            findings_params["search"] = target
        resp2 = await c.get(
            f"{s.rag_api_url}/findings/search",
            params=findings_params,
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        if resp2.status_code == 200:
            findings_data = resp2.json()
            findings = findings_data.get("findings", [])
            if findings:
                return _build_findings_report(
                    target or scope_name or "All Targets", findings, format
                )

        # Nothing found
        return {
            "target": target or scope_name or "All Targets",
            "generated_at": __import__("datetime").datetime.now().isoformat(),
            "summary": {"target": target, "scan_period": {"started": "", "ended": ""},
                        "tools_summary": [], "ports_discovered": [],
                        "findings_by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}},
            "vulnerabilities": {},
            "rendered": f"# Report — {target or scope_name or 'All Targets'}\n\nNo findings found. Run scans first.",
        }


def _build_findings_report(target: str, findings: list, format: str = "markdown") -> dict:
    """Build a report from web_findings when tool_executions is empty."""
    from datetime import datetime
    from collections import defaultdict

    by_severity = defaultdict(list)
    for f in findings:
        by_severity[f.get("severity", "info")].append(f)

    sources = defaultdict(int)
    for f in findings:
        sources[f.get("source", "unknown")] += 1

    summary = {
        "target": target,
        "scan_period": {"started": "", "ended": ""},
        "tools_summary": [
            {"tool": src, "executions": cnt, "successful": cnt, "failed": 0, "avg_duration": 0}
            for src, cnt in sorted(sources.items(), key=lambda x: -x[1])
        ],
        "ports_discovered": [],
        "findings_by_severity": {s: len(by_severity.get(s, [])) for s in ["critical", "high", "medium", "low", "info"]},
    }

    vulns = {}
    for sev in ["critical", "high", "medium", "low", "info"]:
        vulns[sev] = [
            {
                "id": f.get("id", ""),
                "title": f.get("name", f.get("title", "Finding")),
                "tool": f.get("source", ""),
                "target": f.get("ip", f.get("url", target)),
                "port": f.get("port"),
                "cve": f.get("cve", []) if isinstance(f.get("cve"), list) else [f["cve"]] if f.get("cve") else [],
                "detail_url": "",
            }
            for f in by_severity.get(sev, [])
        ]

    report = {
        "target": target,
        "generated_at": datetime.now().isoformat(),
        "summary": summary,
        "vulnerabilities": vulns,
    }

    if format == "markdown":
        lines = [
            f"# Penetration Test Report — {target}",
            f"",
            f"*Generated: {report['generated_at']}*",
            f"",
            f"## Executive Summary",
            f"",
            f"**Total findings: {len(findings)}**",
            f"",
        ]
        for sev in ["critical", "high", "medium", "low", "info"]:
            cnt = len(by_severity.get(sev, []))
            if cnt:
                lines.append(f"- **{sev.upper()}**: {cnt}")
        lines.extend(["", "### Tools / Sources", ""])
        for src, cnt in sorted(sources.items(), key=lambda x: -x[1]):
            lines.append(f"- {src}: {cnt} findings")
        for sev in ["critical", "high", "medium", "low"]:
            items = by_severity.get(sev, [])
            if not items:
                continue
            lines.extend(["", f"## {sev.upper()} Findings ({len(items)})", ""])
            for f in items[:50]:
                name = f.get("name", f.get("title", "Finding"))
                src = f.get("source", "")
                url = f.get("url", f.get("ip", ""))
                evidence = (f.get("evidence") or "")[:200]
                lines.append(f"### {name}")
                lines.append(f"- **Source:** {src}")
                if url:
                    lines.append(f"- **URL:** {url}")
                if f.get("cve"):
                    lines.append(f"- **CVE:** {f['cve']}")
                if evidence:
                    lines.append(f"- **Evidence:** {evidence}")
                lines.append("")
        report["rendered"] = "\n".join(lines)

    return report


class ExportRequest(BaseModel):
    title: str = "Penetration Test Report"
    target: Optional[str] = None
    severity_filter: Optional[list[str]] = None
    source_filter: Optional[list[str]] = None
    session_id: Optional[str] = None
    include_findings: bool = True
    include_recommendations: bool = True


@router.post("/api/reports/export")
async def export_pdf(req: ExportRequest):
    s = get_settings()
    # Gather data for the report
    findings_data = {}
    summary_data = {}

    async with httpx.AsyncClient(verify=False, timeout=60) as c:
        # Get findings
        params: dict = {"limit": 500}
        if req.severity_filter:
            params["severity"] = req.severity_filter
        if req.source_filter:
            params["source"] = req.source_filter
        if req.target:
            params["ip"] = req.target

        resp = await c.get(
            f"{s.rag_api_url}/findings/search",
            params=params,
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        if resp.status_code == 200:
            findings_data = resp.json()

        # Get report summary
        summary_params = {}
        if req.session_id:
            summary_params["session_id"] = req.session_id
        try:
            resp2 = await c.get(
                f"{s.autogen_url}/reports/summary",
                params=summary_params,
                headers={"x-api-key": s.api_key, **engagement_headers()},
            )
            if resp2.status_code == 200:
                summary_data = resp2.json()
        except Exception:
            pass

    pdf_bytes = render_pdf(
        title=req.title,
        findings=findings_data.get("findings", []),
        aggregations=findings_data.get("aggregations", {}),
        summary=summary_data,
    )

    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="pentest-report.pdf"'},
    )


@router.get("/api/reports/export-zap-xml")
async def export_zap_xml():
    """Proxy the latest ZAP XML report from web-scanner."""
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=60) as c:
        resp = await c.get(f"{s.web_scanner_url}/reports/zap-xml")
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
    return StreamingResponse(
        io.BytesIO(resp.content),
        media_type="application/xml",
        headers={"Content-Disposition": 'attachment; filename="zap_report.xml"'},
    )


@router.post("/api/reports/export-burp")
async def export_burp(req: ExportRequest):
    s = get_settings()
    params: dict = {}
    if req.severity_filter:
        params["severity"] = req.severity_filter
    if req.source_filter:
        params["source"] = req.source_filter
    if req.target:
        params["ip"] = req.target

    async with httpx.AsyncClient(verify=False, timeout=120) as c:
        resp = await c.get(
            f"{s.rag_api_url}/export/burp",
            params=params,
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)

    return StreamingResponse(
        io.BytesIO(resp.content),
        media_type="application/xml; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="burp_sitemap_export.xml"'},
    )


@router.post("/api/reports/export-har")
async def export_har(request: Request):
    """Export findings as HAR file (Burp Suite + ZAP compatible)."""
    s = get_settings()
    body = await request.json()
    params: dict = {"limit": body.get("limit", 2000)}
    if body.get("severity_filter"):
        params["severity"] = body["severity_filter"]
    if body.get("source_filter"):
        params["source"] = body["source_filter"]
    if body.get("target"):
        params["ip"] = body["target"]
    if body.get("search"):
        params["search"] = body["search"]

    async with httpx.AsyncClient(verify=False, timeout=120) as c:
        resp = await c.get(
            f"{s.rag_api_url}/export/har",
            params=params,
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)

    return StreamingResponse(
        io.BytesIO(resp.content),
        media_type="application/json; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="findings_export.har"'},
    )


@router.get("/api/reports/proxy-replay/status")
async def proxy_replay_status():
    """Get proxy replay progress."""
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=5) as c:
        resp = await c.get(f"{s.rag_api_url}/export/proxy-replay/status", headers={"x-api-key": s.api_key, **engagement_headers()})
        return safe_json(resp)


@router.post("/api/reports/proxy-replay")
async def proxy_replay(request: Request):
    """Replay finding URLs through a configured proxy."""
    s = get_settings()
    body = await request.json()
    async with httpx.AsyncClient(verify=False, timeout=30) as c:
        resp = await c.post(
            f"{s.rag_api_url}/export/proxy-replay",
            json=body,
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.post("/api/reports/export-zap-report")
async def export_zap_report(request: Request):
    """Export findings as ZAP XML report."""
    s = get_settings()
    body = await request.json()
    params: dict = {"limit": body.get("limit", 2000)}
    if body.get("severity_filter"):
        params["severity"] = body["severity_filter"]
    if body.get("source_filter"):
        params["source"] = body["source_filter"]
    if body.get("target"):
        params["ip"] = body["target"]

    async with httpx.AsyncClient(verify=False, timeout=120) as c:
        resp = await c.get(
            f"{s.rag_api_url}/export/zap-report",
            params=params,
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)

    return StreamingResponse(
        io.BytesIO(resp.content),
        media_type="application/xml; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="zap_report_export.xml"'},
    )


@router.get("/sarif-export")
async def sarif_export(
    severity: str = None,
    source: str = None,
    limit: int = 5000,
):
    s = get_settings()
    params: dict = {"limit": limit}
    if severity:
        params["severity"] = severity.split(",")
    if source:
        params["source"] = source.split(",")

    async with httpx.AsyncClient(verify=False, timeout=120) as c:
        resp = await c.get(
            f"{s.rag_api_url}/export/sarif",
            params=params,
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)

    return StreamingResponse(
        io.BytesIO(resp.content),
        media_type="application/json",
        headers={"Content-Disposition": 'attachment; filename="pentest_findings.sarif"'},
    )
