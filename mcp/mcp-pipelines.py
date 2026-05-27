#!/usr/bin/env python3
"""MCP Server: Composite Scan Pipelines (3 tools) — Port 9021"""

import json, os, logging
from typing import Annotated
import httpx
from pydantic import Field
from mcp.server.fastmcp import FastMCP

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

NMAP_URL = os.environ.get("NMAP_URL", "https://nmap_scanner:8012")
WEB_SCANNER_URL = os.environ.get("WEB_SCANNER_URL", "https://web-scanner:8010")
TIMEOUT = float(os.environ.get("MCP_TIMEOUT_SCAN", "300"))

mcp = FastMCP("scan-pipelines", host="0.0.0.0", port=9021, stateless_http=True, streamable_http_path="/mcp")


@mcp.tool()
async def start_full_port_scan(
    target: Annotated[str, Field(description="IP address or CIDR range, e.g. '192.168.1.0/24'")],
    rate: Annotated[int, Field(description="Packets per second for Masscan")] = 1000,
) -> str:
    """Complete port scan pipeline: Masscan 1-1000 → Nmap service detection → Masscan 1001-65535 → Nmap → SMB vuln scan.

    Args:
        target: IP address or CIDR range (e.g., '192.168.1.0/24')
        rate: Packets per second for Masscan (default: 1000)
    """
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT) as client:
        resp = await client.post(
            f"{NMAP_URL}/jobs/full-scan",
            json={"targets": [target], "rate": rate},
        )
        return json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2)


@mcp.tool()
async def start_web_pipeline(
    target_url: Annotated[str, Field(description="Target URL, e.g. 'http://192.168.1.150'")],
    max_paths: Annotated[int, Field(description="Max paths for Playwright to visit")] = 50,
) -> str:
    """Complete web scan pipeline: Gobuster → Playwright → ZAP → Nuclei (each stage feeds results to the next).

    Args:
        target_url: Target URL (e.g., 'http://192.168.1.150')
        max_paths: Max paths for Playwright to visit (default: 50)
    """
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT) as client:
        resp = await client.post(
            f"{WEB_SCANNER_URL}/jobs/pipeline-scan",
            json={"target_url": target_url, "max_paths_to_visit": max_paths},
        )
        return json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2)


@mcp.tool()
async def get_pipeline_status(
    job_id: Annotated[str, Field(description="Job UUID returned by start_full_port_scan or start_web_pipeline")],
    pipeline_type: Annotated[str, Field(description="'port' for full port scan, 'web' for web pipeline")] = "port",
) -> str:
    """Check status of a running pipeline scan.

    Args:
        job_id: Job UUID returned by start_full_port_scan or start_web_pipeline
        pipeline_type: 'port' for full port scan, 'web' for web pipeline (default: 'port')
    """
    base = NMAP_URL if pipeline_type == "port" else WEB_SCANNER_URL
    async with httpx.AsyncClient(verify=False, timeout=15) as client:
        resp = await client.get(f"{base}/jobs/{job_id}")
        return json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2)


if __name__ == "__main__":
    logger.info("Starting MCP Pipelines Server on 0.0.0.0:9021")
    mcp.run(transport="streamable-http")
