"""BFF router for About page — serves docs list, doc content, and MCP tool catalogue."""

import os
import re
import logging
import yaml
from pathlib import Path
from fastapi import APIRouter, HTTPException
from utils import safe_json

router = APIRouter()
log = logging.getLogger("about")

DOCS_DIR = Path(os.environ.get("DOCS_DIR", "/docs"))
MCP_DIR = Path(os.environ.get("MCP_DIR", "/mcp"))
MCP_REGISTRY_PATH = Path(os.environ.get("MCP_REGISTRY_PATH", "/mcp/third_party/registry.yaml"))


@router.get("/api/about/docs")
async def list_docs():
    """List all markdown files in the Docs directory."""
    if not DOCS_DIR.exists():
        return {"docs": []}
    files = sorted(
        [
            {"name": f.name, "size": f.stat().st_size}
            for f in DOCS_DIR.glob("*.md")
            if f.is_file()
        ],
        key=lambda x: x["name"].lower(),
    )
    return {"docs": files}


@router.get("/api/about/docs/{filename}")
async def get_doc(filename: str):
    """Return the content of a specific markdown file."""
    # Prevent path traversal
    if "/" in filename or "\\" in filename or ".." in filename:
        raise HTTPException(400, "Invalid filename")
    path = DOCS_DIR / filename
    if not path.exists() or not path.is_file():
        raise HTTPException(404, "Doc not found")
    return {"name": filename, "content": path.read_text(errors="replace")}


# ── MCP Tool Catalogue ──

_TOOL_RE = re.compile(
    r'@mcp\.tool\(\)\s*\n'
    r'async\s+def\s+(\w+)\(([^)]*)\)[^:]*:\s*\n'
    r'\s*"""(.*?)"""',
    re.DOTALL,
)

_PARAM_RE = re.compile(
    r'(\w+):\s*Annotated\[([^,\]]+),\s*Field\(description=["\']([^"\']+)["\']',
)

MCP_SERVERS = {
    "mcp-sessions.py": {"name": "Sessions & Queries", "port": 9016},
    "mcp-scanning.py": {"name": "Scanning", "port": 9017},
    "mcp-recon.py": {"name": "Recon & OSINT", "port": 9018},
    "mcp-exploit.py": {"name": "Exploits & Metasploit", "port": 9019},
    "mcp-credentials.py": {"name": "Credentials", "port": 9020},
    "mcp-pipelines.py": {"name": "Scan Pipelines", "port": 9021},
    "mcp-burp.py": {"name": "Burp Suite", "port": 9022},
    "mcp-zap.py": {"name": "ZAP Scanner", "port": 9023},
}


def _parse_mcp_file(path: Path) -> list[dict]:
    """Extract tool name, description, and parameters from an MCP server file."""
    text = path.read_text(errors="replace")
    tools = []
    for m in _TOOL_RE.finditer(text):
        name = m.group(1)
        params_raw = m.group(2)
        docstring = m.group(3).strip().split("\n")[0].strip()  # first line only

        params = []
        for pm in _PARAM_RE.finditer(params_raw):
            params.append({
                "name": pm.group(1),
                "type": pm.group(2).strip(),
                "description": pm.group(3),
            })

        tools.append({"name": name, "description": docstring, "params": params})
    return tools


def _load_third_party_servers() -> list[dict]:
    """Load third-party MCP servers from registry YAML."""
    if not MCP_REGISTRY_PATH.exists():
        return []
    try:
        data = yaml.safe_load(MCP_REGISTRY_PATH.read_text(errors="replace"))
        return data.get("servers", []) if isinstance(data, dict) else []
    except Exception as e:
        log.warning("Failed to load MCP registry: %s", e)
        return []


@router.get("/api/about/mcp-tools")
async def list_mcp_tools():
    """Return all MCP tools grouped by server, including third-party."""
    servers = []

    # Built-in servers (parsed from Python source)
    if MCP_DIR.exists():
        for filename, meta in MCP_SERVERS.items():
            path = MCP_DIR / filename
            if not path.exists():
                continue
            tools = _parse_mcp_file(path)
            servers.append({
                "file": filename,
                "name": meta["name"],
                "port": meta["port"],
                "tool_count": len(tools),
                "tools": tools,
                "builtin": True,
            })

    # Third-party servers (from registry YAML)
    for srv in _load_third_party_servers():
        if not srv.get("enabled", False):
            continue
        name = srv.get("name", "unknown")
        port = srv.get("port", 0)
        description = srv.get("description", "")
        source = srv.get("source", "external")
        transport = srv.get("transport", "stdio")

        # Try to parse tools if it's a local Python file
        tools = []
        entry = srv.get("entry", "")
        if entry and entry.endswith(".py"):
            # Check common paths for the entry file
            for candidate in [
                MCP_DIR / "third_party" / name / entry,
                MCP_DIR / "third_party" / entry,
                Path(srv.get("path", "")) / entry if srv.get("path") else None,
            ]:
                if candidate and candidate.exists():
                    tools = _parse_mcp_file(candidate)
                    break

        servers.append({
            "file": entry or name,
            "name": name,
            "port": port,
            "tool_count": len(tools),
            "tools": tools,
            "builtin": False,
            "description": description,
            "source": source,
            "transport": transport,
            "url": srv.get("url", ""),
        })

    return {"servers": servers, "total_tools": sum(s["tool_count"] for s in servers)}
