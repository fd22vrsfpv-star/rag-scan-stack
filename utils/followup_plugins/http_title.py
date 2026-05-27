"""
HTTP title plugin: fetch <title> from HTTP(S) on standard and non-standard ports.
Falls back between http/https schemes if first attempt fails.
"""
import asyncio
from typing import Dict, Any


def _fetch_title(url: str, timeout: float = 5.0) -> Dict[str, Any]:
    import requests
    try:
        r = requests.get(url, timeout=timeout, verify=False, headers={"User-Agent": "followup/1.0"})
        html = r.text or ""
        title = None
        import re
        m = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
        if m:
            title = m.group(1).strip()
        return {"status": r.status_code, "title": title, "headers": dict(r.headers), "url": url, "length": len(html)}
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}", "url": url}


async def run(host: str, port: int, proto: str, context: Dict[str, Any]) -> Dict[str, Any]:
    scheme_hint = (context or {}).get("scheme") or ("https" if port in (443, 8443) else "http")
    urls = [f"{scheme_hint}://{host}:{port}"]
    urls.append(("http" if scheme_hint == "https" else "https") + f"://{host}:{port}")
    first = await asyncio.to_thread(_fetch_title, urls[0])
    if "error" in first:
        second = await asyncio.to_thread(_fetch_title, urls[1])
        if "error" not in second:
            return {"findings": [{"plugin": "http_title", "title": second.get("title"), "severity": "info", "data": second}], "artifacts": [second]}
    return {"findings": [{"plugin": "http_title", "title": first.get("title"), "severity": "info", "data": first}], "artifacts": [first]}
