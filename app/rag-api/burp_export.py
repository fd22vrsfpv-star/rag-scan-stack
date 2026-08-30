"""Export a security_test's command/payload to a Burp-ingestible form.

The whole point of this platform is to feed MANUAL tools (CLAUDE.md): a custom
test or payload is only useful to a tester if they can drop it into Burp. Burp
imports HAR (File -> ... -> Import) and pastes raw HTTP into Repeater, so we
emit both:
  * a raw HTTP/1.1 request (for Repeater paste), and
  * a HAR log (for Import), one entry per test.

The test command is parsed best-effort: `curl` commands yield the exact method /
URL / headers / body (the payload lands where the tester expects it); non-HTTP
commands (nuclei/sqlmap/...) fall back to a GET on the target with the command
and payload preserved in a comment so the tester can pivot into Burp manually.
"""
from __future__ import annotations

import json
import shlex
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit, parse_qsl

_UA = "Mozilla/5.0 (X11; Linux x86_64; rv:115.0) Gecko/20100101 Firefox/115.0"


def parse_curl(command: str) -> Optional[Dict[str, Any]]:
    """Best-effort curl -> {method, url, headers{}, body}. None if not a curl or
    no URL can be found."""
    if not command:
        return None
    try:
        toks = shlex.split(command)
    except ValueError:
        toks = command.split()
    if not toks or toks[0].split("/")[-1] != "curl":
        return None
    method, url, body = None, None, None
    headers: Dict[str, str] = {}
    i = 1
    while i < len(toks):
        t = toks[i]
        if t in ("-X", "--request") and i + 1 < len(toks):
            method = toks[i + 1].upper(); i += 2; continue
        if t in ("-H", "--header") and i + 1 < len(toks):
            hv = toks[i + 1]
            if ":" in hv:
                k, v = hv.split(":", 1); headers[k.strip()] = v.strip()
            i += 2; continue
        if t in ("-d", "--data", "--data-raw", "--data-binary") and i + 1 < len(toks):
            body = toks[i + 1]; i += 2; continue
        if t in ("-A", "--user-agent") and i + 1 < len(toks):
            headers["User-Agent"] = toks[i + 1]; i += 2; continue
        if t in ("-b", "--cookie") and i + 1 < len(toks):
            headers["Cookie"] = toks[i + 1]; i += 2; continue
        if t.startswith("http://") or t.startswith("https://"):
            url = t
        i += 1
    if not url:
        return None
    if body and not method:
        method = "POST"
    return {"method": method or "GET", "url": url, "headers": headers, "body": body}


def _http_from_target(target_ip: Optional[str], target_port: Optional[int],
                      service: Optional[str]) -> Dict[str, Any]:
    port = target_port or 80
    scheme = "https" if port in (443, 8443) or "ssl" in str(service or "").lower() else "http"
    hostport = f"{target_ip or 'TARGET'}:{port}"
    return {"method": "GET", "url": f"{scheme}://{hostport}/", "headers": {}, "body": None}


def to_raw_request(req: Dict[str, Any], comment: str = "") -> str:
    sp = urlsplit(req["url"])
    path = sp.path or "/"
    if sp.query:
        path += "?" + sp.query
    host = sp.netloc
    headers = dict(req.get("headers") or {})
    headers.setdefault("Host", host)
    headers.setdefault("User-Agent", _UA)
    headers.setdefault("Accept", "*/*")
    headers.setdefault("Connection", "close")
    body = req.get("body") or ""
    if body:
        headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
        headers["Content-Length"] = str(len(body))
    lines = [f"{req['method']} {path} HTTP/1.1"]
    # Host first, then the rest
    lines.append(f"Host: {headers.pop('Host')}")
    for k, v in headers.items():
        lines.append(f"{k}: {v}")
    raw = "\r\n".join(lines) + "\r\n\r\n" + body
    if comment:
        raw += "\r\n\r\n" + "\n".join("# " + c for c in comment.splitlines())
    return raw


def to_har_entry(req: Dict[str, Any], comment: str = "") -> Dict[str, Any]:
    sp = urlsplit(req["url"])
    headers = dict(req.get("headers") or {})
    headers.setdefault("Host", sp.netloc)
    headers.setdefault("User-Agent", _UA)
    body = req.get("body")
    entry: Dict[str, Any] = {
        "startedDateTime": datetime.now(timezone.utc).isoformat(),
        "time": 0,
        "request": {
            "method": req["method"],
            "url": req["url"],
            "httpVersion": "HTTP/1.1",
            "headers": [{"name": k, "value": v} for k, v in headers.items()],
            "queryString": [{"name": k, "value": v} for k, v in parse_qsl(sp.query)],
            "cookies": [],
            "headersSize": -1,
            "bodySize": len(body) if body else 0,
            "comment": comment,
        },
        "response": {"status": 0, "statusText": "", "httpVersion": "HTTP/1.1",
                     "headers": [], "cookies": [], "content": {"size": 0, "mimeType": ""},
                     "redirectURL": "", "headersSize": -1, "bodySize": -1},
        "cache": {}, "timings": {"send": 0, "wait": 0, "receive": 0},
    }
    if body:
        entry["request"]["postData"] = {
            "mimeType": (req.get("headers") or {}).get("Content-Type",
                                                       "application/x-www-form-urlencoded"),
            "text": body}
    return entry


def build_har(entries: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {"log": {"version": "1.2",
                    "creator": {"name": "RAG Scan Stack — Security Tests", "version": "1.0"},
                    "entries": entries}}


def _req_for_test(t: Dict[str, Any]) -> Tuple[Dict[str, Any], str]:
    """Return (http_request, comment) for one security_test row."""
    cmd = t.get("command") or ""
    parsed = parse_curl(cmd)
    comment_lines = [
        f"Security test: {t.get('name')}",
        f"tier={t.get('tier')} category={t.get('category')} tool={t.get('tool')}",
        f"command: {cmd}" if cmd else "command: (none)",
    ]
    assertion = t.get("assertion")
    if assertion:
        comment_lines.append("assertion: " + json.dumps(assertion))
    if parsed:
        return parsed, "\n".join(comment_lines)
    # non-HTTP tool: synthesize a GET to the target and keep the command in the note
    req = _http_from_target(str(t.get("target_ip") or "") or None,
                            t.get("target_port"), t.get("target_service"))
    comment_lines.append("NOTE: this tool is not a raw HTTP request — sent as a "
                         "GET to the target; use the command/payload above in Burp.")
    return req, "\n".join(comment_lines)


def export_test(t: Dict[str, Any], fmt: str = "har") -> Tuple[str, str, str]:
    """Return (data, filename, content_type) for one test. fmt: 'har' | 'request'."""
    req, comment = _req_for_test(t)
    tid = str(t.get("id") or "test")[:8]
    if fmt == "request":
        return to_raw_request(req, comment), f"sectest_{tid}.txt", "text/plain"
    har = build_har([to_har_entry(req, comment)])
    return json.dumps(har, indent=2), f"sectest_{tid}.har", "application/json"


def export_tests(rows: List[Dict[str, Any]], fmt: str = "har") -> Tuple[str, str, str]:
    """Bulk export many tests as ONE HAR (or concatenated raw requests)."""
    if fmt == "request":
        blocks = []
        for t in rows:
            req, comment = _req_for_test(t)
            blocks.append(to_raw_request(req, comment))
        return ("\n\n" + "=" * 60 + "\n\n").join(blocks), "sectests.txt", "text/plain"
    entries = []
    for t in rows:
        req, comment = _req_for_test(t)
        entries.append(to_har_entry(req, comment))
    return json.dumps(build_har(entries), indent=2), "sectests.har", "application/json"
