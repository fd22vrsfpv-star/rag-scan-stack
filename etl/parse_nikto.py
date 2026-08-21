"""
Parse Nikto web server scan output into web_findings.

Handles both formats Nikto can emit:
  - XML  (`nikto -Format xml`)  : <niktoscan><scandetails><item>...
  - JSON (`nikto -Format json`) : {"host":..., "vulnerabilities":[{...}]}

SEVERITY: Nikto does not assign severities — every item is reported flat. Rather
than dumping everything as 'info' (which buries real issues) or inflating it all
(which floods triage), `_infer_severity` applies a conservative keyword ladder
and defaults to 'info'. The matched rule is recorded in `tags.severity_reason`
so an operator can see *why* something was rated the way it was, and re-triage
from the UI if they disagree.

Deduplication reuses `web_fingerprint` — the same shared helper Burp, ZAP and
Nuclei use — with source excluded from the hash, so a finding Nikto and ZAP both
report collapses to one row.
"""
import json
import logging
import os
import re
import uuid
from typing import Any, Dict, Optional
from xml.etree.ElementTree import ParseError, iterparse

import psycopg2
import requests

from etl.fingerprint import web_fingerprint

logger = logging.getLogger("parse_nikto")

DB_DSN = os.environ.get("DB_DSN", "postgresql://app:app@rag-postgres:5432/scans")
API_BASE = os.environ.get("API_BASE", "https://rag-api:8000")
API_KEY = os.environ.get("API_KEY", "changeme")
WEBHOOK_ENABLED = os.environ.get("WEBHOOK_ENABLED", "true").lower() == "true"

_IP_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

# Keyword ladder, highest severity first — first match wins. Deliberately
# conservative: Nikto is noisy and over-rating it poisons the triage queue.
_SEVERITY_RULES = (
    ("high", (
        "remote code execution", "rce", "command execution", "shell upload",
        "sql injection", "arbitrary file upload", "directory traversal",
        "path traversal", "authentication bypass",
    )),
    ("medium", (
        "xss", "cross site scripting", "cross-site scripting", "csrf",
        "default account", "default credentials", "admin login", "phpinfo",
        "backup file", "config file", "source code disclosure",
        "information disclosure", "outdated", "out of date",
    )),
    ("low", (
        "directory indexing", "directory listing", "trace method",
        "options method", "http methods", "cookie without", "missing header",
        "x-frame-options", "content-security-policy", "strict-transport-security",
        "server leaks", "banner",
    )),
)


def emit_webhook_event(event_type: str, source: str, data: dict, severity: str = None):
    """Emit a webhook event via the RAG API. Fire-and-forget."""
    if not WEBHOOK_ENABLED:
        return
    try:
        payload = {"event_type": event_type, "source": source, "data": data}
        if severity:
            payload["severity"] = severity
        requests.post(
            f"{API_BASE}/webhooks/emit",
            headers={"x-api-key": API_KEY, "Content-Type": "application/json"},
            json=payload, timeout=5, verify=False,
        )
    except Exception as e:
        logger.warning(f"Failed to emit webhook: {e}")


# Compiled once. Word boundaries matter: a bare substring test rates
# "possible source code disclosure" as high, because "rce" appears inside
# "source". Short acronyms (rce, xss, csrf) make that failure mode routine.
_SEVERITY_PATTERNS = tuple(
    (sev, tuple((kw, re.compile(r"\b" + re.escape(kw) + r"\b")) for kw in keywords))
    for sev, keywords in _SEVERITY_RULES
)


def _infer_severity(text: str) -> tuple:
    """Return (severity, reason). Defaults to ('info', 'default')."""
    low = (text or "").lower()
    for sev, patterns in _SEVERITY_PATTERNS:
        for kw, rx in patterns:
            if rx.search(low):
                return sev, kw
    return "info", "default"


try:
    from scope_gate import load_ingest_scope, host_in_scope
except ImportError:  # pragma: no cover — etl/ may already be on PYTHONPATH
    from etl.scope_gate import load_ingest_scope, host_in_scope


def extract_ip_from_url(url: str) -> Optional[str]:
    """Pull a literal IPv4 host out of a URL, if it is one."""
    m = re.match(r"https?://([^/:]+)", url or "")
    if not m:
        return None
    host = m.group(1)
    return host if _IP_RE.match(host) else None


def get_asset_id_for_ip(cur, ip: str) -> Optional[str]:
    """Resolve an IP to an existing asset id, if we know it."""
    if not ip:
        return None
    try:
        cur.execute("SELECT id FROM assets WHERE host(ip) = %s LIMIT 1", (ip,))
        row = cur.fetchone()
        return str(row[0]) if row else None
    except Exception:
        return None


def detect_nikto_format(filepath: str) -> str:
    """Return 'xml', 'json', or 'unknown' by sniffing the first bytes.

    Content-based rather than extension-based: operators routinely save a JSON
    report as .txt or pipe it through a filename that says nothing useful.
    """
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
            head = fh.read(4096).lstrip()
    except OSError:
        return "unknown"
    if not head:
        return "unknown"
    if head[0] in "{[":
        # Confirm it is actually Nikto-shaped JSON, not some other tool's.
        try:
            data = json.loads(head) if head.rstrip().endswith(("}", "]")) else None
        except json.JSONDecodeError:
            data = None
        if data is None:
            return "json" if '"vulnerabilities"' in head or '"niktoscan"' in head else "unknown"
        return "json"
    if "<niktoscan" in head.lower():
        return "xml"
    return "unknown"


def _build_url(host: str, port: str, uri: str, explicit: str = "") -> str:
    """Compose a finding URL from Nikto's split host/port/uri fields."""
    if explicit and explicit.startswith("http"):
        return explicit
    host = (host or "").strip()
    uri = (uri or "").strip()
    if host.startswith("http"):
        base = host.rstrip("/")
    else:
        try:
            p = int(port or 80)
        except (TypeError, ValueError):
            p = 80
        scheme = "https" if p in (443, 8443, 4443, 9443) else "http"
        base = f"{scheme}://{host}" if p in (80, 443) else f"{scheme}://{host}:{p}"
    if uri and not uri.startswith("/"):
        uri = "/" + uri
    return base + uri


def _insert_item(cur, stats: dict, dedupe: bool, *, url: str, message: str,
                 method: str, osvdb: str, item_id: str, host_ip: str,
                 enforce_scope: bool, scope_rows) -> None:
    """Insert one Nikto item as a web_finding."""
    if not url:
        stats["skipped_no_url"] += 1
        return

    severity, reason = _infer_severity(message)
    name = (message or "Nikto finding").strip()[:300]

    fp = web_fingerprint(url=url, source="nikto", name=name, issue_type="nikto")
    if dedupe:
        cur.execute("SELECT id FROM web_findings WHERE fingerprint = %s LIMIT 1", (fp,))
        if cur.fetchone():
            stats["skipped_duplicate"] += 1
            return

    ip = host_ip or extract_ip_from_url(url)
    asset_id = get_asset_id_for_ip(cur, ip) if ip else None

    refs = {}
    if osvdb and osvdb not in ("0", ""):
        refs["osvdb"] = osvdb
    tags = {"severity_reason": reason}
    if item_id:
        tags["nikto_id"] = item_id

    # Ingest scope gate, before the savepoint so a skip needs no rollback.
    # nikto follows redirects, so a scan pointed at one host can report findings
    # against wherever it was sent.
    if not host_in_scope(url, enforce_scope, scope_rows):
        stats["out_of_scope"] = stats.get("out_of_scope", 0) + 1
        return

    finding_id = str(uuid.uuid4())
    try:
        cur.execute("SAVEPOINT nikto_sp")
        cur.execute("""
            INSERT INTO web_findings
              (id, asset_id, url, source, issue_type, name, severity, evidence,
               method, refs, tags, first_seen, last_seen, fingerprint)
            VALUES (%s, %s, %s, 'nikto', 'nikto', %s, %s, %s, %s, %s, %s, now(), now(), %s)
            ON CONFLICT (fingerprint) DO UPDATE SET
                last_seen = now(),
                severity  = EXCLUDED.severity,
                evidence  = COALESCE(EXCLUDED.evidence, web_findings.evidence)
        """, (
            finding_id, asset_id, url, name, severity,
            (message or "")[:2000] or None,
            (method or None),
            json.dumps(refs) if refs else None,
            json.dumps(tags),
            fp,
        ))
        stats["inserted"] += 1
        stats["by_severity"][severity] = stats["by_severity"].get(severity, 0) + 1
        cur.execute("RELEASE SAVEPOINT nikto_sp")

        if severity == "high":
            emit_webhook_event("finding_high", "nikto", {
                "title": name, "url": url, "ip": ip,
                "description": (message or "")[:500],
            }, severity="high")
    except Exception as e:
        cur.execute("ROLLBACK TO SAVEPOINT nikto_sp")
        logger.error(f"  [DB] Insert error: {e}")
        stats["errors"].append(str(e))


def _parse_xml(filepath: str, cur, stats: dict, dedupe: bool,
               enforce_scope: bool, scope_rows) -> None:
    """Stream a Nikto XML report. iterparse keeps memory flat on big scans."""
    host = port = host_ip = ""
    for event, elem in iterparse(filepath, events=("start", "end")):
        tag = elem.tag.lower()
        if event == "start" and tag == "scandetails":
            host = elem.get("targethostname") or elem.get("targetip") or ""
            host_ip = elem.get("targetip") or ""
            port = elem.get("targetport") or "80"
            continue
        if event != "end" or tag != "item":
            continue
        _insert_item(
            cur, stats, dedupe,
            url=_build_url(host, port,
                           elem.findtext("uri") or "",
                           (elem.findtext("namelink") or "").strip()),
            message=(elem.findtext("description") or "").strip(),
            method=elem.get("method") or "GET",
            osvdb=elem.get("osvdbid") or "",
            item_id=elem.get("id") or "",
            host_ip=host_ip,
            enforce_scope=enforce_scope, scope_rows=scope_rows,
        )
        elem.clear()


def _parse_json(filepath: str, cur, stats: dict, dedupe: bool,
                enforce_scope: bool, scope_rows) -> None:
    """Parse a Nikto JSON report.

    Nikto has shipped this as both a single object and a list of host objects
    depending on version, so both shapes are accepted.
    """
    with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
        data = json.load(fh)
    hosts = data if isinstance(data, list) else [data]
    for entry in hosts:
        if not isinstance(entry, dict):
            continue
        host = entry.get("host") or entry.get("hostname") or entry.get("ip") or ""
        host_ip = entry.get("ip") or ""
        port = str(entry.get("port") or "80")
        for vuln in (entry.get("vulnerabilities") or []):
            if not isinstance(vuln, dict):
                continue
            _insert_item(
                cur, stats, dedupe,
                url=_build_url(host, port, vuln.get("url") or "", vuln.get("url") or ""),
                message=(vuln.get("msg") or vuln.get("description") or "").strip(),
                method=vuln.get("method") or "GET",
                osvdb=str(vuln.get("OSVDB") or vuln.get("osvdb") or ""),
                item_id=str(vuln.get("id") or ""),
                host_ip=host_ip,
                enforce_scope=enforce_scope, scope_rows=scope_rows,
            )


def parse_nikto(filepath: str, profile: str = "cli", dedupe: bool = True) -> Dict[str, Any]:
    """
    Parse a Nikto report (XML or JSON) and insert findings into web_findings.

    Args:
        filepath: Path to the Nikto report
        profile:  Ingest profile label (provenance only)
        dedupe:   Skip findings whose fingerprint already exists

    Returns a stats dict: format, inserted, skipped_duplicate, skipped_no_url,
    by_severity, errors.
    """
    stats: Dict[str, Any] = {
        "format": "unknown", "inserted": 0, "skipped_duplicate": 0,
        "skipped_no_url": 0, "by_severity": {}, "errors": [], "profile": profile,
    }

    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Nikto report not found: {filepath}")

    fmt = detect_nikto_format(filepath)
    stats["format"] = fmt
    if fmt == "unknown":
        raise ValueError(
            f"{filepath} does not look like a Nikto XML or JSON report "
            "(expected a <niktoscan> root or a JSON object with 'vulnerabilities')"
        )

    conn = psycopg2.connect(DB_DSN)
    try:
        with conn.cursor() as cur:
            _enforce_scope, _scope_rows = load_ingest_scope(cur)
            if fmt == "xml":
                try:
                    _parse_xml(filepath, cur, stats, dedupe, _enforce_scope, _scope_rows)
                except ParseError as e:
                    raise ValueError(f"Malformed Nikto XML: {e}") from e
            else:
                try:
                    _parse_json(filepath, cur, stats, dedupe, _enforce_scope, _scope_rows)
                except json.JSONDecodeError as e:
                    raise ValueError(f"Malformed Nikto JSON: {e}") from e
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

    logger.info(
        f"[nikto] {fmt}: inserted={stats['inserted']} "
        f"dupes={stats['skipped_duplicate']} severities={stats['by_severity']}"
    )
    if stats["inserted"]:
        emit_webhook_event("web_scan_parsed", "nikto", {
            "format": fmt, "inserted": stats["inserted"],
            "by_severity": stats["by_severity"], "profile": profile,
        })
    return stats


if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO)
    if len(sys.argv) < 2:
        print("usage: python -m etl.parse_nikto <report.xml|report.json>")
        raise SystemExit(2)
    print(json.dumps(parse_nikto(sys.argv[1]), indent=2))
