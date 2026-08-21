"""
Parse an OWASP ZAP *report file* into web_findings.

WHY A SEPARATE MODULE FROM parse_zap.py:
    `parse_zap.py` pulls alerts from a **live ZAP instance's API** — it needs a
    running ZAP to talk to. That is the right path for scans this stack drives
    itself, but it cannot ingest a report someone hands you from an engagement
    run elsewhere. This module reads a saved report off disk instead. Both write
    the same `web_findings` shape with `source='zap'`, and both use the shared
    `web_fingerprint`, so findings deduplicate across the two paths.

Handles the two report formats ZAP exports:
  - JSON (`-Report ... -format json`): {"site":[{"alerts":[{...,"instances":[...]}]}]}
  - XML  (traditional report):          <OWASPZAPReport><site><alerts><alertitem>

ZAP reports one alert with N instances (one per affected URL). Each instance
becomes its own web_finding so per-URL triage works, matching how the live-API
path already behaves.
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

logger = logging.getLogger("parse_zap_file")

DB_DSN = os.environ.get("DB_DSN", "postgresql://app:app@rag-postgres:5432/scans")
API_BASE = os.environ.get("API_BASE", "https://rag-api:8000")
API_KEY = os.environ.get("API_KEY", "changeme")
WEBHOOK_ENABLED = os.environ.get("WEBHOOK_ENABLED", "true").lower() == "true"

_IP_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

# Mirrors SEVERITY_MAP in parse_zap.py — keep the two in sync so the same alert
# lands with the same severity whichever path ingested it.
SEVERITY_MAP = {
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "info",
    "information": "info",
    "info": "info",
    "false positive": None,   # skip
}

# XML <riskcode> is numeric; JSON reports carry the word form.
RISKCODE_MAP = {"0": "info", "1": "low", "2": "medium", "3": "high"}


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


try:
    from scope_gate import load_ingest_scope, host_in_scope
except ImportError:  # pragma: no cover — etl/ may already be on PYTHONPATH
    from etl.scope_gate import load_ingest_scope, host_in_scope


def extract_ip_from_url(url: str) -> Optional[str]:
    m = re.match(r"https?://([^/:]+)", url or "")
    if not m:
        return None
    host = m.group(1)
    return host if _IP_RE.match(host) else None


def get_asset_id_for_ip(cur, ip: str) -> Optional[str]:
    if not ip:
        return None
    try:
        cur.execute("SELECT id FROM assets WHERE host(ip) = %s LIMIT 1", (ip,))
        row = cur.fetchone()
        return str(row[0]) if row else None
    except Exception:
        return None


def _strip_html(text: str) -> str:
    """ZAP descriptions are HTML fragments; findings render as plain text."""
    if not text:
        return ""
    return re.sub(r"<[^>]+>", "", text).replace("&lt;", "<").replace("&gt;", ">") \
             .replace("&amp;", "&").replace("&quot;", '"').strip()


def _map_severity(risk_raw: str, riskcode: str = "") -> Optional[str]:
    """Resolve ZAP's risk wording (or numeric riskcode) to our severity scale.

    Returns None for false positives, which the caller skips.
    """
    raw = (risk_raw or "").strip().lower()
    # ZAP sometimes writes "Medium (High)" — confidence in parentheses.
    raw = raw.split("(")[0].strip()
    if raw in SEVERITY_MAP:
        return SEVERITY_MAP[raw]
    if riskcode and str(riskcode).strip() in RISKCODE_MAP:
        return RISKCODE_MAP[str(riskcode).strip()]
    return "info"


def detect_zap_format(filepath: str) -> str:
    """Return 'json', 'xml', or 'unknown' by sniffing content, not extension."""
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
            head = fh.read(4096).lstrip()
    except OSError:
        return "unknown"
    if not head:
        return "unknown"
    if head[0] in "{[":
        return "json" if ('"site"' in head or '"alerts"' in head or '"@programName"' in head) else "unknown"
    if "owaspzapreport" in head.lower() or "<alertitem" in head.lower():
        return "xml"
    return "unknown"


def _insert_finding(cur, stats: dict, dedupe: bool, *, url: str, name: str,
                    severity: str, evidence: str, method: str, attack: str,
                    cwe: str, description: str, solution: str, reference: str,
                    confidence: str, plugin_id: str, param: str,
                    enforce_scope: bool, scope_rows) -> None:
    if not url:
        stats["skipped_no_url"] += 1
        return

    # Ingest scope gate, applied at the single insert chokepoint so every alert
    # in the report is judged. ZAP follows links, so a spidered report can carry
    # third-party hosts that nobody asked about.
    if not host_in_scope(url, enforce_scope, scope_rows):
        stats["out_of_scope"] = stats.get("out_of_scope", 0) + 1
        return

    fp = web_fingerprint(url=url, source="zap", name=name, issue_type="zap-alert")
    if dedupe:
        cur.execute("SELECT id FROM web_findings WHERE fingerprint = %s LIMIT 1", (fp,))
        if cur.fetchone():
            stats["skipped_duplicate"] += 1
            return

    ip = extract_ip_from_url(url)
    asset_id = get_asset_id_for_ip(cur, ip) if ip else None

    cwe_list = [f"CWE-{cwe}"] if cwe and str(cwe).isdigit() and cwe != "0" else None
    refs = {"reference": reference} if reference else {}
    tags = {"import": "zap-file"}
    if plugin_id:
        tags["zap_plugin_id"] = str(plugin_id)
    if param:
        tags["param"] = param

    finding_id = str(uuid.uuid4())
    try:
        cur.execute("SAVEPOINT zapf_sp")
        cur.execute("""
            INSERT INTO web_findings
              (id, asset_id, url, source, issue_type, name, severity, evidence,
               method, payload, cwe, refs, description, solution, reference,
               confidence, tags, first_seen, last_seen, fingerprint)
            VALUES (%s, %s, %s, 'zap', 'zap-alert', %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, now(), now(), %s)
            ON CONFLICT (fingerprint) DO UPDATE SET
                last_seen = now(),
                severity  = EXCLUDED.severity,
                evidence  = COALESCE(EXCLUDED.evidence, web_findings.evidence)
        """, (
            finding_id, asset_id, url, name, severity,
            (evidence or None), (method or None), (attack or None),
            cwe_list, json.dumps(refs) if refs else None,
            (description or None), (solution or None), (reference or None),
            (confidence or None), json.dumps(tags), fp,
        ))
        stats["inserted"] += 1
        stats["by_severity"][severity] = stats["by_severity"].get(severity, 0) + 1
        cur.execute("RELEASE SAVEPOINT zapf_sp")

        if severity == "high":
            emit_webhook_event("finding_high", "zap", {
                "title": name, "url": url, "ip": ip,
                "description": (description or "")[:500],
            }, severity="high")
    except Exception as e:
        cur.execute("ROLLBACK TO SAVEPOINT zapf_sp")
        logger.error(f"  [DB] Insert error: {e}")
        stats["errors"].append(str(e))


def _parse_json(filepath: str, cur, stats: dict, dedupe: bool,
                enforce_scope: bool, scope_rows) -> None:
    with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
        data = json.load(fh)

    # Report root is usually {"site": [...]}; some exports are a bare list.
    sites = data.get("site") if isinstance(data, dict) else data
    if isinstance(sites, dict):
        sites = [sites]
    for site in (sites or []):
        if not isinstance(site, dict):
            continue
        site_url = site.get("@name") or site.get("name") or ""
        for alert in (site.get("alerts") or []):
            if not isinstance(alert, dict):
                continue
            severity = _map_severity(alert.get("riskdesc") or alert.get("risk") or "",
                                     alert.get("riskcode") or "")
            if severity is None:
                stats["skipped_false_positive"] += 1
                continue
            name = (alert.get("name") or alert.get("alert") or "ZAP alert").strip()
            desc = _strip_html(alert.get("desc") or alert.get("description") or "")
            soln = _strip_html(alert.get("solution") or "")
            ref = _strip_html(alert.get("reference") or "")
            cwe = str(alert.get("cweid") or "")
            plugin_id = str(alert.get("pluginid") or "")
            confidence = str(alert.get("confidence") or "")

            instances = alert.get("instances") or []
            if not instances:
                # Alert with no per-URL instances — record it against the site.
                instances = [{"uri": site_url}]
            for inst in instances:
                if not isinstance(inst, dict):
                    continue
                _insert_finding(
                    cur, stats, dedupe,
                    url=inst.get("uri") or site_url,
                    name=name, severity=severity,
                    evidence=inst.get("evidence") or "",
                    method=inst.get("method") or "",
                    attack=inst.get("attack") or "",
                    cwe=cwe, description=desc, solution=soln, reference=ref,
                    confidence=confidence, plugin_id=plugin_id,
                    param=inst.get("param") or "",
                    enforce_scope=enforce_scope, scope_rows=scope_rows,
                )


def _parse_xml(filepath: str, cur, stats: dict, dedupe: bool,
               enforce_scope: bool, scope_rows) -> None:
    """Stream a ZAP XML report; <alertitem> carries the alert, <instance> the URLs."""
    for event, elem in iterparse(filepath, events=("end",)):
        if elem.tag.lower() != "alertitem":
            continue
        severity = _map_severity(elem.findtext("riskdesc") or "",
                                 elem.findtext("riskcode") or "")
        if severity is None:
            stats["skipped_false_positive"] += 1
            elem.clear()
            continue

        name = (elem.findtext("alert") or elem.findtext("name") or "ZAP alert").strip()
        desc = _strip_html(elem.findtext("desc") or "")
        soln = _strip_html(elem.findtext("solution") or "")
        ref = _strip_html(elem.findtext("reference") or "")
        cwe = (elem.findtext("cweid") or "").strip()
        plugin_id = (elem.findtext("pluginid") or "").strip()
        confidence = (elem.findtext("confidencedesc") or elem.findtext("confidence") or "").strip()

        instances = elem.findall("./instances/instance")
        if not instances:
            uri = (elem.findtext("uri") or "").strip()
            if uri:
                _insert_finding(cur, stats, dedupe, url=uri, name=name,
                                enforce_scope=enforce_scope, scope_rows=scope_rows,
                                severity=severity, evidence=elem.findtext("evidence") or "",
                                method=elem.findtext("method") or "",
                                attack=elem.findtext("attack") or "", cwe=cwe,
                                description=desc, solution=soln, reference=ref,
                                confidence=confidence, plugin_id=plugin_id,
                                param=elem.findtext("param") or "")
        for inst in instances:
            _insert_finding(
                cur, stats, dedupe,
                url=(inst.findtext("uri") or "").strip(),
                name=name, severity=severity,
                evidence=inst.findtext("evidence") or "",
                method=inst.findtext("method") or "",
                attack=inst.findtext("attack") or "",
                cwe=cwe, description=desc, solution=soln, reference=ref,
                confidence=confidence, plugin_id=plugin_id,
                param=inst.findtext("param") or "",
                enforce_scope=enforce_scope, scope_rows=scope_rows,
            )
        elem.clear()


def parse_zap_file(filepath: str, profile: str = "cli", dedupe: bool = True) -> Dict[str, Any]:
    """
    Parse a saved ZAP report (JSON or XML) into web_findings.

    Args:
        filepath: Path to the ZAP report
        profile:  Ingest profile label (provenance only)
        dedupe:   Skip findings whose fingerprint already exists

    Returns a stats dict: format, inserted, skipped_duplicate,
    skipped_false_positive, skipped_no_url, by_severity, errors.
    """
    stats: Dict[str, Any] = {
        "format": "unknown", "inserted": 0, "skipped_duplicate": 0,
        "skipped_false_positive": 0, "skipped_no_url": 0,
        "by_severity": {}, "errors": [], "profile": profile,
    }

    if not os.path.exists(filepath):
        raise FileNotFoundError(f"ZAP report not found: {filepath}")

    fmt = detect_zap_format(filepath)
    stats["format"] = fmt
    if fmt == "unknown":
        raise ValueError(
            f"{filepath} does not look like a ZAP report "
            "(expected an <OWASPZAPReport> root or JSON with a 'site' key)"
        )

    conn = psycopg2.connect(DB_DSN)
    try:
        with conn.cursor() as cur:
            # Loaded once per report; passed to every insert so the gate cannot be
            # forgotten at one of the three call sites.
            _enforce_scope, _scope_rows = load_ingest_scope(cur)
            if fmt == "xml":
                try:
                    _parse_xml(filepath, cur, stats, dedupe, _enforce_scope, _scope_rows)
                except ParseError as e:
                    raise ValueError(f"Malformed ZAP XML: {e}") from e
            else:
                try:
                    _parse_json(filepath, cur, stats, dedupe, _enforce_scope, _scope_rows)
                except json.JSONDecodeError as e:
                    raise ValueError(f"Malformed ZAP JSON: {e}") from e
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

    logger.info(
        f"[zap-file] {fmt}: inserted={stats['inserted']} "
        f"dupes={stats['skipped_duplicate']} fp={stats['skipped_false_positive']} "
        f"severities={stats['by_severity']}"
    )
    if stats["inserted"]:
        emit_webhook_event("web_scan_parsed", "zap", {
            "format": fmt, "inserted": stats["inserted"],
            "by_severity": stats["by_severity"], "profile": profile,
        })
    return stats


if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO)
    if len(sys.argv) < 2:
        print("usage: python -m etl.parse_zap_file <report.json|report.xml>")
        raise SystemExit(2)
    print(json.dumps(parse_zap_file(sys.argv[1]), indent=2))
