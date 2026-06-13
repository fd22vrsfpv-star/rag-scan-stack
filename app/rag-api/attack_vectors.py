"""
Attack "vector map" — maps findings to MITRE ATT&CK techniques and computes a
unified risk score for attack-path prioritization.

Config-driven: all technique mappings and risk weights live in
knowledge/mitre/attack_map.yaml (git-tracked, reloads on restart). This module
only INTERPRETS that config — no hardcoded technique lists or weights.

Consumed by:
  - the AI agents (ranked next-best-action via /attack-vectors + an MCP tool),
  - the Attack Map UI (/attack-vectors/graph),
  - the webhook bus (attack_vectors_recomputed).
"""
import os
import json
import logging
from typing import Any, Dict, List, Optional, Tuple

import psycopg2
from psycopg2.extras import RealDictCursor, Json

logger = logging.getLogger("attack_vectors")

DB_DSN = os.environ.get("DB_DSN", "postgresql://app:app@rag-postgres:5432/scans")
ATTACK_MAP_PATH = os.environ.get("ATTACK_MAP_PATH", "/knowledge/mitre/attack_map.yaml")

_CONFIG: Optional[Dict[str, Any]] = None
_CONFIG_MTIME: float = 0.0


def _get_conn():
    return psycopg2.connect(DB_DSN)


def load_config() -> Dict[str, Any]:
    """Load + cache the ATT&CK map config; reloads if the file changed on disk."""
    global _CONFIG, _CONFIG_MTIME
    try:
        mtime = os.path.getmtime(ATTACK_MAP_PATH)
    except OSError:
        mtime = 0.0
    if _CONFIG is not None and mtime == _CONFIG_MTIME:
        return _CONFIG
    import yaml
    try:
        with open(ATTACK_MAP_PATH) as f:
            _CONFIG = yaml.safe_load(f) or {}
        _CONFIG_MTIME = mtime
        logger.info("attack_map loaded: %d techniques, %d rules",
                    len(_CONFIG.get("techniques", {})), len(_CONFIG.get("rules", [])))
    except Exception as e:
        logger.error("attack_map load failed (%s); using empty config", e)
        _CONFIG = _CONFIG or {}
    return _CONFIG


# ---- finding -> technique mapping -------------------------------------------

def _haystack(finding: Dict[str, Any]) -> str:
    parts = [
        finding.get("title"), finding.get("issue_type"), finding.get("name"),
        finding.get("script"), finding.get("finding_type"), finding.get("output"),
        finding.get("evidence"), finding.get("service"),
    ]
    return " ".join(str(p) for p in parts if p).lower()


def _rule_matches(rule: Dict[str, Any], finding: Dict[str, Any], hay: str) -> bool:
    """A rule matches if EVERY key it specifies matches the finding."""
    cwes = {c.upper() for c in (finding.get("cwe") or [])}
    if rule.get("cwe") and not (cwes & {c.upper() for c in rule["cwe"]}):
        # cwe is an OR with keyword in many rules; treat cwe as satisfying on its own,
        # but only fail here if NO other positive key matches below.
        cwe_ok = False
    else:
        cwe_ok = bool(rule.get("cwe"))

    svc = (finding.get("service") or "").lower()
    if rule.get("service"):
        if not any(s.lower() in svc for s in rule["service"] if svc):
            return False
    if rule.get("source"):
        if (finding.get("source") or "").lower() not in {s.lower() for s in rule["source"]}:
            return False
    if rule.get("finding_type") or rule.get("issue_type"):
        want = {s.lower() for s in (rule.get("finding_type") or []) + (rule.get("issue_type") or [])}
        have = {(finding.get("finding_type") or "").lower(), (finding.get("issue_type") or "").lower()}
        if not (want & have):
            return False
    if rule.get("keyword"):
        kw_ok = any(k.lower() in hay for k in rule["keyword"])
        # keyword OR cwe (either signal is enough when both are listed)
        if not kw_ok and not cwe_ok:
            return False
    elif rule.get("cwe") and not cwe_ok:
        return False
    return True


def map_finding(finding: Dict[str, Any]) -> List[Tuple[str, str, float]]:
    """Return [(technique_id, tactic, confidence)] for a finding via config rules."""
    cfg = load_config()
    techniques = cfg.get("techniques", {})
    hay = _haystack(finding)
    out: Dict[str, Tuple[str, float]] = {}
    for rule in cfg.get("rules", []):
        if not _rule_matches(rule, finding, hay):
            continue
        tid = rule.get("technique")
        if not tid:
            continue
        conf = float(rule.get("confidence", 0.6))
        if tid not in out or conf > out[tid][1]:
            tactic = (techniques.get(tid) or {}).get("tactic", "")
            out[tid] = (tactic, conf)
    return [(tid, tac, conf) for tid, (tac, conf) in out.items()]


# ---- risk scoring -----------------------------------------------------------

def _risk_score(finding: Dict[str, Any], tactic: str, kev: bool, exploit: bool,
                cfg: Dict[str, Any]) -> Tuple[float, Dict[str, float]]:
    r = cfg.get("risk", {})
    w = r.get("weights", {})
    sev_scores = r.get("severity_scores", {})
    crit_tags = r.get("asset_criticality_tags", {})
    tactics = cfg.get("tactics", {})

    sev = (finding.get("severity") or "info").lower()
    terms = {
        "severity": float(sev_scores.get(sev, 0.05)),
        "cvss": min(float(finding.get("cvss") or 0) / 10.0, 1.0),
        "kev": 1.0 if kev else 0.0,
        "exploit_available": 1.0 if exploit else 0.0,
        "tactic_position": float((tactics.get(tactic) or {}).get("position", 0.0)),
        "asset_criticality": 0.0,
    }
    tags = [t.lower() for t in (finding.get("asset_tags") or [])]
    env = (finding.get("asset_env") or "").lower()
    crit = [float(v) for k, v in crit_tags.items() if k.lower() in tags or k.lower() == env]
    terms["asset_criticality"] = max(crit) if crit else 0.0

    score = 100.0 * sum(float(w.get(k, 0)) * v for k, v in terms.items())
    return round(min(score, 100.0), 1), {k: round(v, 3) for k, v in terms.items()}


# ---- data access ------------------------------------------------------------

def _fetch_findings(cur, engagement_id: Optional[str]) -> List[Dict[str, Any]]:
    eng = "AND f.engagement_id = %(eid)s" if engagement_id else ""
    params = {"eid": engagement_id}
    rows: List[Dict[str, Any]] = []

    cur.execute(f"""
        SELECT 'vuln' AS source, f.id, f.asset_id, f.severity, f.cve, f.cvss,
               NULL::text[] AS cwe, f.title, f.script, f.output,
               NULL AS issue_type, NULL AS name, NULL AS evidence, NULL AS finding_type,
               p.service AS service, host(a.ip)::text AS target, a.tags AS asset_tags, a.env AS asset_env
        FROM public.vulns f
        JOIN public.assets a ON a.id = f.asset_id
        LEFT JOIN public.ports p ON p.id = f.port_id
        WHERE 1=1 {eng}
    """, params)
    rows += [dict(r) for r in cur.fetchall()]

    cur.execute(f"""
        SELECT 'web_finding' AS source, f.id, f.asset_id, f.severity, NULL::text[] AS cve, NULL AS cvss,
               f.cwe, COALESCE(f.name, f.issue_type) AS title, NULL AS script, NULL AS output,
               f.issue_type, f.name, f.evidence, NULL AS finding_type,
               f.source AS service, COALESCE(f.url, host(a.ip)::text) AS target, a.tags AS asset_tags, a.env AS asset_env
        FROM public.web_findings f
        JOIN public.assets a ON a.id = f.asset_id
        WHERE 1=1 {eng}
    """, params)
    rows += [dict(r) for r in cur.fetchall()]

    cur.execute(f"""
        SELECT 'recon_finding' AS source, f.id, f.asset_id, f.severity, NULL::text[] AS cve, NULL AS cvss,
               NULL::text[] AS cwe, f.finding_type AS title, NULL AS script, NULL AS output,
               NULL AS issue_type, NULL AS name, NULL AS evidence, f.finding_type,
               f.source AS service, f.target AS target,
               a.tags AS asset_tags, a.env AS asset_env
        FROM public.recon_findings f
        LEFT JOIN public.assets a ON a.id = f.asset_id
        WHERE 1=1 {eng}
    """, params)
    rows += [dict(r) for r in cur.fetchall()]
    return rows


def _kev_cves(cur) -> set:
    # cur is a RealDictCursor → rows are dicts; alias and read by key.
    cur.execute("SELECT upper(cve_id) AS cve FROM public.cisa_kev_cache")
    return {r["cve"] for r in cur.fetchall() if r.get("cve")}


def _assets_with_exploits(cur) -> set:
    cur.execute("SELECT DISTINCT asset_id FROM public.pending_exploits WHERE asset_id IS NOT NULL")
    return {str(r["asset_id"]) for r in cur.fetchall()}


def compute_attack_vectors(engagement_id: Optional[str] = None) -> Dict[str, Any]:
    """(Re)compute attack vectors for findings, mapping each to ATT&CK techniques
    and scoring risk. Idempotent upsert into attack_vectors. Returns counts."""
    cfg = load_config()
    techniques = cfg.get("techniques", {})
    written = 0
    considered = 0
    conn = _get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            findings = _fetch_findings(cur, engagement_id)
            kev = _kev_cves(cur)
            exploit_assets = _assets_with_exploits(cur)
        considered = len(findings)
        with conn.cursor() as cur:
            for f in findings:
                mapped = map_finding(f)
                if not mapped:
                    continue
                cve_set = {c.upper() for c in (f.get("cve") or [])}
                is_kev = bool(cve_set & kev)
                has_exploit = str(f.get("asset_id")) in exploit_assets
                for tid, tactic, conf in mapped:
                    score, factors = _risk_score(f, tactic, is_kev, has_exploit, cfg)
                    factors["technique_confidence"] = round(conf, 3)
                    tname = (techniques.get(tid) or {}).get("name")
                    rationale = (f"{f.get('title') or f.get('source')} → {tid} {tname or ''}"
                                 f" ({tactic})").strip()
                    cur.execute("""
                        INSERT INTO public.attack_vectors
                          (engagement_id, asset_id, finding_source, finding_id, technique,
                           technique_name, tactic, kill_chain_phase, severity, risk_score,
                           risk_factors, rationale, target)
                        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s,%s)
                        ON CONFLICT (finding_source, finding_id, technique) DO UPDATE SET
                          risk_score = EXCLUDED.risk_score,
                          risk_factors = EXCLUDED.risk_factors,
                          severity = EXCLUDED.severity,
                          rationale = EXCLUDED.rationale,
                          target = EXCLUDED.target,
                          tactic = EXCLUDED.tactic,
                          technique_name = EXCLUDED.technique_name,
                          updated_at = now()
                    """, (
                        engagement_id, f.get("asset_id"), f["source"], f["id"], tid,
                        tname, tactic, tactic, f.get("severity"), score,
                        Json(factors), rationale, f.get("target"),
                    ))
                    written += 1
        conn.commit()
    finally:
        conn.close()
    logger.info("attack_vectors computed: %d findings -> %d vectors (eng=%s)",
                considered, written, engagement_id)
    return {"findings_considered": considered, "vectors_written": written}


def get_attack_vectors(engagement_id: Optional[str] = None, limit: int = 100,
                       min_risk: float = 0.0) -> List[Dict[str, Any]]:
    """Ranked attack vectors (highest risk first) — the AI's prioritized list."""
    conn = _get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            where = ["risk_score >= %(min)s"]
            params: Dict[str, Any] = {"min": min_risk, "limit": limit}
            if engagement_id:
                where.append("engagement_id = %(eid)s")
                params["eid"] = engagement_id
            cur.execute(f"""
                SELECT id, engagement_id, asset_id, finding_source, finding_id,
                       technique, technique_name, tactic, severity, risk_score,
                       risk_factors, rationale, target, updated_at
                FROM public.attack_vectors
                WHERE {' AND '.join(where)}
                ORDER BY risk_score DESC, updated_at DESC
                LIMIT %(limit)s
            """, params)
            return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()


def get_graph(engagement_id: Optional[str] = None) -> Dict[str, Any]:
    """Nodes + edges for the Attack Map: target → technique → tactic, risk-weighted."""
    vectors = get_attack_vectors(engagement_id, limit=500)
    nodes: Dict[str, Dict[str, Any]] = {}
    edges: List[Dict[str, Any]] = []

    def _node(nid, ntype, label, risk=None):
        n = nodes.get(nid)
        if not n:
            nodes[nid] = {"id": nid, "type": ntype, "label": label, "risk": risk or 0}
        elif risk and risk > nodes[nid]["risk"]:
            nodes[nid]["risk"] = risk

    for v in vectors:
        tgt = v.get("target") or "unknown"
        tech = v["technique"]
        tac = v.get("tactic") or "unknown"
        risk = float(v["risk_score"])
        _node(f"target:{tgt}", "target", tgt, risk)
        _node(f"technique:{tech}", "technique", f"{tech} {v.get('technique_name') or ''}".strip(), risk)
        _node(f"tactic:{tac}", "tactic", tac, risk)
        edges.append({"from": f"target:{tgt}", "to": f"technique:{tech}", "risk": risk})
        edges.append({"from": f"technique:{tech}", "to": f"tactic:{tac}", "risk": risk})

    return {"nodes": list(nodes.values()), "edges": edges, "count": len(vectors)}
