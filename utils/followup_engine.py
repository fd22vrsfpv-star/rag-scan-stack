"""
Follow-up scan rules engine with queue enqueue and optional vector-aware LLM advisory.

- Reads normalized port metadata (service/product/banner) from DB.
- Matches rules to select plugin actions (non-standard ports supported).
- Enqueues idempotent follow-up tasks into DB.
- Optionally consults a local LLM and includes vector search context to refine action selection.

Environment:
- DB_DSN: Postgres DSN
- FOLLOWUP_USE_LLM=1: enable LLM advisory
- LLM_ENDPOINT: local LLM endpoint (e.g., http://ollama:11434)
- LLM_MODEL: local LLM model name (default: llama3)
- RAG_API_BASE: base URL to semantic search endpoint (optional; used to fetch vector context)
"""
import os
import re
from dataclasses import dataclass
from typing import List, Optional, Dict, Any, Tuple

import psycopg2
from psycopg2.extras import RealDictCursor, Json


DB_DSN = os.environ.get("DB_DSN", "postgresql://app:app@rag-postgres:5432/scans")

# Optional LLM advisory and vector context settings
LLM_ENDPOINT = os.environ.get("LLM_ENDPOINT", "").strip()
LLM_MODEL = os.environ.get("LLM_MODEL", "llama3")
USE_LLM_FOR_RULES = os.environ.get("FOLLOWUP_USE_LLM", "0") == "1"
RAG_API_BASE = os.environ.get("RAG_API_BASE", "https://rag-api:8000").rstrip("/")


def _conn():
    return psycopg2.connect(DB_DSN)


def ensure_followup_schema():
    """
    Ensure database schema features required for follow-ups:
      - tasks.action column for plugin identifier
      - followup_findings table to persist plugin results
    """
    ddl = [
        "CREATE EXTENSION IF NOT EXISTS pgcrypto",
        "ALTER TABLE IF EXISTS tasks ADD COLUMN IF NOT EXISTS action text",
        """
        CREATE TABLE IF NOT EXISTS followup_findings (
            id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            task_id       uuid,
            host          inet,
            port          integer,
            proto         text,
            plugin        text NOT NULL,
            title         text,
            severity      text,
            data          jsonb NOT NULL DEFAULT '{}'::jsonb,
            observed_at   timestamptz NOT NULL DEFAULT now()
        )
        """,
        "CREATE INDEX IF NOT EXISTS idx_followup_findings_host_port ON followup_findings(host, port)",
        "CREATE INDEX IF NOT EXISTS idx_followup_findings_plugin ON followup_findings(plugin)",
    ]
    with _conn() as c, c.cursor() as cur:
        for stmt in ddl:
            try:
                cur.execute(stmt)
            except Exception:
                pass
        c.commit()


@dataclass(frozen=True)
class PortCtx:
    host: str
    port: int
    proto: str
    service: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    banner: Optional[str] = None


@dataclass(frozen=True)
class FollowupAction:
    plugin: str
    params: Dict[str, Any] = None


@dataclass(frozen=True)
class Rule:
    name: str
    service_regex: Optional[str] = None
    product_regex: Optional[str] = None
    banner_regex: Optional[str] = None
    port_in: Optional[List[int]] = None
    actions: List[FollowupAction] = None

    def matches(self, ctx: PortCtx) -> bool:
        if self.service_regex and not (ctx.service and re.search(self.service_regex, ctx.service, re.I)):
            return False
        if self.product_regex and not (ctx.product and re.search(self.product_regex, ctx.product, re.I)):
            return False
        if self.banner_regex and not (ctx.banner and re.search(self.banner_regex, ctx.banner, re.I)):
            return False
        if self.port_in is not None and ctx.port not in self.port_in:
            return False
        return True


DEFAULT_RULES: List[Rule] = [
    Rule(
        name="http",
        service_regex=r"^http|^https|^http-proxy",
        actions=[FollowupAction("http_title")],
    ),
    Rule(
        name="tls",
        service_regex=r"^ssl|^tls|^https",
        actions=[FollowupAction("tls_cert")],
    ),
    Rule(
        name="ssh",
        service_regex=r"^ssh$",
        actions=[FollowupAction("ssh_algos")],
    ),
    Rule(
        name="banner_http",
        banner_regex=r"HTTP/1\.[01]|Server:",
        actions=[FollowupAction("http_title")],
    ),
    Rule(
        name="banner_ssh",
        banner_regex=r"^SSH-2\.0",
        actions=[FollowupAction("ssh_algos")],
    ),
]


def _vector_context_for(ctx: PortCtx) -> List[Dict[str, Any]]:
    """
    Optional: query local semantic search API to retrieve vector-similar context
    for the given port context; returns a small list of {title, text, metadata, distance}.
    """
    try:
        import requests
        query = f"{ctx.service or ''} {ctx.product or ''} {ctx.version or ''} {ctx.banner or ''}".strip() or f"{ctx.proto}/{ctx.port}"
        payload = {"query": query, "k": 5, "metadata_eq": {"host": ctx.host} if ctx.host else None}
        r = requests.post(f"{RAG_API_BASE}/rag/search", json=payload, timeout=5)
        data = r.json().get("results", []) if r.status_code < 300 else []
        # Normalize minimal fields to reduce prompt size
        out = []
        for d in data:
            out.append({
                "title": d.get("title"),
                "distance": d.get("distance"),
                "metadata": d.get("metadata"),
            })
        return out
    except Exception:
        return []


def _llm_choose_extra_actions(ctx: PortCtx) -> List[FollowupAction]:
    """
    Optional: ask local LLM to suggest additional actions. Includes vector context if available.
    Expects JSON array of plugin names in response (e.g., ["http_title","tls_cert"]).
    """
    if not (USE_LLM_FOR_RULES and LLM_ENDPOINT):
        return []
    try:
        import requests
        context_snippets = _vector_context_for(ctx)
        prompt = (
            "You are selecting safe, fast follow-up checks for a discovered network service. "
            "Choose from ['http_title','tls_cert','ssh_algos'] based on the context below. "
            "Return a JSON array of plugin names only.\n\n"
            f"Service context:\n"
            f"- host: {ctx.host}\n- port: {ctx.port}\n- proto: {ctx.proto}\n"
            f"- service: {ctx.service}\n- product: {ctx.product}\n- version: {ctx.version}\n- banner: {ctx.banner}\n\n"
            f"Vector context (top similar):\n{context_snippets}\n"
        )
        payload = {"model": LLM_MODEL, "prompt": prompt}
        r = requests.post(f"{LLM_ENDPOINT}/api/generate", json=payload, timeout=8)
        text = (r.text or "").strip()
        import json as _json
        arr = _json.loads(text) if text.startswith("[") else []
        out: List[FollowupAction] = []
        for name in arr:
            if isinstance(name, str) and name in ("http_title", "tls_cert", "ssh_algos"):
                out.append(FollowupAction(name))
        return out
    except Exception:
        return []


def select_ports(limit: Optional[int] = None) -> List[PortCtx]:
    """
    Fetch open ports and best-effort metadata from DB to drive rule selection.
    """
    sql = """
        SELECT host(a.ip)::text AS host,
               COALESCE(p.proto,'tcp') AS proto,
               p.port,
               p.service,
               p.product,
               p.version,
               p.banner
        FROM ports p
        JOIN assets a ON a.id = p.asset_id
        WHERE COALESCE(p.is_open, true)
        ORDER BY a.ip, p.port
    """
    params: Tuple[Any, ...] = tuple()
    if limit:
        sql += " LIMIT %s"
        params = (limit,)
    with _conn() as c, c.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(sql, params)
        rows = cur.fetchall()
        return [
            PortCtx(
                host=r["host"],
                port=int(r["port"]),
                proto=r["proto"] or "tcp",
                service=r.get("service"),
                product=r.get("product"),
                version=r.get("version"),
                banner=r.get("banner"),
            )
            for r in rows
        ]


def choose_actions(ctx: PortCtx, rules: Optional[List[Rule]] = None) -> List[FollowupAction]:
    """
    Match rules and optionally augment choices via LLM with vector context.
    Returns deduplicated list of actions.
    """
    rules = rules or DEFAULT_RULES
    picked: List[FollowupAction] = []
    for rule in rules:
        if rule.matches(ctx):
            picked.extend(rule.actions or [])
    # Deduplicate while preserving order
    seen = set()
    uniq: List[FollowupAction] = []
    for a in picked:
        k = (a.plugin, tuple(sorted((a.params or {}).items())))
        if k not in seen:
            seen.add(k)
            uniq.append(a)
    # Optional LLM suggestions
    for a in _llm_choose_extra_actions(ctx):
        k = (a.plugin, tuple(sorted((a.params or {}).items())))
        if k not in seen:
            seen.add(k)
            uniq.append(a)
    return uniq


def _task_exists(cur, job_id: str, host: str, port: int, proto: str, plugin: str) -> bool:
    cur.execute(
        """
        SELECT 1
        FROM tasks
        WHERE job_id=%s::uuid AND type='followup'
          AND target_host=%s::inet AND target_port=%s AND COALESCE(proto,'')=%s AND COALESCE(action,'')=%s
        LIMIT 1
        """,
        (job_id, host, port, proto or "", plugin),
    )
    return cur.fetchone() is not None


def enqueue_followups_from_ports(
    job_id: Optional[str],
    limit_ports: Optional[int] = None,
    rules: Optional[List[Rule]] = None,
) -> Dict[str, Any]:
    """
    Analyze ports using rules and enqueue follow-up tasks idempotently.
    Creates a job if job_id is None.
    """
    ensure_followup_schema()
    if rules is None:
        rules = DEFAULT_RULES
    created_job_id = None
    with _conn() as c, c.cursor(cursor_factory=RealDictCursor) as cur:
        if not job_id:
            cur.execute(
                "INSERT INTO jobs (type, status, params) VALUES ('masscan-nmap','queued', %s) RETURNING id",
                (Json({"phase": "followup"}),),
            )
            created_job_id = str(cur.fetchone()["id"])
            job_id = created_job_id
            c.commit()

        ports = select_ports(limit_ports)
        enq = 0
        for p in ports:
            actions = choose_actions(p, rules=rules)
            for act in actions:
                if _task_exists(cur, job_id, p.host, p.port, p.proto, act.plugin):
                    continue
                cur.execute(
                    """
                    INSERT INTO tasks (job_id, type, target_host, target_port, proto, status, action)
                    VALUES (%s::uuid, 'followup', %s::inet, %s, %s, 'queued', %s)
                    """,
                    (job_id, p.host, p.port, p.proto, act.plugin),
                )
                enq += 1
        try:
            cur.execute(
                "UPDATE jobs SET total_tasks = GREATEST(total_tasks, finished_tasks + %s) WHERE id=%s::uuid",
                (enq, job_id),
            )
        except Exception:
            pass
        c.commit()
    return {"ok": True, "job_id": job_id, "created_job_id": created_job_id, "enqueued": enq}
