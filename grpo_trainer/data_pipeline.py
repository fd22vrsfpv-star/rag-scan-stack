"""
Data pipeline for GRPO training.
Extracts prompts from PostgreSQL scan data and feedback, formats JSONL datasets.
"""

import json
import os
import uuid
from contextlib import contextmanager
from datetime import datetime
from typing import Dict, List, Optional

import psycopg2
from psycopg2.extras import RealDictCursor


def get_db_dsn() -> str:
    return os.environ.get(
        "DB_DSN",
        "postgresql://app:app@rag-postgres:5432/scans"
    )


@contextmanager
def get_db():
    conn = psycopg2.connect(get_db_dsn())
    try:
        yield conn
    finally:
        conn.close()


def extract_scan_analysis_prompts(limit: int = 500) -> List[Dict]:
    """
    Extract scan analysis prompts by joining assets + ports + vulns + web_findings.
    Formats as "analyze these scan results" prompt.
    """
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("""
            SELECT
                a.id as asset_id,
                host(a.ip) as ip,
                a.hostname,
                a.os,
                json_agg(DISTINCT jsonb_build_object(
                    'port', p.port,
                    'proto', p.proto,
                    'service', p.service,
                    'product', p.product,
                    'version', p.version
                )) FILTER (WHERE p.id IS NOT NULL) as ports,
                json_agg(DISTINCT jsonb_build_object(
                    'script', v.script,
                    'severity', v.severity,
                    'cve', v.cve,
                    'output', LEFT(v.output, 500)
                )) FILTER (WHERE v.id IS NOT NULL) as vulns,
                json_agg(DISTINCT jsonb_build_object(
                    'url', wf.url,
                    'name', wf.name,
                    'severity', wf.severity,
                    'source', wf.source
                )) FILTER (WHERE wf.id IS NOT NULL) as web_findings
            FROM assets a
            LEFT JOIN ports p ON p.asset_id = a.id AND p.is_open = true
            LEFT JOIN vulns v ON v.asset_id = a.id
            LEFT JOIN web_findings wf ON wf.asset_id = a.id
            GROUP BY a.id, a.ip, a.hostname, a.os
            HAVING COUNT(p.id) > 0
            LIMIT %s
        """, (limit,))

        rows = cur.fetchall()

    prompts = []
    for row in rows:
        ports_str = ""
        if row["ports"]:
            port_lines = []
            for p in row["ports"][:20]:  # Limit to 20 ports
                svc = f"{p.get('service', 'unknown')}"
                if p.get("product"):
                    svc += f" ({p['product']}"
                    if p.get("version"):
                        svc += f" {p['version']}"
                    svc += ")"
                port_lines.append(f"  - {p.get('port')}/{p.get('proto')}: {svc}")
            ports_str = "\n".join(port_lines)

        vulns_str = ""
        if row["vulns"]:
            vuln_lines = []
            for v in row["vulns"][:10]:
                cves = ", ".join(v.get("cve") or []) if v.get("cve") else "N/A"
                vuln_lines.append(
                    f"  - [{v.get('severity', 'unknown')}] {v.get('script')}: CVEs={cves}"
                )
            vulns_str = "\n".join(vuln_lines)

        hostname = f" ({row['hostname']})" if row.get("hostname") else ""
        os_info = f"\nOS: {row['os']}" if row.get("os") else ""

        prompt = (
            f"Analyze the following scan results for {row['ip']}{hostname}:{os_info}\n\n"
            f"Open Ports:\n{ports_str}\n"
        )
        if vulns_str:
            prompt += f"\nVulnerabilities Found:\n{vulns_str}\n"
        prompt += (
            "\nProvide a security assessment including:\n"
            "1. Risk level and attack surface summary\n"
            "2. Critical vulnerabilities with CVE references\n"
            "3. Recommended remediation steps"
        )

        prompts.append({
            "task_type": "scan_analysis",
            "prompt": prompt,
            "context": {
                "asset_id": str(row["asset_id"]),
                "ip": row["ip"],
            },
        })

    return prompts


def extract_exploit_recommendation_prompts(limit: int = 500) -> List[Dict]:
    """
    Extract exploit recommendation prompts from high/critical vulns.
    """
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("""
            SELECT
                host(a.ip) as ip,
                p.port,
                p.proto,
                p.service,
                p.product,
                p.version,
                v.script,
                v.severity,
                v.cve,
                LEFT(v.output, 500) as vuln_output
            FROM vulns v
            JOIN ports p ON v.port_id = p.id
            JOIN assets a ON v.asset_id = a.id
            WHERE v.severity IN ('high', 'critical')
            LIMIT %s
        """, (limit,))

        rows = cur.fetchall()

    prompts = []
    for row in rows:
        svc = f"{row.get('service', 'unknown')}"
        if row.get("product"):
            svc += f" {row['product']}"
            if row.get("version"):
                svc += f" {row['version']}"

        cves = ", ".join(row.get("cve") or []) if row.get("cve") else "none identified"

        prompt = (
            f"Find matching exploits for the following vulnerability:\n\n"
            f"Target: {row['ip']}:{row['port']}/{row['proto']}\n"
            f"Service: {svc}\n"
            f"Vulnerability: {row.get('script', 'unknown')} ({row['severity']})\n"
            f"CVEs: {cves}\n"
            f"Output: {row.get('vuln_output', 'N/A')}\n\n"
            f"Search ExploitDB and Metasploit for matching exploits. "
            f"Provide exploit IDs, reliability assessment, and customized parameters."
        )

        prompts.append({
            "task_type": "exploit_recommendation",
            "prompt": prompt,
            "context": {
                "ip": row["ip"],
                "port": row["port"],
                "service": svc,
            },
        })

    return prompts


def extract_agent_decision_prompts(limit: int = 500) -> List[Dict]:
    """
    Extract coordinator decision prompts from agent_messages.
    """
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("""
            SELECT
                m.id,
                m.session_id,
                m.content,
                m.created_at,
                (
                    SELECT json_agg(jsonb_build_object(
                        'agent_name', prev.agent_name,
                        'content', LEFT(prev.content, 300)
                    ) ORDER BY prev.created_at)
                    FROM (
                        SELECT agent_name, content, created_at
                        FROM agent_messages
                        WHERE session_id = m.session_id
                          AND created_at < m.created_at
                        ORDER BY created_at DESC
                        LIMIT 3
                    ) prev
                ) as prior_context
            FROM agent_messages m
            WHERE m.agent_name = 'Coordinator'
              AND m.role = 'assistant'
              AND LENGTH(m.content) > 50
            ORDER BY m.created_at DESC
            LIMIT %s
        """, (limit,))

        rows = cur.fetchall()

    prompts = []
    for row in rows:
        context_str = ""
        if row.get("prior_context"):
            for ctx in row["prior_context"]:
                context_str += f"[{ctx['agent_name']}]: {ctx['content']}\n\n"

        prompt = (
            f"You are the Pentest Coordinator. Based on the conversation so far, "
            f"decide what the next step should be.\n\n"
            f"Recent conversation:\n{context_str}\n"
            f"What should the team do next? Direct specific agents to take action."
        )

        prompts.append({
            "task_type": "agent_decision",
            "prompt": prompt,
            "context": {
                "session_id": str(row["session_id"]),
                "message_id": str(row["id"]),
            },
        })

    return prompts


def extract_feedback_dataset(
    task_types: Optional[List[str]] = None,
    min_rating: int = 1,
) -> List[Dict]:
    """
    Extract rated feedback entries as training data.
    """
    conditions = ["rating IS NOT NULL", "rating >= %s"]
    params = [min_rating]

    if task_types:
        conditions.append("task_type = ANY(%s)")
        params.append(task_types)

    where_clause = " AND ".join(conditions)

    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            f"""
            SELECT id, task_type, user_prompt, model_response, system_prompt,
                   context, rating, rating_dimensions
            FROM grpo_feedback
            WHERE {where_clause}
            ORDER BY created_at ASC
            """,
            params
        )
        rows = cur.fetchall()

    return [
        {
            "task_type": row["task_type"],
            "prompt": row["user_prompt"],
            "response": row["model_response"],
            "rating": row["rating"],
            "rating_dimensions": row["rating_dimensions"],
        }
        for row in rows
    ]


def extract_rag_dataset(
    days: int = 90,
    min_rating: Optional[int] = None,
) -> Dict:
    """Extract RAG training data: embedding triplets, reranker rows,
    and GRPO RLHF rows -- all derived from the rag_query_log x
    rag_feedback join populated by the live scan_recommender service.

    Mirror of ``_build_rag_training_datasets`` in scan_recommender so
    the offline GRPO pipeline can produce the same dataset the live
    dashboard surfaces.  Each row carries a ``source_query_log_id`` so
    the offline dataset can be re-joined with the runtime tables for
    ablation studies.

    Returns ``{"summary": {...}, "triplets": [...], "reranker": [...],
    "grpo": [...]}`` -- the GRPO list is what ``build_dataset`` folds
    into the unified train.jsonl under ``task_type='rag_answer'``;
    the other two are emitted as separate side-car files (since their
    schemas differ from the per-row prompt/response format).
    """
    conds = ["f.created_at >= now() - %s::interval"]
    params: list = [f"{days} days"]
    if min_rating is not None:
        conds.append("f.rating >= %s")
        params.append(min_rating)
    where = " AND ".join(conds)

    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            f"""
            SELECT q.id AS query_log_id, q.query, q.top_k_chunk_ids,
                   q.top_k_sims, q.llm_answer, q.engagement_id,
                   f.rating, f.helpful_chunk_ids, f.unhelpful_chunk_ids,
                   f.comment, f.created_at AS feedback_at
              FROM rag_feedback f
              JOIN rag_query_log q ON q.id = f.query_log_id
             WHERE {where}
             ORDER BY f.created_at ASC
            """,
            params,
        )
        rows = cur.fetchall()

        all_ids: set = set()
        for r in rows:
            for ids in (r.get("top_k_chunk_ids") or [],
                        r.get("helpful_chunk_ids") or [],
                        r.get("unhelpful_chunk_ids") or []):
                for cid in ids:
                    if cid is not None:
                        all_ids.add(int(cid))
        chunks: Dict[int, dict] = {}
        if all_ids:
            cur.execute(
                "SELECT id, edb_id, title, path, section_header, chunk, source_repo "
                "FROM exploit_chunks WHERE id = ANY(%s)",
                (list(all_ids),),
            )
            chunks = {int(c["id"]): dict(c) for c in cur.fetchall()}

    triplets: List[dict] = []
    reranker: List[dict] = []
    grpo: List[dict] = []

    for r in rows:
        query = r["query"]
        rating = r.get("rating")
        helpful = [int(c) for c in (r.get("helpful_chunk_ids") or [])]
        unhelpful = [int(c) for c in (r.get("unhelpful_chunk_ids") or [])]
        top_k = [int(c) for c in (r.get("top_k_chunk_ids") or [])]
        top_k_sims = list(r.get("top_k_sims") or [])

        for pid in helpful:
            p = chunks.get(pid)
            if not p:
                continue
            for nid in unhelpful:
                n = chunks.get(nid)
                if not n:
                    continue
                triplets.append({
                    "query": query,
                    "positive": p["chunk"],
                    "negative": n["chunk"],
                    "positive_meta": {
                        "chunk_id": pid,
                        "title": p["title"],
                        "section_header": p.get("section_header"),
                    },
                    "negative_meta": {
                        "chunk_id": nid,
                        "title": n["title"],
                        "section_header": n.get("section_header"),
                    },
                    "source_query_log_id": str(r["query_log_id"]),
                })

        labeled = []
        for idx, cid in enumerate(top_k):
            ch = chunks.get(cid)
            if not ch:
                continue
            label = 1 if cid in helpful else (-1 if cid in unhelpful else 0)
            labeled.append({
                "chunk_id": cid,
                "chunk": ch["chunk"],
                "title": ch["title"],
                "section_header": ch.get("section_header"),
                "similarity": top_k_sims[idx] if idx < len(top_k_sims) else None,
                "label": label,
            })
        if labeled:
            reranker.append({
                "query": query,
                "chunks": labeled,
                "overall_rating": rating,
                "source_query_log_id": str(r["query_log_id"]),
            })

        llm = r.get("llm_answer") or ""
        if llm and not llm.startswith("[LLM_ERROR]") and rating is not None:
            grpo.append({
                "task_type": "rag_answer",
                "user_prompt": query,
                "model_response": llm,
                "system_prompt": None,
                "context": {
                    "top_k_chunk_ids": top_k,
                    "helpful_chunk_ids": helpful,
                    "unhelpful_chunk_ids": unhelpful,
                    "engagement_id": str(r["engagement_id"]) if r.get("engagement_id") else None,
                },
                "rating": rating,
                "source_query_log_id": str(r["query_log_id"]),
            })

    return {
        "summary": {
            "days": days,
            "min_rating": min_rating,
            "raw_feedback_rows": len(rows),
            "triplets": len(triplets),
            "reranker_rows": len(reranker),
            "grpo_rows": len(grpo),
        },
        "triplets": triplets,
        "reranker": reranker,
        "grpo": grpo,
    }


def build_dataset(
    version: str,
    task_types: Optional[List[str]] = None,
    min_rating: int = 1,
    include_synthetic: bool = True,
    output_dir: str = "/app/datasets",
    include_rag: bool = True,
    rag_days: int = 90,
) -> Dict:
    """
    Build a versioned JSONL training dataset.

    Combines:
    1. Rated human feedback (gold standard)
    2. Synthetic prompts from scan data (for GRPO generation)

    Args:
        version: Dataset version string (e.g. "v1")
        task_types: Filter task types
        min_rating: Minimum rating for feedback data
        include_synthetic: Include synthetic prompts from scan data
        output_dir: Output directory

    Returns:
        Dict with dataset stats
    """
    os.makedirs(os.path.join(output_dir, version), exist_ok=True)
    train_path = os.path.join(output_dir, version, "train.jsonl")

    all_entries = []

    # 1. Rated feedback
    feedback_data = extract_feedback_dataset(task_types, min_rating)
    for entry in feedback_data:
        all_entries.append({
            "source": "feedback",
            **entry,
        })

    # 2. Synthetic prompts from scan data
    if include_synthetic:
        types = task_types or ["scan_analysis", "exploit_recommendation", "agent_decision"]

        if "scan_analysis" in types:
            for entry in extract_scan_analysis_prompts(limit=200):
                all_entries.append({"source": "synthetic", **entry})

        if "exploit_recommendation" in types:
            for entry in extract_exploit_recommendation_prompts(limit=200):
                all_entries.append({"source": "synthetic", **entry})

        if "agent_decision" in types:
            for entry in extract_agent_decision_prompts(limit=200):
                all_entries.append({"source": "synthetic", **entry})

    # 3. RAG feedback dataset (Layer 3): GRPO rows fold into the
    # unified train.jsonl; triplets + reranker rows are emitted as
    # separate side-car files because their schemas differ.
    rag_summary: Dict = {}
    if include_rag:
        rag = extract_rag_dataset(days=rag_days)
        rag_summary = rag["summary"]
        for entry in rag["grpo"]:
            all_entries.append({"source": "rag_feedback", **entry})

        # Side-car files
        triplets_path = os.path.join(output_dir, version, "rag_triplets.jsonl")
        with open(triplets_path, "w") as f:
            for entry in rag["triplets"]:
                f.write(json.dumps(entry, default=str) + "\n")

        reranker_path = os.path.join(output_dir, version, "rag_reranker.jsonl")
        with open(reranker_path, "w") as f:
            for entry in rag["reranker"]:
                f.write(json.dumps(entry, default=str) + "\n")

    # Write JSONL
    with open(train_path, "w") as f:
        for entry in all_entries:
            f.write(json.dumps(entry, default=str) + "\n")

    # Audit fix: previously `synthetic_entries` subtracted
    # `len(rag_summary and [rag_summary] or [])` which evaluates to 0 or 1
    # regardless of how many RAG rows actually landed in all_entries.
    # The correct subtraction is the count of RAG GRPO rows folded in.
    rag_entries_count = rag_summary.get("grpo_rows", 0) if rag_summary else 0
    stats = {
        "version": version,
        "total_entries": len(all_entries),
        "feedback_entries": len(feedback_data),
        "synthetic_entries": len(all_entries) - len(feedback_data) - rag_entries_count,
        "rag_entries": rag_entries_count,
        "rag_triplets": rag_summary.get("triplets", 0) if rag_summary else 0,
        "rag_reranker_rows": rag_summary.get("reranker_rows", 0) if rag_summary else 0,
        "output_path": train_path,
        "by_task_type": {},
    }
    for entry in all_entries:
        tt = entry.get("task_type", "unknown")
        stats["by_task_type"][tt] = stats["by_task_type"].get(tt, 0) + 1

    # Write stats
    stats_path = os.path.join(output_dir, version, "stats.json")
    with open(stats_path, "w") as f:
        json.dump(stats, f, indent=2, default=str)

    return stats
