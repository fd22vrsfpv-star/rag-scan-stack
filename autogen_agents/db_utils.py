"""
Database utilities for Autogen agent sessions
"""

import os
import uuid
from contextlib import contextmanager
from typing import Optional, Dict, List
import psycopg2
import psycopg2.pool
from psycopg2.extras import RealDictCursor, Json


def _sid(val) -> str:
    """Convert any session_id (uuid.UUID or str) to str for psycopg2 params."""
    return str(val)


def get_db_dsn() -> str:
    """Get database connection string from environment"""
    return os.environ.get(
        "DB_DSN",
        "postgresql://app:app@rag-postgres:5432/scans"
    )


# Thread-safe connection pool (min 2, max 20 connections)
_pool: Optional[psycopg2.pool.ThreadedConnectionPool] = None


def _get_pool() -> psycopg2.pool.ThreadedConnectionPool:
    global _pool
    if _pool is None or _pool.closed:
        _pool = psycopg2.pool.ThreadedConnectionPool(
            minconn=2, maxconn=20, dsn=get_db_dsn()
        )
    return _pool


@contextmanager
def get_db():
    """Context manager that borrows a connection from the pool.
    Uses autocommit so each statement commits immediately."""
    pool = _get_pool()
    conn = pool.getconn()
    conn.autocommit = True
    try:
        yield conn
    finally:
        pool.putconn(conn)


def ensure_schema():
    """Create required tables if they don't exist. Idempotent — safe to call on every startup."""
    ddl = [
        "CREATE EXTENSION IF NOT EXISTS pgcrypto",
        # _touch_updated_at helper function
        """
        CREATE OR REPLACE FUNCTION public._touch_updated_at()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN NEW.updated_at = now(); RETURN NEW; END; $$
        """,
        # agent_sessions
        """
        CREATE TABLE IF NOT EXISTS agent_sessions (
            id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            session_name        text NOT NULL,
            target_description  text NOT NULL,
            status              text NOT NULL DEFAULT 'active'
                                CHECK (status IN ('active','completed','failed','stopped','stalled')),
            configuration       jsonb DEFAULT '{}'::jsonb,
            summary             text,
            metadata            jsonb DEFAULT '{}'::jsonb,
            created_at          timestamptz NOT NULL DEFAULT now(),
            updated_at          timestamptz NOT NULL DEFAULT now(),
            end_time            timestamptz
        )
        """,
        "CREATE INDEX IF NOT EXISTS idx_agent_sessions_status ON agent_sessions(status)",
        "CREATE INDEX IF NOT EXISTS idx_agent_sessions_created_at ON agent_sessions(created_at DESC)",
        # agent_messages
        """
        CREATE TABLE IF NOT EXISTS agent_messages (
            id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            session_id  uuid NOT NULL REFERENCES agent_sessions(id) ON DELETE CASCADE,
            agent_name  text NOT NULL,
            role        text NOT NULL,
            content     text NOT NULL,
            metadata    jsonb DEFAULT '{}'::jsonb,
            created_at  timestamptz NOT NULL DEFAULT now()
        )
        """,
        "CREATE INDEX IF NOT EXISTS idx_agent_messages_session_id ON agent_messages(session_id)",
        "CREATE INDEX IF NOT EXISTS idx_agent_messages_agent_name ON agent_messages(agent_name)",
        "CREATE INDEX IF NOT EXISTS idx_agent_messages_created_at ON agent_messages(created_at DESC)",
        # session_scan_metrics
        """
        CREATE TABLE IF NOT EXISTS session_scan_metrics (
            id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            session_id        uuid NOT NULL,
            scan_type         text NOT NULL,
            scan_phase        text,
            job_id            text,
            status            text NOT NULL DEFAULT 'running',
            started_at        timestamptz,
            completed_at      timestamptz,
            duration_seconds  numeric,
            params            jsonb DEFAULT '{}'::jsonb,
            result_summary    jsonb DEFAULT '{}'::jsonb,
            created_at        timestamptz NOT NULL DEFAULT now()
        )
        """,
        "CREATE INDEX IF NOT EXISTS idx_session_scan_metrics_session_id ON session_scan_metrics(session_id)",
        "CREATE INDEX IF NOT EXISTS idx_session_scan_metrics_scan_type ON session_scan_metrics(scan_type)",
        "CREATE INDEX IF NOT EXISTS idx_session_scan_metrics_created_at ON session_scan_metrics(created_at DESC)",
        # llm_request_metrics
        """
        CREATE TABLE IF NOT EXISTS llm_request_metrics (
            id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            session_id          uuid NOT NULL,
            agent_name          text,
            model_name          text NOT NULL,
            prompt_tokens       integer,
            completion_tokens   integer,
            total_tokens        integer,
            latency_ms          numeric NOT NULL,
            has_tool_calls      boolean NOT NULL DEFAULT false,
            tool_call_count     integer DEFAULT 0,
            tool_names          text[],
            is_error            boolean NOT NULL DEFAULT false,
            error_message       text,
            request_params      jsonb DEFAULT '{}'::jsonb,
            created_at          timestamptz NOT NULL DEFAULT now()
        )
        """,
        "CREATE INDEX IF NOT EXISTS idx_llm_request_metrics_session_id ON llm_request_metrics(session_id)",
        "CREATE INDEX IF NOT EXISTS idx_llm_request_metrics_model_name ON llm_request_metrics(model_name)",
        "CREATE INDEX IF NOT EXISTS idx_llm_request_metrics_agent_name ON llm_request_metrics(agent_name)",
        "CREATE INDEX IF NOT EXISTS idx_llm_request_metrics_created_at ON llm_request_metrics(created_at DESC)",
        # pending_exploits
        """
        CREATE TABLE IF NOT EXISTS pending_exploits (
            id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            asset_id            uuid,
            port_id             uuid,
            source              text NOT NULL CHECK (source IN ('exploitdb', 'metasploit')),
            exploit_id          text NOT NULL,
            exploit_title       text NOT NULL,
            target_ip           text NOT NULL,
            target_port         integer,
            target_service      text,
            target_version      text,
            exploit_type        text CHECK (exploit_type IN ('rce', 'auth_bypass', 'info_disclosure', 'other')),
            customized_command  text NOT NULL,
            parameters          jsonb DEFAULT '{}'::jsonb,
            match_confidence    numeric,
            match_reasoning     text,
            session_id          uuid,
            requested_by        text,
            status              text NOT NULL DEFAULT 'pending'
                                CHECK (status IN ('pending','approved','rejected','executed','failed')),
            reviewed_by         text,
            reviewed_at         timestamptz,
            rejection_reason    text,
            metadata            jsonb DEFAULT '{}'::jsonb,
            created_at          timestamptz NOT NULL DEFAULT now(),
            updated_at          timestamptz NOT NULL DEFAULT now()
        )
        """,
        "CREATE INDEX IF NOT EXISTS idx_pending_exploits_status ON pending_exploits(status)",
        "CREATE INDEX IF NOT EXISTS idx_pending_exploits_session ON pending_exploits(session_id)",
        # exploit_results
        """
        CREATE TABLE IF NOT EXISTS exploit_results (
            id                   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            pending_exploit_id   uuid NOT NULL REFERENCES pending_exploits(id) ON DELETE CASCADE,
            success              boolean NOT NULL,
            output               text,
            parsed_result        jsonb DEFAULT '{}'::jsonb,
            session_type         text,
            session_id           text,
            execution_time_ms    integer,
            executor_container   text,
            executed_at          timestamptz NOT NULL DEFAULT now(),
            completed_at         timestamptz
        )
        """,
        "CREATE INDEX IF NOT EXISTS idx_exploit_results_pending ON exploit_results(pending_exploit_id)",
        # msf_modules
        """
        CREATE TABLE IF NOT EXISTS msf_modules (
            id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            module_path       text NOT NULL UNIQUE,
            module_type       text NOT NULL,
            name              text NOT NULL,
            description       text,
            rank              text,
            platforms         text[],
            architectures     text[],
            targets           jsonb DEFAULT '[]'::jsonb,
            cve               text[],
            edb_id            text[],
            required_options  jsonb DEFAULT '{}'::jsonb,
            optional_options  jsonb DEFAULT '{}'::jsonb,
            author            text[],
            disclosure_date   text,
            last_updated      timestamptz NOT NULL DEFAULT now()
        )
        """,
        "CREATE INDEX IF NOT EXISTS idx_msf_modules_type ON msf_modules(module_type)",
        "CREATE INDEX IF NOT EXISTS idx_msf_modules_cve ON msf_modules USING gin(cve)",
        # prompt_configs — store named prompt configuration sets
        """
        CREATE TABLE IF NOT EXISTS prompt_configs (
            id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            name        text NOT NULL UNIQUE,
            description text,
            prompts     jsonb NOT NULL,
            is_active   boolean NOT NULL DEFAULT false,
            created_at  timestamptz NOT NULL DEFAULT now(),
            updated_at  timestamptz NOT NULL DEFAULT now()
        )
        """,
        "CREATE INDEX IF NOT EXISTS idx_prompt_configs_name ON prompt_configs(name)",
        "CREATE INDEX IF NOT EXISTS idx_prompt_configs_active ON prompt_configs(is_active) WHERE is_active = true",
    ]
    # Migrations for existing databases
    migrations = [
        # Allow 'stalled' status in agent_sessions (added for session watchdog)
        """
        DO $$ BEGIN
            ALTER TABLE agent_sessions DROP CONSTRAINT IF EXISTS agent_sessions_status_check;
            ALTER TABLE agent_sessions ADD CONSTRAINT agent_sessions_status_check
                CHECK (status IN ('active','completed','failed','stopped','stalled'));
        EXCEPTION WHEN undefined_table THEN NULL;
        END $$
        """,
        # Add parent_session_id for resumed sessions
        """
        DO $$ BEGIN
            ALTER TABLE agent_sessions ADD COLUMN parent_session_id uuid REFERENCES agent_sessions(id);
        EXCEPTION WHEN duplicate_column THEN NULL;
        END $$
        """,
    ]
    import logging
    logger = logging.getLogger("db_utils")
    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                for stmt in ddl:
                    try:
                        cur.execute(stmt)
                    except Exception as e:
                        logger.warning(f"DDL statement skipped: {e}")
                for stmt in migrations:
                    try:
                        cur.execute(stmt)
                    except Exception as e:
                        logger.warning(f"Migration skipped: {e}")
            conn.commit()
        logger.info("Database schema verified")
    except Exception as e:
        logger.error(f"ensure_schema failed: {e}")


def create_agent_session(
    session_name: str,
    target_description: str,
    configuration: Optional[Dict] = None
) -> uuid.UUID:
    """
    Create a new agent session

    Args:
        session_name: Human-readable session name
        target_description: Description of pentest target
        configuration: Optional configuration parameters

    Returns:
        Session UUID
    """
    with get_db() as conn, conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO agent_sessions
            (session_name, target_description, configuration, status)
            VALUES (%s, %s, %s, 'active')
            RETURNING id
            """,
            (session_name, target_description, Json(configuration or {}))
        )
        session_id = cur.fetchone()[0]
        conn.commit()
        return session_id


def update_agent_session(
    session_id: uuid.UUID,
    status: Optional[str] = None,
    summary: Optional[str] = None,
    metadata: Optional[Dict] = None
):
    """
    Update an agent session

    Args:
        session_id: Session UUID
        status: New status (active, completed, failed)
        summary: Session summary
        metadata: Additional metadata
    """
    with get_db() as conn, conn.cursor() as cur:
        updates = []
        params = []

        if status:
            updates.append("status = %s")
            params.append(status)

        if summary:
            updates.append("summary = %s")
            params.append(summary)

        if metadata:
            updates.append("metadata = %s")
            params.append(Json(metadata))

        if status in ['completed', 'failed']:
            updates.append("end_time = NOW()")

        if updates:
            updates.append("updated_at = NOW()")
            sql = f"UPDATE agent_sessions SET {', '.join(updates)} WHERE id = %s"
            params.append(_sid(session_id))
            cur.execute(sql, params)
            conn.commit()


def add_agent_message(
    session_id: uuid.UUID,
    agent_name: str,
    role: str,
    content: str,
    metadata: Optional[Dict] = None
) -> uuid.UUID:
    """
    Add a message to an agent session

    Args:
        session_id: Session UUID
        agent_name: Name of the agent
        role: Message role (system, user, assistant, function)
        content: Message content
        metadata: Optional metadata

    Returns:
        Message UUID
    """
    with get_db() as conn, conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO agent_messages
            (session_id, agent_name, role, content, metadata)
            VALUES (%s, %s, %s, %s, %s)
            RETURNING id
            """,
            (_sid(session_id), agent_name, role, content, Json(metadata or {}))
        )
        message_id = cur.fetchone()[0]
        conn.commit()
        return message_id


def get_agent_session(session_id: uuid.UUID) -> Optional[Dict]:
    """
    Get agent session details

    Args:
        session_id: Session UUID

    Returns:
        Session dictionary or None
    """
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            "SELECT * FROM agent_sessions WHERE id = %s",
            (_sid(session_id),)
        )
        return cur.fetchone()


def delete_agent_session(session_id: uuid.UUID) -> bool:
    """
    Delete an agent session and all associated data.

    Messages are automatically deleted via ON DELETE CASCADE.
    Pending exploits will have session_id set to NULL via ON DELETE SET NULL.

    Args:
        session_id: Session UUID to delete

    Returns:
        True if session was deleted, False if not found
    """
    with get_db() as conn, conn.cursor() as cur:
        cur.execute(
            "DELETE FROM agent_sessions WHERE id = %s RETURNING id",
            (_sid(session_id),)
        )
        result = cur.fetchone()
        conn.commit()
        return result is not None


def delete_old_sessions(
    older_than_hours: int = 24,
    statuses: Optional[List[str]] = None
) -> Dict:
    """
    Delete sessions older than specified hours with given statuses.

    Args:
        older_than_hours: Delete sessions older than this many hours
        statuses: List of statuses to delete (default: completed, failed, stalled, cancelled)

    Returns:
        Dict with deleted_count, deleted_sessions list, and message_count
    """
    if statuses is None:
        statuses = ['completed', 'failed', 'stalled', 'cancelled']

    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        # First get the sessions that will be deleted and their message counts
        cur.execute(
            """
            SELECT s.id, s.session_name, s.status, s.created_at,
                   COUNT(m.id) as message_count
            FROM agent_sessions s
            LEFT JOIN agent_messages m ON m.session_id = s.id
            WHERE s.status = ANY(%s)
              AND s.created_at < NOW() - INTERVAL '%s hours'
            GROUP BY s.id
            """,
            (statuses, older_than_hours)
        )
        sessions_to_delete = cur.fetchall()

        if not sessions_to_delete:
            return {
                "deleted_count": 0,
                "deleted_sessions": [],
                "message_count": 0,
                "message": "No sessions matched deletion criteria"
            }

        session_ids = [s['id'] for s in sessions_to_delete]
        total_messages = sum(s['message_count'] for s in sessions_to_delete)

        # Delete the sessions (messages cascade automatically)
        cur.execute(
            "DELETE FROM agent_sessions WHERE id = ANY(%s)",
            (session_ids,)
        )
        conn.commit()

        return {
            "deleted_count": len(session_ids),
            "deleted_sessions": [
                {
                    "id": str(s['id']),
                    "name": s['session_name'],
                    "status": s['status'],
                    "created_at": s['created_at'].isoformat() if s['created_at'] else None,
                    "messages_deleted": s['message_count']
                }
                for s in sessions_to_delete
            ],
            "message_count": total_messages,
            "message": f"Deleted {len(session_ids)} sessions and {total_messages} messages"
        }


def get_agent_messages(
    session_id: uuid.UUID,
    limit: int = 100
) -> List[Dict]:
    """
    Get messages for an agent session

    Args:
        session_id: Session UUID
        limit: Maximum number of messages

    Returns:
        List of message dictionaries
    """
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            """
            SELECT * FROM agent_messages
            WHERE session_id = %s
            ORDER BY created_at ASC
            LIMIT %s
            """,
            (_sid(session_id), limit)
        )
        return cur.fetchall()


def build_resume_context(parent_session_id: uuid.UUID) -> Optional[str]:
    """
    Build a rich context summary from a parent session for use in a resumed session.

    Queries session details, scan metrics, agent messages, and discovered
    assets/ports/findings to produce a text summary that tells the new
    session's agents what work was already done.

    Args:
        parent_session_id: UUID of the parent (failed/stalled/stopped) session

    Returns:
        Formatted context string, or None if the parent session doesn't exist
    """
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        # 1. Get parent session details
        cur.execute(
            "SELECT * FROM agent_sessions WHERE id = %s",
            (_sid(parent_session_id),)
        )
        parent = cur.fetchone()
        if not parent:
            return None

        target = parent['target_description']
        status = parent['status']
        created = parent['created_at']
        ended = parent.get('end_time')
        summary = parent.get('summary') or ''
        metadata = parent.get('metadata') or {}

        duration = ''
        if created and ended:
            delta = ended - created
            minutes = int(delta.total_seconds() // 60)
            seconds = int(delta.total_seconds() % 60)
            duration = f"{minutes}m{seconds}s"
        elif created:
            duration = "unknown duration"

        # 2. Get scan metrics
        cur.execute(
            """
            SELECT scan_type, status, result_summary, duration_seconds
            FROM session_scan_metrics
            WHERE session_id = %s
            ORDER BY created_at ASC
            """,
            (_sid(parent_session_id),)
        )
        scans = cur.fetchall()

        # 3. Get last 10 messages from Reporter and Coordinator
        cur.execute(
            """
            SELECT agent_name, content, created_at
            FROM agent_messages
            WHERE session_id = %s
              AND agent_name IN ('Reporter', 'Coordinator')
            ORDER BY created_at DESC
            LIMIT 10
            """,
            (_sid(parent_session_id),)
        )
        key_messages = cur.fetchall()

        # 4. Extract target IP from target_description for asset/port/finding queries
        import re
        ip_match = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?', target)
        target_ip = ip_match.group(0) if ip_match else None

        assets_info = []
        if target_ip:
            # Strip CIDR for exact-match queries; cast to inet for type match
            query_ip = target_ip.split('/')[0]

            # Query assets (ip column is inet type)
            cur.execute(
                "SELECT id, ip, os FROM assets WHERE ip = %s::inet",
                (query_ip,)
            )
            assets = cur.fetchall()

            # Query ports
            cur.execute(
                """
                SELECT p.port, p.proto, p.service, p.version
                FROM ports p
                JOIN assets a ON p.asset_id = a.id
                WHERE a.ip = %s::inet
                ORDER BY p.port
                """,
                (query_ip,)
            )
            ports = cur.fetchall()

            # Query findings via asset_id join
            cur.execute(
                """
                SELECT f.severity, f.title
                FROM findings f
                JOIN assets a ON f.asset_id = a.id
                WHERE a.ip = %s::inet
                ORDER BY
                    CASE f.severity
                        WHEN 'critical' THEN 1
                        WHEN 'high' THEN 2
                        WHEN 'medium' THEN 3
                        WHEN 'low' THEN 4
                        ELSE 5
                    END
                """,
                (query_ip,)
            )
            findings = cur.fetchall()

            assets_info = {
                'ip': query_ip,
                'asset_count': len(assets),
                'ports': ports,
                'findings': findings,
            }

    # Build the context string
    lines = []
    lines.append("=== RESUMED SESSION ===")
    lines.append(
        f"This session continues a previous pentest (session {parent_session_id}) "
        f"that {status} after {duration}."
    )
    lines.append(f"Target: {target}")
    if summary:
        lines.append(f"Previous session summary: {summary[:300]}")
    lines.append("")

    # Scan results
    if scans:
        lines.append("== Previous Scan Results ==")
        completed_types = set()
        failed_types = set()
        for scan in scans:
            scan_type = scan['scan_type']
            scan_status = scan['status']
            result = scan.get('result_summary') or {}
            dur = scan.get('duration_seconds')
            dur_str = f" ({dur:.0f}s)" if dur else ""

            result_detail = ""
            if isinstance(result, dict) and result:
                # Summarize key parts of result_summary
                parts = []
                for k, v in list(result.items())[:3]:
                    parts.append(f"{k}={v}")
                if parts:
                    result_detail = f" — {', '.join(parts)}"

            lines.append(f"- {scan_type}: {scan_status}{dur_str}{result_detail}")

            if scan_status == 'completed':
                completed_types.add(scan_type)
            elif scan_status in ('failed', 'timeout', 'error'):
                failed_types.add(scan_type)
        lines.append("")
    else:
        completed_types = set()
        failed_types = set()

    # Assets, ports, findings
    if assets_info and isinstance(assets_info, dict):
        ports = assets_info.get('ports', [])
        findings = assets_info.get('findings', [])
        ip = assets_info['ip']

        lines.append("== Discovered Assets & Findings ==")
        severity_counts = {}
        for f in findings:
            sev = f.get('severity', 'info')
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        sev_summary = ', '.join(f"{c} {s}" for s, c in severity_counts.items()) if severity_counts else "none"
        lines.append(f"- {ip}: {len(ports)} open ports, {len(findings)} findings ({sev_summary})")

        for port in ports[:15]:  # Limit to 15 ports
            version = f" {port['version']}" if port.get('version') else ""
            lines.append(f"  - Port {port['port']}/{port['proto']}: {port.get('service', 'unknown')}{version}")
        if len(ports) > 15:
            lines.append(f"  - ... and {len(ports) - 15} more ports")
        lines.append("")

    # Key agent observations
    if key_messages:
        lines.append("== Key Agent Observations ==")
        for msg in reversed(key_messages[:5]):
            agent = msg['agent_name']
            content = (msg['content'] or '')[:200]
            lines.append(f"[{agent}] {content}")
        lines.append("")

    # Recommended next steps
    lines.append("== Recommended Next Steps ==")
    if failed_types:
        lines.append(
            f"Continue from where the previous session stopped. "
            f"The following scans still need to be run or re-run: {', '.join(sorted(failed_types))}."
        )
    else:
        lines.append("Continue from where the previous session stopped.")

    if assets_info and isinstance(assets_info, dict):
        n_findings = len(assets_info.get('findings', []))
        if n_findings:
            lines.append(f"Focus on deeper analysis of the {n_findings} findings already identified.")

    lines.append("")

    return '\n'.join(lines)


def build_existing_target_context(target_description: str) -> Optional[str]:
    """
    Query the database for existing scan data about a target (from any prior
    session or manual scan) and build a context block so the agents know what
    data already exists before planning their work.

    Returns a context string, or None if no existing data was found.
    """
    import re

    ip_match = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?', target_description)
    target_ip = ip_match.group(0).split('/')[0] if ip_match else None

    if not target_ip:
        return None

    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        # Query assets
        cur.execute("SELECT id, ip, hostname, os FROM assets WHERE ip = %s::inet", (target_ip,))
        assets = cur.fetchall()
        if not assets:
            return None

        asset_ids = [str(a['id']) for a in assets]

        # Query open ports
        cur.execute(
            """
            SELECT p.port, p.proto, p.service, p.version, p.state
            FROM ports p
            JOIN assets a ON p.asset_id = a.id
            WHERE a.ip = %s::inet
            ORDER BY p.port
            """,
            (target_ip,)
        )
        ports = cur.fetchall()

        # Query findings (vulns from nmap, nuclei, etc.)
        cur.execute(
            """
            SELECT f.severity, f.title, f.source, f.template_id, f.created_at
            FROM findings f
            JOIN assets a ON f.asset_id = a.id
            WHERE a.ip = %s::inet
            ORDER BY
                CASE f.severity
                    WHEN 'critical' THEN 1 WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5
                END,
                f.created_at DESC
            LIMIT 100
            """,
            (target_ip,)
        )
        findings = cur.fetchall()

        # Query web findings (gobuster, nikto, zap, playwright, etc.)
        cur.execute(
            """
            SELECT wf.tool, wf.finding_type, wf.url, wf.severity, wf.title, wf.created_at
            FROM web_findings wf
            WHERE wf.target_url LIKE %s
            ORDER BY
                CASE wf.severity
                    WHEN 'critical' THEN 1 WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5
                END,
                wf.created_at DESC
            LIMIT 100
            """,
            (f"%{target_ip}%",)
        )
        web_findings = cur.fetchall()

        # Query previous sessions that targeted this host
        cur.execute(
            """
            SELECT session_name, status, created_at, end_time, summary
            FROM agent_sessions
            WHERE target_description LIKE %s
            ORDER BY created_at DESC
            LIMIT 5
            """,
            (f"%{target_ip}%",)
        )
        prev_sessions = cur.fetchall()

    # Build context string
    if not ports and not findings and not web_findings:
        return None

    lines = []
    lines.append("=== EXISTING DATA FOR TARGET ===")
    lines.append(
        f"The database already contains scan results for {target_ip} from prior scans. "
        f"Review this data before deciding which scans to run — skip scans whose data is already adequate."
    )
    lines.append("")

    # Previous sessions
    if prev_sessions:
        lines.append(f"== Previous Sessions ({len(prev_sessions)}) ==")
        for ps in prev_sessions:
            ts = ps['created_at']
            lines.append(f"  - {ps['session_name']} [{ps['status']}] started {ts}")
            if ps.get('summary'):
                lines.append(f"    Summary: {ps['summary'][:150]}")
        lines.append("")

    # Ports
    if ports:
        lines.append(f"== Open Ports ({len(ports)}) ==")
        for p in ports:
            svc = p.get('service') or 'unknown'
            ver = f" ({p['version']})" if p.get('version') else ''
            lines.append(f"  {p['port']}/{p['proto']} — {svc}{ver}")
        lines.append("")

    # Findings by severity
    if findings:
        sev_counts = {}
        sources = set()
        for f in findings:
            sev = f.get('severity', 'info')
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
            if f.get('source'):
                sources.add(f['source'])
        sev_str = ", ".join(f"{k}: {v}" for k, v in sorted(sev_counts.items(),
                           key=lambda x: ['critical','high','medium','low','info'].index(x[0])
                           if x[0] in ['critical','high','medium','low','info'] else 9))
        lines.append(f"== Vulnerability Findings ({len(findings)}) ==")
        lines.append(f"  Severity breakdown: {sev_str}")
        lines.append(f"  Sources: {', '.join(sorted(sources))}")
        for f in findings[:20]:
            lines.append(f"  [{f['severity']}] {f['title']} (source: {f.get('source', '?')})")
        if len(findings) > 20:
            lines.append(f"  ... and {len(findings) - 20} more")
        lines.append("")

    # Web findings by tool
    if web_findings:
        tools = set(wf.get('tool', '?') for wf in web_findings)
        lines.append(f"== Web Findings ({len(web_findings)}) ==")
        lines.append(f"  Tools: {', '.join(sorted(tools))}")
        for wf in web_findings[:15]:
            lines.append(
                f"  [{wf.get('severity', '?')}] {wf.get('title', wf.get('finding_type', '?'))} "
                f"— {wf.get('url', '?')} (tool: {wf.get('tool', '?')})"
            )
        if len(web_findings) > 15:
            lines.append(f"  ... and {len(web_findings) - 15} more")
        lines.append("")

    lines.append(
        "Use this existing data to inform your scan plan. Focus scanning efforts on areas "
        "NOT already covered. Include ALL existing findings (from any source) in your final analysis and report."
    )
    lines.append("")

    return '\n'.join(lines)


def list_agent_sessions(
    status: Optional[str] = None,
    limit: int = 50
) -> List[Dict]:
    """
    List agent sessions

    Args:
        status: Filter by status (active, completed, failed)
        limit: Maximum number of sessions

    Returns:
        List of session dictionaries
    """
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        if status:
            cur.execute(
                """
                SELECT * FROM agent_sessions
                WHERE status = %s
                ORDER BY created_at DESC
                LIMIT %s
                """,
                (status, limit)
            )
        else:
            cur.execute(
                """
                SELECT * FROM agent_sessions
                ORDER BY created_at DESC
                LIMIT %s
                """,
                (limit,)
            )
        return cur.fetchall()


def link_session_to_scans(
    session_id: uuid.UUID,
    scan_type: str,
    scan_id: uuid.UUID
):
    """
    Link an agent session to a specific scan

    Args:
        session_id: Agent session UUID
        scan_type: Type of scan (nmap, web, nuclei, playwright)
        scan_id: Scan UUID
    """
    with get_db() as conn, conn.cursor() as cur:
        # Update session metadata with scan reference
        cur.execute(
            """
            UPDATE agent_sessions
            SET metadata = COALESCE(metadata, '{}'::jsonb) ||
                jsonb_build_object('scans',
                    COALESCE(metadata->'scans', '[]'::jsonb) ||
                    jsonb_build_array(jsonb_build_object(
                        'type', %s,
                        'scan_id', %s,
                        'linked_at', NOW()
                    ))
                )
            WHERE id = %s
            """,
            (scan_type, str(scan_id), session_id)
        )
        conn.commit()


# ===============================
# Exploit Approval Workflow Functions
# ===============================

def create_pending_exploit(
    source: str,
    exploit_id: str,
    exploit_title: str,
    target_ip: str,
    customized_command: str,
    target_port: Optional[int] = None,
    target_service: Optional[str] = None,
    target_version: Optional[str] = None,
    exploit_type: Optional[str] = None,
    parameters: Optional[Dict] = None,
    match_confidence: Optional[float] = None,
    match_reasoning: Optional[str] = None,
    asset_id: Optional[uuid.UUID] = None,
    port_id: Optional[uuid.UUID] = None,
    session_id: Optional[uuid.UUID] = None,
    requested_by: Optional[str] = None
) -> uuid.UUID:
    """
    Queue an exploit for human approval.

    Args:
        source: 'exploitdb' or 'metasploit'
        exploit_id: EDB-ID or MSF module path
        exploit_title: Human-readable exploit name
        target_ip: Target IP address
        customized_command: Ready-to-run command/script
        target_port: Target port number
        target_service: Service name (e.g., 'smb', 'ssh')
        target_version: Service version
        exploit_type: 'rce', 'auth_bypass', 'info_disclosure', 'other'
        parameters: Dict of parameters (RHOST, LHOST, etc.)
        match_confidence: 0.0-1.0 confidence score
        match_reasoning: Why this exploit was matched
        asset_id: Reference to assets table
        port_id: Reference to ports table
        session_id: Reference to agent_sessions table
        requested_by: Agent/user that requested this exploit

    Returns:
        Pending exploit UUID
    """
    with get_db() as conn, conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO pending_exploits
            (source, exploit_id, exploit_title, target_ip, target_port,
             target_service, target_version, exploit_type, customized_command,
             parameters, match_confidence, match_reasoning, asset_id, port_id,
             session_id, requested_by, status)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'pending')
            RETURNING id
            """,
            (source, exploit_id, exploit_title, target_ip, target_port,
             target_service, target_version, exploit_type, customized_command,
             Json(parameters or {}), match_confidence, match_reasoning,
             asset_id, port_id, session_id, requested_by)
        )
        pending_id = cur.fetchone()[0]
        conn.commit()
        return pending_id


def get_pending_exploit(exploit_id: uuid.UUID) -> Optional[Dict]:
    """
    Get a pending exploit by ID.

    Args:
        exploit_id: Pending exploit UUID

    Returns:
        Exploit dictionary or None
    """
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            "SELECT * FROM pending_exploits WHERE id = %s",
            (exploit_id,)
        )
        return cur.fetchone()


def list_pending_exploits(
    status: Optional[str] = None,
    session_id: Optional[uuid.UUID] = None,
    limit: int = 50
) -> List[Dict]:
    """
    List pending exploits with optional filtering.

    Args:
        status: Filter by status ('pending', 'approved', 'rejected', 'executed', 'failed')
        session_id: Filter by agent session
        limit: Maximum number of results

    Returns:
        List of exploit dictionaries
    """
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        conditions = []
        params = []

        if status:
            conditions.append("status = %s")
            params.append(status)

        if session_id:
            conditions.append("session_id = %s")
            params.append(_sid(session_id))

        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""

        cur.execute(
            f"""
            SELECT * FROM pending_exploits
            {where_clause}
            ORDER BY created_at DESC
            LIMIT %s
            """,
            params + [limit]
        )
        return cur.fetchall()


def approve_exploit(
    exploit_id: uuid.UUID,
    reviewed_by: str,
    notes: Optional[str] = None
) -> bool:
    """
    Approve a pending exploit for execution.

    Args:
        exploit_id: Pending exploit UUID
        reviewed_by: Human approver identifier
        notes: Optional approval notes

    Returns:
        True if approved, False if not found or already processed
    """
    with get_db() as conn, conn.cursor() as cur:
        cur.execute(
            """
            UPDATE pending_exploits
            SET status = 'approved',
                reviewed_by = %s,
                reviewed_at = NOW(),
                metadata = COALESCE(metadata, '{}'::jsonb) ||
                    CASE WHEN %s IS NOT NULL
                         THEN jsonb_build_object('approval_notes', %s)
                         ELSE '{}'::jsonb END
            WHERE id = %s AND status = 'pending'
            RETURNING id
            """,
            (reviewed_by, notes, notes, exploit_id)
        )
        result = cur.fetchone()
        conn.commit()
        return result is not None


def reject_exploit(
    exploit_id: uuid.UUID,
    reviewed_by: str,
    reason: str
) -> bool:
    """
    Reject a pending exploit.

    Args:
        exploit_id: Pending exploit UUID
        reviewed_by: Human reviewer identifier
        reason: Rejection reason

    Returns:
        True if rejected, False if not found or already processed
    """
    with get_db() as conn, conn.cursor() as cur:
        cur.execute(
            """
            UPDATE pending_exploits
            SET status = 'rejected',
                reviewed_by = %s,
                reviewed_at = NOW(),
                rejection_reason = %s
            WHERE id = %s AND status = 'pending'
            RETURNING id
            """,
            (reviewed_by, reason, exploit_id)
        )
        result = cur.fetchone()
        conn.commit()
        return result is not None


def mark_exploit_executed(exploit_id: uuid.UUID) -> bool:
    """
    Mark an approved exploit as executed.

    Args:
        exploit_id: Pending exploit UUID

    Returns:
        True if marked, False if not approved
    """
    with get_db() as conn, conn.cursor() as cur:
        cur.execute(
            """
            UPDATE pending_exploits
            SET status = 'executed'
            WHERE id = %s AND status = 'approved'
            RETURNING id
            """,
            (exploit_id,)
        )
        result = cur.fetchone()
        conn.commit()
        return result is not None


def mark_exploit_failed(exploit_id: uuid.UUID, error: Optional[str] = None) -> bool:
    """
    Mark an exploit execution as failed.

    Args:
        exploit_id: Pending exploit UUID
        error: Error message

    Returns:
        True if marked, False if not found
    """
    with get_db() as conn, conn.cursor() as cur:
        cur.execute(
            """
            UPDATE pending_exploits
            SET status = 'failed',
                metadata = COALESCE(metadata, '{}'::jsonb) ||
                    CASE WHEN %s IS NOT NULL
                         THEN jsonb_build_object('error', %s)
                         ELSE '{}'::jsonb END
            WHERE id = %s AND status IN ('approved', 'executed')
            RETURNING id
            """,
            (error, error, exploit_id)
        )
        result = cur.fetchone()
        conn.commit()
        return result is not None


def create_exploit_result(
    pending_exploit_id: uuid.UUID,
    success: bool,
    output: Optional[str] = None,
    parsed_result: Optional[Dict] = None,
    session_type: Optional[str] = None,
    session_id: Optional[str] = None,
    execution_time_ms: Optional[int] = None,
    executor_container: Optional[str] = None
) -> uuid.UUID:
    """
    Record the result of an exploit execution.

    Args:
        pending_exploit_id: Reference to pending_exploits table
        success: Whether the exploit succeeded
        output: Raw stdout/stderr output
        parsed_result: Structured result data
        session_type: 'meterpreter', 'shell', or None
        session_id: MSF session ID if applicable
        execution_time_ms: Execution duration in milliseconds
        executor_container: Container ID that ran the exploit

    Returns:
        Result UUID
    """
    with get_db() as conn, conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO exploit_results
            (pending_exploit_id, success, output, parsed_result, session_type,
             session_id, execution_time_ms, executor_container, completed_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, NOW())
            RETURNING id
            """,
            (pending_exploit_id, success, output, Json(parsed_result or {}),
             session_type, session_id, execution_time_ms, executor_container)
        )
        result_id = cur.fetchone()[0]
        conn.commit()
        return result_id


def get_exploit_result(pending_exploit_id: uuid.UUID) -> Optional[Dict]:
    """
    Get the execution result for a pending exploit.

    Args:
        pending_exploit_id: Pending exploit UUID

    Returns:
        Result dictionary or None
    """
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            """
            SELECT * FROM exploit_results
            WHERE pending_exploit_id = %s
            ORDER BY executed_at DESC
            LIMIT 1
            """,
            (pending_exploit_id,)
        )
        return cur.fetchone()


# ===============================
# Metasploit Module Cache Functions
# ===============================

def upsert_msf_module(
    module_path: str,
    module_type: str,
    name: str,
    description: Optional[str] = None,
    rank: Optional[str] = None,
    platforms: Optional[List[str]] = None,
    architectures: Optional[List[str]] = None,
    targets: Optional[List[Dict]] = None,
    cve: Optional[List[str]] = None,
    edb_id: Optional[List[str]] = None,
    required_options: Optional[Dict] = None,
    optional_options: Optional[Dict] = None,
    author: Optional[List[str]] = None,
    disclosure_date: Optional[str] = None
) -> uuid.UUID:
    """
    Insert or update a Metasploit module in the cache.

    Returns:
        Module UUID
    """
    with get_db() as conn, conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO msf_modules
            (module_path, module_type, name, description, rank, platforms,
             architectures, targets, cve, edb_id, required_options,
             optional_options, author, disclosure_date, last_updated)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
            ON CONFLICT (module_path) DO UPDATE SET
                name = EXCLUDED.name,
                description = EXCLUDED.description,
                rank = EXCLUDED.rank,
                platforms = EXCLUDED.platforms,
                architectures = EXCLUDED.architectures,
                targets = EXCLUDED.targets,
                cve = EXCLUDED.cve,
                edb_id = EXCLUDED.edb_id,
                required_options = EXCLUDED.required_options,
                optional_options = EXCLUDED.optional_options,
                author = EXCLUDED.author,
                disclosure_date = EXCLUDED.disclosure_date,
                last_updated = NOW()
            RETURNING id
            """,
            (module_path, module_type, name, description, rank, platforms,
             architectures, Json(targets or []), cve, edb_id,
             Json(required_options or {}), Json(optional_options or {}),
             author, disclosure_date)
        )
        module_id = cur.fetchone()[0]
        conn.commit()
        return module_id


def search_msf_modules(
    query: Optional[str] = None,
    module_type: Optional[str] = None,
    cve: Optional[str] = None,
    platform: Optional[str] = None,
    limit: int = 20
) -> List[Dict]:
    """
    Search Metasploit modules by various criteria.

    Args:
        query: Search term for name/description
        module_type: 'exploit', 'auxiliary', 'post'
        cve: CVE identifier to match
        platform: Target platform
        limit: Maximum results

    Returns:
        List of matching modules
    """
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        conditions = []
        params = []

        if query:
            conditions.append("(name ILIKE %s OR description ILIKE %s OR module_path ILIKE %s)")
            params.extend([f"%{query}%", f"%{query}%", f"%{query}%"])

        if module_type:
            conditions.append("module_type = %s")
            params.append(module_type)

        if cve:
            conditions.append("%s = ANY(cve)")
            params.append(cve)

        if platform:
            conditions.append("%s = ANY(platforms)")
            params.append(platform)

        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""

        cur.execute(
            f"""
            SELECT * FROM msf_modules
            {where_clause}
            ORDER BY
                CASE rank
                    WHEN 'excellent' THEN 1
                    WHEN 'great' THEN 2
                    WHEN 'good' THEN 3
                    WHEN 'normal' THEN 4
                    WHEN 'average' THEN 5
                    WHEN 'low' THEN 6
                    ELSE 7
                END,
                last_updated DESC
            LIMIT %s
            """,
            params + [limit]
        )
        return cur.fetchall()


# ===============================
# Prompt Configuration Functions
# ===============================

def list_prompt_configs(limit: int = 50) -> List[Dict]:
    """List all prompt configurations."""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            "SELECT id, name, description, is_active, created_at, updated_at "
            "FROM prompt_configs ORDER BY created_at DESC LIMIT %s",
            (limit,)
        )
        return cur.fetchall()


def get_prompt_config(config_id: uuid.UUID) -> Optional[Dict]:
    """Get a prompt configuration by ID (includes full prompts)."""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("SELECT * FROM prompt_configs WHERE id = %s", (config_id,))
        return cur.fetchone()


def get_prompt_config_by_name(name: str) -> Optional[Dict]:
    """Get a prompt configuration by name (includes full prompts)."""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("SELECT * FROM prompt_configs WHERE name = %s", (name,))
        return cur.fetchone()


def get_active_prompt_config() -> Optional[Dict]:
    """Get the currently active prompt configuration."""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            "SELECT * FROM prompt_configs WHERE is_active = true LIMIT 1"
        )
        return cur.fetchone()


def create_prompt_config(
    name: str,
    prompts: Dict,
    description: Optional[str] = None,
    is_active: bool = False
) -> uuid.UUID:
    """Create a new prompt configuration."""
    with get_db() as conn, conn.cursor() as cur:
        if is_active:
            cur.execute("UPDATE prompt_configs SET is_active = false WHERE is_active = true")
        cur.execute(
            """
            INSERT INTO prompt_configs (name, description, prompts, is_active)
            VALUES (%s, %s, %s, %s)
            RETURNING id
            """,
            (name, description, Json(prompts), is_active)
        )
        config_id = cur.fetchone()[0]
        conn.commit()
        return config_id


def update_prompt_config(
    config_id: uuid.UUID,
    name: Optional[str] = None,
    description: Optional[str] = None,
    prompts: Optional[Dict] = None,
    is_active: Optional[bool] = None
) -> bool:
    """Update an existing prompt configuration."""
    with get_db() as conn, conn.cursor() as cur:
        updates = []
        params = []
        if name is not None:
            updates.append("name = %s")
            params.append(name)
        if description is not None:
            updates.append("description = %s")
            params.append(description)
        if prompts is not None:
            updates.append("prompts = %s")
            params.append(Json(prompts))
        if is_active is not None:
            if is_active:
                cur.execute("UPDATE prompt_configs SET is_active = false WHERE is_active = true")
            updates.append("is_active = %s")
            params.append(is_active)
        if not updates:
            return False
        updates.append("updated_at = now()")
        params.append(config_id)
        cur.execute(
            f"UPDATE prompt_configs SET {', '.join(updates)} WHERE id = %s RETURNING id",
            params
        )
        result = cur.fetchone()
        conn.commit()
        return result is not None


def duplicate_prompt_config(config_id: uuid.UUID, new_name: str) -> uuid.UUID:
    """Duplicate a prompt configuration with a new name."""
    source = get_prompt_config(config_id)
    if not source:
        raise ValueError(f"Prompt config {config_id} not found")
    return create_prompt_config(
        name=new_name,
        prompts=source["prompts"],
        description=f"Duplicated from '{source['name']}'",
        is_active=False
    )


def delete_prompt_config(config_id: uuid.UUID) -> bool:
    """Delete a prompt configuration."""
    with get_db() as conn, conn.cursor() as cur:
        cur.execute("DELETE FROM prompt_configs WHERE id = %s RETURNING id", (config_id,))
        result = cur.fetchone()
        conn.commit()
        return result is not None
