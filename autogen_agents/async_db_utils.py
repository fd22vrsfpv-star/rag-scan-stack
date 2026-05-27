"""
Async database utilities for Autogen agent sessions using asyncpg

This module provides non-blocking database operations for use in async contexts.
The sync version in db_utils.py is kept for backwards compatibility.
"""

import os
import uuid
import json
import asyncio
from contextlib import asynccontextmanager
from typing import Optional, Dict, List, Any
import asyncpg

# Connection pool singleton
_pool: Optional[asyncpg.Pool] = None
_pool_lock = asyncio.Lock()


def get_db_dsn() -> str:
    """Get database connection string from environment"""
    return os.environ.get(
        "DB_DSN",
        "postgresql://app:app@rag-postgres:5432/scans"
    )


async def get_pool() -> asyncpg.Pool:
    """Get or create the connection pool"""
    global _pool
    if _pool is None or _pool._closed:
        async with _pool_lock:
            # Double-check after acquiring lock
            if _pool is None or _pool._closed:
                _pool = await asyncpg.create_pool(
                    get_db_dsn(),
                    min_size=int(os.environ.get("DB_POOL_MIN", "2")),
                    max_size=int(os.environ.get("DB_POOL_MAX", "10")),
                    command_timeout=60.0
                )
    return _pool


async def close_pool():
    """Close the connection pool"""
    global _pool
    if _pool is not None:
        await _pool.close()
        _pool = None


@asynccontextmanager
async def get_db():
    """Async context manager for database connections"""
    pool = await get_pool()
    async with pool.acquire() as conn:
        yield conn


def _serialize_dict(d: Optional[Dict]) -> Optional[str]:
    """Serialize dict to JSON string for asyncpg"""
    if d is None:
        return None
    return json.dumps(d)


def _deserialize_record(record: asyncpg.Record) -> Dict:
    """Convert asyncpg Record to dict"""
    if record is None:
        return None
    return dict(record)


def _deserialize_records(records: List[asyncpg.Record]) -> List[Dict]:
    """Convert list of asyncpg Records to list of dicts"""
    return [dict(r) for r in records]


# ===============================
# Agent Session Functions
# ===============================

async def create_agent_session(
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
    async with get_db() as conn:
        row = await conn.fetchrow(
            """
            INSERT INTO agent_sessions
            (session_name, target_description, configuration, status)
            VALUES ($1, $2, $3::jsonb, 'active')
            RETURNING id
            """,
            session_name, target_description, _serialize_dict(configuration or {})
        )
        return row['id']


async def update_agent_session(
    session_id: uuid.UUID,
    status: Optional[str] = None,
    summary: Optional[str] = None,
    metadata: Optional[Dict] = None
) -> bool:
    """
    Update an agent session

    Args:
        session_id: Session UUID
        status: New status (active, completed, failed)
        summary: Session summary
        metadata: Additional metadata

    Returns:
        True if updated, False if not found
    """
    async with get_db() as conn:
        # Build dynamic update query
        updates = []
        params = []
        param_idx = 1

        if status:
            updates.append(f"status = ${param_idx}")
            params.append(status)
            param_idx += 1

        if summary:
            updates.append(f"summary = ${param_idx}")
            params.append(summary)
            param_idx += 1

        if metadata:
            updates.append(f"metadata = ${param_idx}::jsonb")
            params.append(_serialize_dict(metadata))
            param_idx += 1

        if status in ['completed', 'failed', 'stopped']:
            updates.append("end_time = NOW()")

        if not updates:
            return False

        updates.append("updated_at = NOW()")
        params.append(session_id)
        sql = f"UPDATE agent_sessions SET {', '.join(updates)} WHERE id = ${param_idx} RETURNING id"
        param_idx += 1
        result = await conn.fetchrow(sql, *params)
        return result is not None


async def get_agent_session(session_id: uuid.UUID) -> Optional[Dict]:
    """
    Get agent session details

    Args:
        session_id: Session UUID

    Returns:
        Session dictionary or None
    """
    async with get_db() as conn:
        row = await conn.fetchrow(
            "SELECT * FROM agent_sessions WHERE id = $1",
            session_id
        )
        return _deserialize_record(row)


async def delete_agent_session(session_id: uuid.UUID) -> bool:
    """
    Delete an agent session and all associated data.

    Messages are automatically deleted via ON DELETE CASCADE.
    Pending exploits will have session_id set to NULL via ON DELETE SET NULL.

    Args:
        session_id: Session UUID to delete

    Returns:
        True if session was deleted, False if not found
    """
    async with get_db() as conn:
        result = await conn.fetchrow(
            "DELETE FROM agent_sessions WHERE id = $1 RETURNING id",
            session_id
        )
        return result is not None


async def delete_old_sessions(
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

    async with get_db() as conn:
        # First get the sessions that will be deleted and their message counts
        sessions_to_delete = await conn.fetch(
            """
            SELECT s.id, s.session_name, s.status, s.created_at,
                   COUNT(m.id) as message_count
            FROM agent_sessions s
            LEFT JOIN agent_messages m ON m.session_id = s.id
            WHERE s.status = ANY($1)
              AND s.created_at < NOW() - INTERVAL '1 hour' * $2
            GROUP BY s.id
            """,
            statuses, older_than_hours
        )

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
        await conn.execute(
            "DELETE FROM agent_sessions WHERE id = ANY($1)",
            session_ids
        )

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


async def list_agent_sessions(
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
    async with get_db() as conn:
        if status:
            rows = await conn.fetch(
                """
                SELECT * FROM agent_sessions
                WHERE status = $1
                ORDER BY created_at DESC
                LIMIT $2
                """,
                status, limit
            )
        else:
            rows = await conn.fetch(
                """
                SELECT * FROM agent_sessions
                ORDER BY created_at DESC
                LIMIT $1
                """,
                limit
            )
        return _deserialize_records(rows)


async def add_agent_message(
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
    async with get_db() as conn:
        row = await conn.fetchrow(
            """
            INSERT INTO agent_messages
            (session_id, agent_name, role, content, metadata)
            VALUES ($1, $2, $3, $4, $5::jsonb)
            RETURNING id
            """,
            session_id, agent_name, role, content, _serialize_dict(metadata or {})
        )
        return row['id']


async def get_agent_messages(
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
    async with get_db() as conn:
        rows = await conn.fetch(
            """
            SELECT * FROM agent_messages
            WHERE session_id = $1
            ORDER BY created_at ASC
            LIMIT $2
            """,
            session_id, limit
        )
        return _deserialize_records(rows)


async def link_session_to_scans(
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
    async with get_db() as conn:
        await conn.execute(
            """
            UPDATE agent_sessions
            SET metadata = COALESCE(metadata, '{}'::jsonb) ||
                jsonb_build_object('scans',
                    COALESCE(metadata->'scans', '[]'::jsonb) ||
                    jsonb_build_array(jsonb_build_object(
                        'type', $1,
                        'scan_id', $2,
                        'linked_at', NOW()
                    ))
                )
            WHERE id = $3
            """,
            scan_type, str(scan_id), session_id
        )


# ===============================
# Exploit Approval Workflow Functions
# ===============================

async def create_pending_exploit(
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
    async with get_db() as conn:
        row = await conn.fetchrow(
            """
            INSERT INTO pending_exploits
            (source, exploit_id, exploit_title, target_ip, target_port,
             target_service, target_version, exploit_type, customized_command,
             parameters, match_confidence, match_reasoning, asset_id, port_id,
             session_id, requested_by, status)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb, $11, $12, $13, $14, $15, $16, 'pending')
            RETURNING id
            """,
            source, exploit_id, exploit_title, target_ip, target_port,
            target_service, target_version, exploit_type, customized_command,
            _serialize_dict(parameters or {}), match_confidence, match_reasoning,
            asset_id, port_id, session_id, requested_by
        )
        return row['id']


async def get_pending_exploit(exploit_id: uuid.UUID) -> Optional[Dict]:
    """
    Get a pending exploit by ID.

    Args:
        exploit_id: Pending exploit UUID

    Returns:
        Exploit dictionary or None
    """
    async with get_db() as conn:
        row = await conn.fetchrow(
            "SELECT * FROM pending_exploits WHERE id = $1",
            exploit_id
        )
        return _deserialize_record(row)


async def list_pending_exploits(
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
    async with get_db() as conn:
        conditions = []
        params = []
        param_idx = 1

        if status:
            conditions.append(f"status = ${param_idx}")
            params.append(status)
            param_idx += 1

        if session_id:
            conditions.append(f"session_id = ${param_idx}")
            params.append(session_id)
            param_idx += 1

        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        params.append(limit)
        limit_idx = param_idx
        param_idx += 1

        rows = await conn.fetch(
            f"""
            SELECT * FROM pending_exploits
            {where_clause}
            ORDER BY created_at DESC
            LIMIT ${limit_idx}
            """,
            *params
        )
        return _deserialize_records(rows)


async def approve_exploit(
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
    async with get_db() as conn:
        # Build metadata update based on notes
        if notes:
            metadata_update = f"jsonb_build_object('approval_notes', $3)"
            result = await conn.fetchrow(
                f"""
                UPDATE pending_exploits
                SET status = 'approved',
                    reviewed_by = $1,
                    reviewed_at = NOW(),
                    metadata = COALESCE(metadata, '{{}}'::jsonb) || {metadata_update}
                WHERE id = $4 AND status = 'pending'
                RETURNING id
                """,
                reviewed_by, notes, notes, exploit_id
            )
        else:
            result = await conn.fetchrow(
                """
                UPDATE pending_exploits
                SET status = 'approved',
                    reviewed_by = $1,
                    reviewed_at = NOW()
                WHERE id = $2 AND status = 'pending'
                RETURNING id
                """,
                reviewed_by, exploit_id
            )
        return result is not None


async def reject_exploit(
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
    async with get_db() as conn:
        result = await conn.fetchrow(
            """
            UPDATE pending_exploits
            SET status = 'rejected',
                reviewed_by = $1,
                reviewed_at = NOW(),
                rejection_reason = $2
            WHERE id = $3 AND status = 'pending'
            RETURNING id
            """,
            reviewed_by, reason, exploit_id
        )
        return result is not None


async def mark_exploit_executed(exploit_id: uuid.UUID) -> bool:
    """
    Mark an approved exploit as executed.

    Args:
        exploit_id: Pending exploit UUID

    Returns:
        True if marked, False if not approved
    """
    async with get_db() as conn:
        result = await conn.fetchrow(
            """
            UPDATE pending_exploits
            SET status = 'executed'
            WHERE id = $1 AND status = 'approved'
            RETURNING id
            """,
            exploit_id
        )
        return result is not None


async def mark_exploit_failed(exploit_id: uuid.UUID, error: Optional[str] = None) -> bool:
    """
    Mark an exploit execution as failed.

    Args:
        exploit_id: Pending exploit UUID
        error: Error message

    Returns:
        True if marked, False if not found
    """
    async with get_db() as conn:
        if error:
            result = await conn.fetchrow(
                """
                UPDATE pending_exploits
                SET status = 'failed',
                    metadata = COALESCE(metadata, '{}'::jsonb) ||
                        jsonb_build_object('error', $1)
                WHERE id = $2 AND status IN ('approved', 'executed')
                RETURNING id
                """,
                error, exploit_id
            )
        else:
            result = await conn.fetchrow(
                """
                UPDATE pending_exploits
                SET status = 'failed'
                WHERE id = $1 AND status IN ('approved', 'executed')
                RETURNING id
                """,
                exploit_id
            )
        return result is not None


async def create_exploit_result(
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
    async with get_db() as conn:
        row = await conn.fetchrow(
            """
            INSERT INTO exploit_results
            (pending_exploit_id, success, output, parsed_result, session_type,
             session_id, execution_time_ms, executor_container, completed_at)
            VALUES ($1, $2, $3, $4::jsonb, $5, $6, $7, $8, NOW())
            RETURNING id
            """,
            pending_exploit_id, success, output, _serialize_dict(parsed_result or {}),
            session_type, session_id, execution_time_ms, executor_container
        )
        return row['id']


async def get_exploit_result(pending_exploit_id: uuid.UUID) -> Optional[Dict]:
    """
    Get the execution result for a pending exploit.

    Args:
        pending_exploit_id: Pending exploit UUID

    Returns:
        Result dictionary or None
    """
    async with get_db() as conn:
        row = await conn.fetchrow(
            """
            SELECT * FROM exploit_results
            WHERE pending_exploit_id = $1
            ORDER BY executed_at DESC
            LIMIT 1
            """,
            pending_exploit_id
        )
        return _deserialize_record(row)


# ===============================
# Metasploit Module Cache Functions
# ===============================

async def upsert_msf_module(
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
    async with get_db() as conn:
        row = await conn.fetchrow(
            """
            INSERT INTO msf_modules
            (module_path, module_type, name, description, rank, platforms,
             architectures, targets, cve, edb_id, required_options,
             optional_options, author, disclosure_date, last_updated)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9, $10, $11::jsonb, $12::jsonb, $13, $14, NOW())
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
            module_path, module_type, name, description, rank, platforms,
            architectures, _serialize_dict(targets or []),
            cve, edb_id,
            _serialize_dict(required_options or {}),
            _serialize_dict(optional_options or {}),
            author, disclosure_date
        )
        return row['id']


async def search_msf_modules(
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
    async with get_db() as conn:
        conditions = []
        params = []
        param_idx = 1

        if query:
            conditions.append(f"(name ILIKE ${param_idx} OR description ILIKE ${param_idx + 1} OR module_path ILIKE ${param_idx + 2})")
            params.extend([f"%{query}%", f"%{query}%", f"%{query}%"])
            param_idx += 3

        if module_type:
            conditions.append(f"module_type = ${param_idx}")
            params.append(module_type)
            param_idx += 1

        if cve:
            conditions.append(f"${param_idx} = ANY(cve)")
            params.append(cve)
            param_idx += 1

        if platform:
            conditions.append(f"${param_idx} = ANY(platforms)")
            params.append(platform)
            param_idx += 1

        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        params.append(limit)
        limit_idx = param_idx
        param_idx += 1

        rows = await conn.fetch(
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
            LIMIT ${limit_idx}
            """,
            *params
        )
        return _deserialize_records(rows)


# ===============================
# Utility Functions
# ===============================

async def get_session_with_messages(session_id: uuid.UUID) -> Optional[Dict]:
    """
    Get a session with its messages in a single query.

    Args:
        session_id: Session UUID

    Returns:
        Session dict with 'messages' key, or None
    """
    async with get_db() as conn:
        # Use a transaction for consistency
        async with conn.transaction():
            session = await conn.fetchrow(
                "SELECT * FROM agent_sessions WHERE id = $1",
                session_id
            )
            if not session:
                return None

            messages = await conn.fetch(
                """
                SELECT * FROM agent_messages
                WHERE session_id = $1
                ORDER BY created_at ASC
                """,
                session_id
            )

            result = dict(session)
            result['messages'] = [dict(m) for m in messages]
            return result


async def cancel_active_sessions(older_than_hours: int = 24, status: str = "active") -> int:
    """
    Cancel sessions that have been active for too long.

    Args:
        older_than_hours: Cancel sessions older than this
        status: Status to filter by (default: active)

    Returns:
        Number of sessions cancelled
    """
    async with get_db() as conn:
        result = await conn.execute(
            """
            UPDATE agent_sessions
            SET status = 'stopped',
                end_time = NOW(),
                updated_at = NOW(),
                metadata = COALESCE(metadata, '{}'::jsonb) ||
                    jsonb_build_object('cancelled_reason', 'timeout', 'cancelled_at', NOW())
            WHERE status = $1
              AND created_at < NOW() - INTERVAL '1 hour' * $2
            """,
            status, older_than_hours
        )
        # Extract count from "UPDATE X" response
        return int(result.split()[-1]) if result else 0
