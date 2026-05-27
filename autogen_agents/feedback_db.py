"""
Feedback CRUD for GRPO training pipeline.
Stores (prompt, response, human_rating) tuples for model fine-tuning.
"""

import json
import os
import uuid
from contextlib import contextmanager
from typing import Optional, Dict, List

import psycopg2
from psycopg2.extras import RealDictCursor, Json, register_uuid

from db_utils import get_db_dsn, get_db

register_uuid()

# Agent name → task_type mapping
AGENT_TASK_TYPE_MAP = {
    "Analyzer": "scan_analysis",
    "Scanner": "scan_analysis",
    "Reconnaissance": "scan_analysis",
    "Exploit": "exploit_recommendation",
    "Coordinator": "agent_decision",
    "Reporter": "scan_analysis",
}


def create_feedback(
    task_type: str,
    user_prompt: str,
    model_response: str,
    system_prompt: Optional[str] = None,
    context: Optional[Dict] = None,
    session_id: Optional[uuid.UUID] = None,
    agent_message_id: Optional[uuid.UUID] = None,
) -> uuid.UUID:
    """
    Create a new feedback entry (unrated).

    Args:
        task_type: scan_analysis, exploit_recommendation, or agent_decision
        user_prompt: The prompt given to the model
        model_response: The model's response
        system_prompt: System prompt used
        context: Additional context (jsonb)
        session_id: FK to agent_sessions
        agent_message_id: FK to agent_messages

    Returns:
        Feedback entry UUID
    """
    with get_db() as conn, conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO grpo_feedback
            (task_type, user_prompt, model_response, system_prompt, context,
             session_id, agent_message_id)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            RETURNING id
            """,
            (task_type, user_prompt, model_response, system_prompt,
             Json(context or {}), session_id, agent_message_id)
        )
        feedback_id = cur.fetchone()[0]
        conn.commit()
        return feedback_id


def update_feedback_rating(
    feedback_id: uuid.UUID,
    rating: int,
    rating_dimensions: Optional[Dict] = None,
    reviewer_id: Optional[str] = None,
    notes: Optional[str] = None,
) -> bool:
    """
    Add or update a human rating on a feedback entry.

    Args:
        feedback_id: Feedback UUID
        rating: 1-5 scale
        rating_dimensions: {accuracy, completeness, actionability} each 1-5
        reviewer_id: Identifier for the human reviewer
        notes: Optional review notes

    Returns:
        True if updated, False if not found
    """
    with get_db() as conn, conn.cursor() as cur:
        cur.execute(
            """
            UPDATE grpo_feedback
            SET rating = %s,
                rating_dimensions = %s,
                reviewer_id = %s,
                review_notes = %s
            WHERE id = %s
            RETURNING id
            """,
            (rating, Json(rating_dimensions or {}), reviewer_id, notes, feedback_id)
        )
        result = cur.fetchone()
        conn.commit()
        return result is not None


def get_feedback(feedback_id: uuid.UUID) -> Optional[Dict]:
    """Get a single feedback entry by ID."""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            "SELECT * FROM grpo_feedback WHERE id = %s",
            (feedback_id,)
        )
        return cur.fetchone()


def list_feedback(
    task_type: Optional[str] = None,
    rated: Optional[bool] = None,
    session_id: Optional[uuid.UUID] = None,
    limit: int = 50,
    offset: int = 0,
) -> List[Dict]:
    """
    List feedback entries with optional filtering.

    Args:
        task_type: Filter by task type
        rated: True for rated only, False for unrated only, None for all
        session_id: Filter by session
        limit: Max results
        offset: Pagination offset

    Returns:
        List of feedback dictionaries
    """
    conditions = []
    params = []

    if task_type:
        conditions.append("task_type = %s")
        params.append(task_type)

    if rated is True:
        conditions.append("rating IS NOT NULL")
    elif rated is False:
        conditions.append("rating IS NULL")

    if session_id:
        conditions.append("session_id = %s")
        params.append(session_id)

    where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""

    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            f"""
            SELECT * FROM grpo_feedback
            {where_clause}
            ORDER BY created_at DESC
            LIMIT %s OFFSET %s
            """,
            params + [limit, offset]
        )
        return cur.fetchall()


def get_feedback_stats() -> Dict:
    """Get aggregate feedback statistics."""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("""
            SELECT
                task_type,
                COUNT(*) as total,
                COUNT(rating) as rated,
                COUNT(*) - COUNT(rating) as unrated,
                ROUND(AVG(rating), 2) as avg_rating,
                COUNT(CASE WHEN used_in_training THEN 1 END) as used_in_training
            FROM grpo_feedback
            GROUP BY task_type
            ORDER BY task_type
        """)
        by_task = cur.fetchall()

        cur.execute("""
            SELECT
                rating, COUNT(*) as count
            FROM grpo_feedback
            WHERE rating IS NOT NULL
            GROUP BY rating
            ORDER BY rating
        """)
        distribution = cur.fetchall()

        return {
            "by_task_type": by_task,
            "rating_distribution": distribution,
            "total": sum(row["total"] for row in by_task) if by_task else 0,
            "total_rated": sum(row["rated"] for row in by_task) if by_task else 0,
        }


def export_training_dataset(
    task_types: Optional[List[str]] = None,
    min_rating: int = 1,
    dataset_version: Optional[str] = None,
) -> List[Dict]:
    """
    Export rated feedback as training dataset (JSONL-ready dicts).

    Args:
        task_types: Filter by task types (None = all)
        min_rating: Minimum rating to include
        dataset_version: Tag exported rows with this version

    Returns:
        List of dicts suitable for JSONL export
    """
    conditions = ["rating IS NOT NULL", "rating >= %s"]
    params = [min_rating]

    if task_types:
        conditions.append("task_type = ANY(%s)")
        params.append(task_types)

    where_clause = f"WHERE {' AND '.join(conditions)}"

    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            f"""
            SELECT id, task_type, user_prompt, model_response, system_prompt,
                   context, rating, rating_dimensions
            FROM grpo_feedback
            {where_clause}
            ORDER BY created_at ASC
            """,
            params
        )
        rows = cur.fetchall()

        # Mark as exported with dataset_version
        if dataset_version and rows:
            ids = [row["id"] for row in rows]
            cur.execute(
                """
                UPDATE grpo_feedback
                SET dataset_version = %s
                WHERE id = ANY(%s)
                """,
                (dataset_version, ids)
            )
            conn.commit()

        # Format for training
        dataset = []
        for row in rows:
            entry = {
                "id": str(row["id"]),
                "task_type": row["task_type"],
                "prompt": row["user_prompt"],
                "response": row["model_response"],
                "rating": row["rating"],
                "rating_dimensions": row["rating_dimensions"],
            }
            if row["system_prompt"]:
                entry["system_prompt"] = row["system_prompt"]
            if row["context"]:
                entry["context"] = row["context"]
            dataset.append(entry)

        return dataset


def capture_session_outputs(session_id: uuid.UUID) -> List[uuid.UUID]:
    """
    Auto-capture agent outputs from a completed session as unrated feedback entries.

    Iterates agent_messages for the session, classifies by agent name → task_type,
    and creates unrated feedback entries. The prompt is constructed from the
    conversation context preceding each agent message.

    Args:
        session_id: Agent session UUID

    Returns:
        List of created feedback UUIDs
    """
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        # Get all messages for this session ordered chronologically
        cur.execute(
            """
            SELECT id, agent_name, role, content, created_at
            FROM agent_messages
            WHERE session_id = %s
            ORDER BY created_at ASC
            """,
            (session_id,)
        )
        messages = cur.fetchall()

    created_ids = []
    context_window = []

    for msg in messages:
        agent_name = msg["agent_name"]
        content = msg["content"] or ""

        # Only capture messages from agents we care about
        task_type = AGENT_TASK_TYPE_MAP.get(agent_name)
        if task_type and msg["role"] in ("assistant", "user") and msg["agent_name"] != "System" and len(content.strip()) > 50:
            # Build prompt from recent context (last 3 non-empty messages before this one)
            recent_context = [
                m for m in context_window[-5:]
                if m.get("content") and len(m["content"].strip()) > 10
            ]
            prompt_parts = []
            for ctx_msg in recent_context[-3:]:
                prompt_parts.append(f"[{ctx_msg['agent_name']}]: {ctx_msg['content'][:500]}")

            user_prompt = "\n\n".join(prompt_parts) if prompt_parts else "(session start)"

            feedback_id = create_feedback(
                task_type=task_type,
                user_prompt=user_prompt,
                model_response=content,
                context={"agent_name": agent_name, "auto_captured": True},
                session_id=session_id,
                agent_message_id=msg["id"],
            )
            created_ids.append(feedback_id)

        context_window.append(msg)

    return created_ids
