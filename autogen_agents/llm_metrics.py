"""
LLM Request Metrics Instrumentation

Captures per-request LLM metrics for agent sessions:
- Wall-clock latency
- Token counts (prompt, completion, total)
- Tool call detection
- Agent name extraction
- Model name extraction

Metrics are buffered in memory and flushed to PostgreSQL periodically.
Uses thread-local storage for session context (same pattern as SessionScanTracker).
"""

import time
import threading
import logging
from typing import Optional, Dict, Any, List
from contextlib import contextmanager

logger = logging.getLogger("llm_metrics")



class LLMMetricsContext:
    """Thread-safe context and buffer for LLM request metrics."""

    _local = threading.local()
    _buffer: List[Dict[str, Any]] = []
    _buffer_lock = threading.Lock()
    _flush_threshold = 10

    @classmethod
    def set_session(cls, session_id: str):
        cls._local.session_id = session_id
        logger.info(f"[LLMMetrics] Session context set: {session_id}")

    @classmethod
    def clear_session(cls):
        session_id = getattr(cls._local, 'session_id', None)
        if session_id:
            logger.info(f"[LLMMetrics] Session context cleared: {session_id}")
        cls._local.session_id = None

    @classmethod
    def get_current_session(cls) -> Optional[str]:
        return getattr(cls._local, 'session_id', None)

    @classmethod
    def record_request(cls, metric: Dict[str, Any]):
        with cls._buffer_lock:
            cls._buffer.append(metric)
            if len(cls._buffer) >= cls._flush_threshold:
                cls._flush_buffer_locked()

    @classmethod
    def flush_buffer(cls):
        with cls._buffer_lock:
            cls._flush_buffer_locked()

    @classmethod
    def _flush_buffer_locked(cls):
        """Flush buffered metrics to DB. Caller must hold _buffer_lock."""
        if not cls._buffer:
            return

        rows = list(cls._buffer)
        cls._buffer.clear()

        try:
            from db_utils import get_db
            with get_db() as conn:
                with conn.cursor() as cur:
                    for row in rows:
                        cur.execute("""
                            INSERT INTO llm_request_metrics
                                (session_id, agent_name, model_name,
                                 prompt_tokens, completion_tokens, total_tokens,
                                 latency_ms, has_tool_calls, tool_call_count,
                                 tool_names, is_error, error_message, request_params)
                            VALUES
                                (%(session_id)s::uuid, %(agent_name)s, %(model_name)s,
                                 %(prompt_tokens)s, %(completion_tokens)s, %(total_tokens)s,
                                 %(latency_ms)s, %(has_tool_calls)s, %(tool_call_count)s,
                                 %(tool_names)s, %(is_error)s, %(error_message)s,
                                 %(request_params)s::jsonb)
                        """, row)
                conn.commit()
            logger.debug(f"[LLMMetrics] Flushed {len(rows)} metrics to DB")
        except Exception as e:
            logger.error(f"[LLMMetrics] Failed to flush metrics: {e}")


# ===============================
# AutoGen monkeypatch — REMOVED
# ===============================
# `_patched_create()` and `install_llm_metrics_patch()` lived here. They wrapped
# `autogen.oai.client.OpenAIWrapper.create` to capture per-request latency,
# tokens and tool calls. AutoGen is retired
# (Docs/LANGGRAPH_MIGRATION_PLAN.md, Phase 5), and a LangChain client never goes
# through that wrapper — which is exactly why flipping the engine default would
# have silently emptied the LLM cost/latency dashboards.
#
# The replacement is `langgraph_engine.metrics_callback()`, a LangChain callback
# handler that writes the SAME `llm_request_metrics` row shape through
# `LLMMetricsContext.record_request` above. Keep the two row shapes identical:
# the table, its indexes and every dashboard query are unchanged.


@contextmanager
def llm_metrics_session(session_id: str):
    """Context manager that sets/clears LLM metrics session context."""
    LLMMetricsContext.set_session(session_id)
    try:
        yield
    finally:
        LLMMetricsContext.flush_buffer()
        LLMMetricsContext.clear_session()
