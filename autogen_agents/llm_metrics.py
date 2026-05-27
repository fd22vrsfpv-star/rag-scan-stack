"""
LLM Request Metrics Instrumentation

Monkey-patches autogen's OpenAIWrapper.create() to capture per-request metrics:
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

_patch_applied = False
_original_create = None


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


def _patched_create(self, *args, **kwargs):
    """Wrapper around OpenAIWrapper.create() that captures metrics."""
    session_id = LLMMetricsContext.get_current_session()
    if not session_id:
        return _original_create(self, *args, **kwargs)

    # Extract model name
    model_name = "unknown"
    try:
        if hasattr(self, '_config_list') and self._config_list:
            model_name = self._config_list[0].get("model", "unknown")
    except Exception:
        pass

    # Extract agent name from messages
    agent_name = None
    messages = kwargs.get("messages") or (args[1] if len(args) > 1 else None)
    if messages:
        try:
            for msg in reversed(messages):
                if isinstance(msg, dict) and msg.get("name"):
                    agent_name = msg["name"]
                    break
        except Exception:
            pass

    start_time = time.time()
    is_error = False
    error_message = None
    response = None

    try:
        response = _original_create(self, *args, **kwargs)
        return response
    except Exception as e:
        is_error = True
        error_message = f"{type(e).__name__}: {str(e)[:500]}"
        raise
    finally:
        latency_ms = (time.time() - start_time) * 1000

        # Extract token counts
        prompt_tokens = None
        completion_tokens = None
        total_tokens = None
        has_tool_calls = False
        tool_call_count = 0
        tool_names = []

        if response is not None:
            try:
                usage = getattr(response, 'usage', None)
                if usage is None and hasattr(response, 'model_extra'):
                    usage = response.model_extra.get('usage')
                if usage:
                    prompt_tokens = getattr(usage, 'prompt_tokens', None) or (usage.get('prompt_tokens') if isinstance(usage, dict) else None)
                    completion_tokens = getattr(usage, 'completion_tokens', None) or (usage.get('completion_tokens') if isinstance(usage, dict) else None)
                    total_tokens = getattr(usage, 'total_tokens', None) or (usage.get('total_tokens') if isinstance(usage, dict) else None)
            except Exception:
                pass

            try:
                choices = getattr(response, 'choices', None)
                if choices and len(choices) > 0:
                    message = getattr(choices[0], 'message', None)
                    if message:
                        tc = getattr(message, 'tool_calls', None)
                        if tc:
                            has_tool_calls = True
                            tool_call_count = len(tc)
                            for call in tc:
                                fn = getattr(call, 'function', None)
                                if fn:
                                    name = getattr(fn, 'name', None)
                                    if name:
                                        tool_names.append(name)
            except Exception:
                pass

        import json
        metric = {
            "session_id": session_id,
            "agent_name": agent_name,
            "model_name": model_name,
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": total_tokens,
            "latency_ms": round(latency_ms, 2),
            "has_tool_calls": has_tool_calls,
            "tool_call_count": tool_call_count,
            "tool_names": tool_names if tool_names else None,
            "is_error": is_error,
            "error_message": error_message,
            "request_params": json.dumps({"model": model_name}),
        }

        try:
            LLMMetricsContext.record_request(metric)
        except Exception as rec_err:
            logger.error(f"[LLMMetrics] Failed to record metric: {rec_err}")


def install_llm_metrics_patch():
    """Install the monkey-patch on OpenAIWrapper.create(). Idempotent."""
    global _patch_applied, _original_create

    if _patch_applied:
        logger.info("[LLMMetrics] Patch already installed, skipping")
        return

    try:
        from autogen.oai.client import OpenAIWrapper
    except ImportError:
        logger.warning("[LLMMetrics] autogen.oai.client not available, skipping patch")
        return

    _original_create = OpenAIWrapper.create
    OpenAIWrapper.create = _patched_create
    _patch_applied = True
    logger.info("LLM metrics instrumentation installed successfully")


@contextmanager
def llm_metrics_session(session_id: str):
    """Context manager that sets/clears LLM metrics session context."""
    LLMMetricsContext.set_session(session_id)
    try:
        yield
    finally:
        LLMMetricsContext.flush_buffer()
        LLMMetricsContext.clear_session()
