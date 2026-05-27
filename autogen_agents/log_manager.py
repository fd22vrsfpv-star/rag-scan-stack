"""
Log Manager for Diagnostic Web Interface
Captures logs from scan_tools and provides query interface

Supports both sync (threading.Lock) and async (asyncio.Lock) access patterns
for use in FastAPI async endpoints.
"""

import logging
import sys
import asyncio
from collections import deque
from typing import List, Dict, Optional
from datetime import datetime
import threading
import json


class LogRecord:
    """Structured log record"""
    def __init__(self, record: logging.LogRecord):
        self.timestamp = datetime.fromtimestamp(record.created).isoformat()
        self.level = record.levelname
        self.logger = record.name
        self.message = record.getMessage()
        self.module = record.module
        self.function = record.funcName
        self.line = record.lineno

        # Extract request_id from message if present
        self.request_id = None
        if '[' in self.message and ']' in self.message:
            start = self.message.find('[')
            end = self.message.find(']', start)
            if end > start:
                self.request_id = self.message[start+1:end]

    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            "timestamp": self.timestamp,
            "level": self.level,
            "logger": self.logger,
            "message": self.message,
            "module": self.module,
            "function": self.function,
            "line": self.line,
            "request_id": self.request_id
        }


class CircularLogHandler(logging.Handler):
    """
    Custom log handler that stores logs in a circular buffer
    Thread-safe with maximum size limit
    """

    def __init__(self, max_size: int = 1000):
        """
        Initialize circular log handler

        Args:
            max_size: Maximum number of log records to keep
        """
        super().__init__()
        self.max_size = max_size
        self.records = deque(maxlen=max_size)
        self._sync_lock = threading.Lock()  # For sync emit() from logging
        self._async_lock: Optional[asyncio.Lock] = None  # Lazy init for async methods

        # Statistics
        self.stats = {
            "total_received": 0,
            "by_level": {
                "DEBUG": 0,
                "INFO": 0,
                "WARNING": 0,
                "ERROR": 0,
                "CRITICAL": 0
            },
            "started_at": datetime.now().isoformat()
        }

    def _get_async_lock(self) -> asyncio.Lock:
        """Get or create the asyncio lock (lazy initialization)"""
        if self._async_lock is None:
            self._async_lock = asyncio.Lock()
        return self._async_lock

    def emit(self, record: logging.LogRecord):
        """Emit a log record to the circular buffer (sync, called by logging)"""
        try:
            with self._sync_lock:
                log_record = LogRecord(record)
                self.records.append(log_record)

                # Update stats
                self.stats["total_received"] += 1
                if record.levelname in self.stats["by_level"]:
                    self.stats["by_level"][record.levelname] += 1

        except Exception:
            # Don't let logging errors break the application
            self.handleError(record)

    def get_logs(
        self,
        level: Optional[str] = None,
        limit: int = 100,
        search: Optional[str] = None,
        request_id: Optional[str] = None
    ) -> List[Dict]:
        """
        Get logs from buffer with filtering (sync version)

        Args:
            level: Filter by log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
            limit: Maximum number of records to return
            search: Search term in message
            request_id: Filter by request ID

        Returns:
            List of log record dictionaries
        """
        with self._sync_lock:
            # Convert deque to list for filtering
            logs = list(self.records)

            # Filter by level
            if level:
                level_upper = level.upper()
                logs = [log for log in logs if log.level == level_upper]

            # Filter by request_id
            if request_id:
                logs = [log for log in logs if log.request_id and request_id in log.request_id]

            # Filter by search term
            if search:
                search_lower = search.lower()
                logs = [log for log in logs if search_lower in log.message.lower()]

            # Get most recent logs (last N)
            logs = logs[-limit:]

            # Convert to dictionaries
            return [log.to_dict() for log in logs]

    def get_stats(self) -> Dict:
        """Get logging statistics (sync version)"""
        with self._sync_lock:
            return {
                **self.stats,
                "current_buffer_size": len(self.records),
                "max_buffer_size": self.max_size
            }

    def clear(self):
        """Clear all logs from buffer (sync version)"""
        with self._sync_lock:
            self.records.clear()
            self.stats["total_received"] = 0
            for level in self.stats["by_level"]:
                self.stats["by_level"][level] = 0

    def export_json(self) -> str:
        """Export all logs as JSON string (sync version)"""
        with self._sync_lock:
            logs = [log.to_dict() for log in self.records]
            return json.dumps({
                "logs": logs,
                "stats": self.get_stats(),
                "exported_at": datetime.now().isoformat()
            }, indent=2)

    # ===============================
    # Async Methods (for FastAPI async endpoints)
    # ===============================

    def _filter_logs(
        self,
        logs: List['LogRecord'],
        level: Optional[str] = None,
        search: Optional[str] = None,
        request_id: Optional[str] = None,
        limit: int = 100
    ) -> List[Dict]:
        """Internal method to filter logs (shared by sync and async)"""
        # Filter by level
        if level:
            level_upper = level.upper()
            logs = [log for log in logs if log.level == level_upper]

        # Filter by request_id
        if request_id:
            logs = [log for log in logs if log.request_id and request_id in log.request_id]

        # Filter by search term
        if search:
            search_lower = search.lower()
            logs = [log for log in logs if search_lower in log.message.lower()]

        # Get most recent logs (last N)
        logs = logs[-limit:]

        # Convert to dictionaries
        return [log.to_dict() for log in logs]

    async def async_get_logs(
        self,
        level: Optional[str] = None,
        limit: int = 100,
        search: Optional[str] = None,
        request_id: Optional[str] = None
    ) -> List[Dict]:
        """
        Get logs from buffer with filtering (async version)

        Args:
            level: Filter by log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
            limit: Maximum number of records to return
            search: Search term in message
            request_id: Filter by request ID

        Returns:
            List of log record dictionaries
        """
        async with self._get_async_lock():
            # Make a copy of the records to release lock quickly
            logs = list(self.records)

        # Filter outside of lock
        return self._filter_logs(logs, level, search, request_id, limit)

    async def async_get_stats(self) -> Dict:
        """Get logging statistics (async version)"""
        async with self._get_async_lock():
            return {
                **self.stats,
                "current_buffer_size": len(self.records),
                "max_buffer_size": self.max_size
            }

    async def async_clear(self):
        """Clear all logs from buffer (async version)"""
        async with self._get_async_lock():
            self.records.clear()
            self.stats["total_received"] = 0
            for level in self.stats["by_level"]:
                self.stats["by_level"][level] = 0

    async def async_export_json(self) -> str:
        """Export all logs as JSON string (async version)"""
        async with self._get_async_lock():
            logs = [log.to_dict() for log in self.records]
            stats = {
                **self.stats,
                "current_buffer_size": len(self.records),
                "max_buffer_size": self.max_size
            }

        return json.dumps({
            "logs": logs,
            "stats": stats,
            "exported_at": datetime.now().isoformat()
        }, indent=2)


# Global log handler instance
_log_handler = CircularLogHandler(max_size=1000)


def get_log_handler() -> CircularLogHandler:
    """Get the global log handler instance"""
    return _log_handler


def setup_log_capture(use_http_fallback: bool = False, silent: bool = False):
    """
    Setup log capture for scan_tools logger
    Call this once during application startup

    Args:
        use_http_fallback: If True and running in separate process (MCP), send logs via HTTP
                          to the main FastAPI server instead of using in-memory buffer
        silent: If True, suppress initialization messages (useful for MCP stdio mode)
    """
    # Get the scan_tools logger
    scan_logger = logging.getLogger("scan_tools")

    # Check if we're in a separate process (MCP mode via docker exec)
    # by checking if port 8015 is already bound (main FastAPI server)
    in_separate_process = False
    if use_http_fallback:
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.bind(("0.0.0.0", 8015))
            sock.close()
        except OSError:
            # Port already in use - we're in a separate process
            in_separate_process = True
            sock.close()

    if in_separate_process:
        # Running in separate process (MCP) - logs to main server won't work
        # Setup stderr handler so logs appear in docker logs
        stderr_handler = logging.StreamHandler(sys.stderr)
        stderr_handler.setFormatter(logging.Formatter(
            '%(asctime)s [%(levelname)s] %(name)s: %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        ))

        scan_logger.addHandler(stderr_handler)
        scan_logger.setLevel(logging.INFO)

        session_logger = logging.getLogger("pentest_sessions")
        session_logger.addHandler(stderr_handler)
        session_logger.setLevel(logging.INFO)

        if not silent:
            print("Log capture: Running in separate process, logs visible via docker logs", file=sys.stderr)
    else:
        # Running in main FastAPI process - use in-memory circular buffer
        # Only add handler if not already present
        if _log_handler not in scan_logger.handlers:
            scan_logger.addHandler(_log_handler)
            scan_logger.setLevel(logging.INFO)

        # Also capture pentest_sessions logger
        session_logger = logging.getLogger("pentest_sessions")
        if _log_handler not in session_logger.handlers:
            session_logger.addHandler(_log_handler)
            session_logger.setLevel(logging.INFO)

        # NOTE: Do NOT add to root logger - this causes deadlock with uvicorn access logs
        # uvicorn logs requests, and if the request handler tries to access the log buffer
        # while uvicorn is logging, both will wait for the same lock

        if not silent:
            print(f"Log capture initialized: max {_log_handler.max_size} records", file=sys.stderr)
