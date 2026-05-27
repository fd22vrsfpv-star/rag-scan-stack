"""
Circular log handler for kali-listener service.
Maintains recent log entries for web UI display.
"""

import logging
from collections import deque
from threading import Lock
from datetime import datetime
from typing import List, Dict, Any

class CircularLogHandler(logging.Handler):
    """Handler that stores logs in a circular buffer for API access."""

    def __init__(self, max_entries: int = 1000):
        super().__init__()
        self.max_entries = max_entries
        self.logs: deque = deque(maxlen=max_entries)
        self._lock = Lock()
        self.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(name)s: %(message)s'))

    def emit(self, record: logging.LogRecord) -> None:
        try:
            entry = {
                "timestamp": datetime.fromtimestamp(record.created).isoformat(),
                "level": record.levelname,
                "logger": record.name,
                "message": self.format(record),
            }
            with self._lock:
                self.logs.append(entry)
        except Exception:
            self.handleError(record)

    def get_logs(self, limit: int = 100, level: str = None) -> List[Dict[str, Any]]:
        """Get recent logs, optionally filtered by level."""
        with self._lock:
            logs = list(self.logs)

        if level:
            level_upper = level.upper()
            logs = [l for l in logs if l["level"] == level_upper]

        return logs[-limit:]

    def clear(self) -> int:
        """Clear all logs and return count cleared."""
        with self._lock:
            count = len(self.logs)
            self.logs.clear()
        return count


# Singleton instance
_handler: CircularLogHandler = None
_lock = Lock()

def get_log_handler() -> CircularLogHandler:
    """Get or create the singleton log handler."""
    global _handler
    with _lock:
        if _handler is None:
            _handler = CircularLogHandler(max_entries=1000)
        return _handler

def setup_logging(name: str = "kali-listener") -> logging.Logger:
    """Setup logging with circular handler for a logger."""
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)

    handler = get_log_handler()
    if handler not in logger.handlers:
        logger.addHandler(handler)

    # Also add console handler
    console = logging.StreamHandler()
    console.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(name)s: %(message)s'))
    if not any(isinstance(h, logging.StreamHandler) for h in logger.handlers):
        logger.addHandler(console)

    return logger
