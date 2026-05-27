"""
Structured Logging Module for RAG Scan Stack

This module provides consistent JSON-formatted logging across all services.
Logs are compatible with Loki/ELK and include structured data for easy querying.

Usage:
    from common.structured_logger import get_logger

    logger = get_logger(__name__)

    logger.info("Scan started", scan_id="scan-123", target="192.168.1.1")
    logger.error("Scan failed", scan_id="scan-123", error="timeout")

Output Format:
    {
        "timestamp": "2025-11-19T10:00:00.123Z",
        "level": "INFO",
        "logger": "rag_api.scanner",
        "message": "Scan started",
        "scan_id": "scan-123",
        "target": "192.168.1.1",
        "service": "rag-api",
        "hostname": "rag-api-container"
    }

Author: RAG Scan Stack Operations Team
Version: 1.0
Last Updated: 2025-11-19
"""

import json
import logging
import sys
import os
import socket
import traceback
from datetime import datetime
from typing import Any, Dict, Optional
from contextvars import ContextVar

# Context variable for request ID (thread-safe)
request_id_var: ContextVar[Optional[str]] = ContextVar('request_id', default=None)

# Service name from environment or hostname
SERVICE_NAME = os.getenv('SERVICE_NAME', socket.gethostname())


class StructuredFormatter(logging.Formatter):
    """
    Custom formatter that outputs JSON-structured logs.

    Features:
    - Consistent timestamp format (ISO 8601 UTC)
    - Structured fields for easy parsing
    - Exception stack traces in separate field
    - Request ID correlation
    - Extra fields from logger.info(..., extra={...})
    """

    def __init__(self):
        super().__init__()

    def format(self, record: logging.LogRecord) -> str:
        """
        Format log record as JSON.

        Args:
            record: The log record to format

        Returns:
            JSON string representing the log entry
        """
        # Base log structure
        log_data: Dict[str, Any] = {
            'timestamp': self.format_timestamp(record.created),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'service': SERVICE_NAME,
            'hostname': socket.gethostname(),
            'process_id': record.process,
            'thread_id': record.thread,
            'filename': record.filename,
            'function': record.funcName,
            'line_number': record.lineno,
        }

        # Add request ID if available
        request_id = request_id_var.get()
        if request_id:
            log_data['request_id'] = request_id

        # Add extra fields from record
        if hasattr(record, 'extra_fields'):
            log_data.update(record.extra_fields)

        # Add exception information if present
        if record.exc_info:
            log_data['exception'] = {
                'type': record.exc_info[0].__name__ if record.exc_info[0] else None,
                'message': str(record.exc_info[1]) if record.exc_info[1] else None,
                'stacktrace': self.format_exception(record.exc_info)
            }

        # Add stack info if available
        if record.stack_info:
            log_data['stack_info'] = record.stack_info

        return json.dumps(log_data, default=str)

    def format_timestamp(self, created: float) -> str:
        """
        Format timestamp as ISO 8601 UTC.

        Args:
            created: Unix timestamp from log record

        Returns:
            ISO 8601 formatted timestamp with milliseconds
        """
        dt = datetime.utcfromtimestamp(created)
        return dt.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'

    def format_exception(self, exc_info) -> str:
        """
        Format exception information as string.

        Args:
            exc_info: Exception info tuple from sys.exc_info()

        Returns:
            Formatted exception traceback
        """
        return ''.join(traceback.format_exception(*exc_info))


class StructuredLogger:
    """
    Wrapper around Python's logging.Logger with structured logging support.

    Provides convenience methods for logging with structured data.
    """

    def __init__(self, logger: logging.Logger):
        """
        Initialize structured logger.

        Args:
            logger: The underlying Python logger
        """
        self.logger = logger

    def _log(self, level: int, message: str, **kwargs):
        """
        Internal logging method with structured data support.

        Args:
            level: Log level (logging.INFO, etc.)
            message: Log message
            **kwargs: Additional structured fields
        """
        extra = {'extra_fields': kwargs}
        self.logger.log(level, message, extra=extra)

    def debug(self, message: str, **kwargs):
        """Log debug message with structured data."""
        self._log(logging.DEBUG, message, **kwargs)

    def info(self, message: str, **kwargs):
        """Log info message with structured data."""
        self._log(logging.INFO, message, **kwargs)

    def warning(self, message: str, **kwargs):
        """Log warning message with structured data."""
        self._log(logging.WARNING, message, **kwargs)

    def error(self, message: str, **kwargs):
        """Log error message with structured data."""
        self._log(logging.ERROR, message, **kwargs)

    def critical(self, message: str, **kwargs):
        """Log critical message with structured data."""
        self._log(logging.CRITICAL, message, **kwargs)

    def exception(self, message: str, **kwargs):
        """Log exception with structured data and stack trace."""
        kwargs['exc_info'] = True
        self._log(logging.ERROR, message, **kwargs)


def get_logger(name: str, level: str = None) -> StructuredLogger:
    """
    Get a structured logger instance.

    Args:
        name: Logger name (typically __name__)
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
               Defaults to environment variable LOG_LEVEL or INFO

    Returns:
        StructuredLogger instance

    Example:
        logger = get_logger(__name__)
        logger.info("User logged in", user_id="123", ip="192.168.1.1")
    """
    # Determine log level
    if level is None:
        level = os.getenv('LOG_LEVEL', 'INFO').upper()

    # Get or create logger
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level))

    # Remove existing handlers to avoid duplicates
    logger.handlers = []

    # Create console handler with structured formatter
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(StructuredFormatter())
    logger.addHandler(handler)

    # Prevent propagation to root logger
    logger.propagate = False

    return StructuredLogger(logger)


def set_request_id(request_id: str):
    """
    Set request ID for current context (thread-safe).

    This allows all logs within a request to be correlated.

    Args:
        request_id: Unique request identifier

    Example:
        set_request_id("req-abc-123")
        logger.info("Processing request")  # Will include request_id
    """
    request_id_var.set(request_id)


def clear_request_id():
    """
    Clear request ID from current context.

    Call this at the end of request processing.
    """
    request_id_var.set(None)


def get_request_id() -> Optional[str]:
    """
    Get current request ID from context.

    Returns:
        Request ID if set, None otherwise
    """
    return request_id_var.get()


# Example usage and testing
if __name__ == "__main__":
    # Example 1: Basic logging
    logger = get_logger("test.module")

    logger.info("Application started", version="1.0", environment="development")
    logger.debug("Debug information", variable="value", count=42)
    logger.warning("Warning message", threshold=100, current=95)
    logger.error("Error occurred", error_code="E001", user_input="invalid")

    # Example 2: Request ID correlation
    set_request_id("req-12345")
    logger.info("Request received", endpoint="/api/scan", method="POST")
    logger.info("Processing request", scan_id="scan-789")
    logger.info("Request completed", duration_ms=123, status_code=200)
    clear_request_id()

    # Example 3: Exception logging
    try:
        result = 1 / 0
    except Exception as e:
        logger.exception("Division error occurred", dividend=1, divisor=0)

    # Example 4: Structured data
    logger.info(
        "Scan completed successfully",
        scan_id="scan-123",
        target="192.168.1.1",
        ports_scanned=1000,
        vulnerabilities_found=5,
        duration_seconds=42.5,
        scan_type="nmap"
    )

    # Example 5: Different log levels
    logger.debug("Detailed debug information")
    logger.info("Normal operational message")
    logger.warning("Something might be wrong")
    logger.error("An error occurred")
    logger.critical("System is in critical state")

    print("\n" + "="*80)
    print("Structured logging examples complete!")
    print("="*80)
    print("\nAll logs above are JSON-formatted and ready for Loki/ELK ingestion.")
    print("Query examples:")
    print('  - {service="test-service"} |= "error"')
    print('  - {service="test-service"} | json | scan_id="scan-123"')
    print('  - {level="ERROR"} | json | duration_seconds > 30')
