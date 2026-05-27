"""
Log Manager for Nmap Scanner Diagnostic Web Interface
Captures logs from masscan, nmap, and scan operations

Based on scan_recommender/log_manager.py
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

        # Extract job_id from message if present (format: [job_id])
        self.job_id = None
        if '[' in self.message and ']' in self.message:
            start = self.message.find('[')
            end = self.message.find(']', start)
            if end > start:
                potential_id = self.message[start+1:end]
                # Check if it looks like a UUID or tag
                if len(potential_id) >= 8:
                    self.job_id = potential_id

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
            "job_id": self.job_id
        }


class CircularLogHandler(logging.Handler):
    """
    Custom log handler that stores logs in a circular buffer
    Thread-safe with maximum size limit
    """

    def __init__(self, max_size: int = 2000):
        super().__init__()
        self.max_size = max_size
        self.records = deque(maxlen=max_size)
        self._sync_lock = threading.Lock()
        self._async_lock: Optional[asyncio.Lock] = None

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
        """Emit a log record to the circular buffer"""
        try:
            with self._sync_lock:
                log_record = LogRecord(record)
                self.records.append(log_record)

                # Update stats
                self.stats["total_received"] += 1
                if record.levelname in self.stats["by_level"]:
                    self.stats["by_level"][record.levelname] += 1

        except Exception:
            self.handleError(record)

    def get_logs(
        self,
        level: Optional[str] = None,
        limit: int = 100,
        search: Optional[str] = None,
        job_id: Optional[str] = None
    ) -> List[Dict]:
        """Get logs from buffer with filtering"""
        with self._sync_lock:
            logs = list(self.records)

            if level:
                level_upper = level.upper()
                logs = [log for log in logs if log.level == level_upper]

            if job_id:
                logs = [log for log in logs if log.job_id and job_id in log.job_id]

            if search:
                search_lower = search.lower()
                logs = [log for log in logs if search_lower in log.message.lower()]

            logs = logs[-limit:]
            return [log.to_dict() for log in logs]

    def get_stats(self) -> Dict:
        """Get logging statistics"""
        with self._sync_lock:
            return {
                **self.stats,
                "current_buffer_size": len(self.records),
                "max_buffer_size": self.max_size
            }

    def clear(self):
        """Clear all logs from buffer"""
        with self._sync_lock:
            self.records.clear()
            self.stats["total_received"] = 0
            for level in self.stats["by_level"]:
                self.stats["by_level"][level] = 0

    def export_json(self) -> str:
        """Export all logs as JSON string"""
        with self._sync_lock:
            logs = [log.to_dict() for log in self.records]
            return json.dumps({
                "logs": logs,
                "stats": self.get_stats(),
                "exported_at": datetime.now().isoformat()
            }, indent=2)

    async def async_get_logs(
        self,
        level: Optional[str] = None,
        limit: int = 100,
        search: Optional[str] = None,
        job_id: Optional[str] = None
    ) -> List[Dict]:
        """Get logs from buffer with filtering (async version)"""
        async with self._get_async_lock():
            logs = list(self.records)

        # Filter outside of lock
        if level:
            level_upper = level.upper()
            logs = [log for log in logs if log.level == level_upper]

        if job_id:
            logs = [log for log in logs if log.job_id and job_id in log.job_id]

        if search:
            search_lower = search.lower()
            logs = [log for log in logs if search_lower in log.message.lower()]

        logs = logs[-limit:]
        return [log.to_dict() for log in logs]

    async def async_get_stats(self) -> Dict:
        """Get logging statistics (async version)"""
        async with self._get_async_lock():
            return {
                **self.stats,
                "current_buffer_size": len(self.records),
                "max_buffer_size": self.max_size
            }

    async def async_export_json(self) -> str:
        """Export all logs as JSON string (async version)"""
        async with self._get_async_lock():
            logs = [log.to_dict() for log in self.records]
            return json.dumps({
                "logs": logs,
                "stats": self.get_stats(),
                "exported_at": datetime.now().isoformat()
            }, indent=2)


# Global log handler instance
_log_handler = CircularLogHandler(max_size=2000)


def get_log_handler() -> CircularLogHandler:
    """Get the global log handler instance"""
    return _log_handler


def setup_log_capture():
    """
    Setup log capture for nmap_scanner loggers
    Call this once during application startup
    """
    # Get loggers we want to capture
    loggers_to_capture = [
        "root",
        "nmap_scanner",
        "nmap_enrichment",
        "masscan",
        "nmap",
        "parse_nmap",  # ETL parser with raw data logging
        "parse_masscan",
    ]

    for logger_name in loggers_to_capture:
        logger = logging.getLogger(logger_name)
        if _log_handler not in logger.handlers:
            logger.addHandler(_log_handler)
            logger.setLevel(logging.INFO)

    # Also capture the root logger for INFO:root messages
    root_logger = logging.getLogger()
    if _log_handler not in root_logger.handlers:
        root_logger.addHandler(_log_handler)

    print(f"[nmap_scanner] Log capture initialized: max {_log_handler.max_size} records", file=sys.stderr)


# HTML template for logs UI
LOGS_UI_HTML = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Nmap Scanner Logs</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #1a1a1a;
            color: #e0e0e0;
            padding: 20px;
        }
        .container { max-width: 1400px; margin: 0 auto; }
        header {
            background: linear-gradient(135deg, #007bff 0%, #0056b3 100%);
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3);
        }
        h1 { color: white; font-size: 28px; margin-bottom: 10px; }
        .subtitle { color: rgba(255, 255, 255, 0.9); font-size: 14px; }
        .controls {
            background: #2a2a2a;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 20px;
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
        }
        .control-group { display: flex; flex-direction: column; }
        label {
            font-size: 12px;
            color: #aaa;
            margin-bottom: 5px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        input, select {
            background: #1a1a1a;
            border: 1px solid #444;
            color: #e0e0e0;
            padding: 10px;
            border-radius: 5px;
            font-size: 14px;
        }
        input:focus, select:focus { outline: none; border-color: #007bff; }
        button {
            background: #007bff;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 5px;
            cursor: pointer;
            font-size: 14px;
            font-weight: 600;
            transition: all 0.3s;
        }
        button:hover { background: #0056b3; transform: translateY(-1px); }
        button.secondary { background: #6c757d; }
        button.secondary:hover { background: #5a6268; }
        .stats {
            background: #2a2a2a;
            padding: 15px 20px;
            border-radius: 10px;
            margin-bottom: 20px;
            display: flex;
            gap: 30px;
            flex-wrap: wrap;
        }
        .stat-item { display: flex; flex-direction: column; }
        .stat-value { font-size: 24px; font-weight: bold; color: #007bff; }
        .stat-label { font-size: 12px; color: #888; text-transform: uppercase; }
        .logs-container {
            background: #2a2a2a;
            border-radius: 10px;
            padding: 20px;
            max-height: 600px;
            overflow-y: auto;
        }
        .log-entry {
            background: #1a1a1a;
            border-radius: 5px;
            padding: 12px;
            margin-bottom: 8px;
            border-left: 4px solid #6c757d;
        }
        .log-entry.DEBUG { border-left-color: #6c757d; }
        .log-entry.INFO { border-left-color: #007bff; }
        .log-entry.WARNING { border-left-color: #ffc107; }
        .log-entry.ERROR { border-left-color: #dc3545; }
        .log-entry.CRITICAL { border-left-color: #e83e8c; }
        .log-header { display: flex; align-items: center; gap: 10px; margin-bottom: 8px; flex-wrap: wrap; }
        .log-level {
            padding: 2px 8px;
            border-radius: 3px;
            font-size: 11px;
            font-weight: bold;
        }
        .log-level.DEBUG { background: #6c757d; color: white; }
        .log-level.INFO { background: #007bff; color: white; }
        .log-level.WARNING { background: #ffc107; color: black; }
        .log-level.ERROR { background: #dc3545; color: white; }
        .log-level.CRITICAL { background: #e83e8c; color: white; }
        .log-time { color: #888; font-size: 12px; }
        .log-job { background: #2d2d2d; padding: 2px 6px; border-radius: 3px; font-size: 11px; color: #17a2b8; }
        .log-message { font-family: monospace; font-size: 13px; word-break: break-word; }
        .log-meta { color: #666; font-size: 11px; margin-top: 6px; }
        .loading { text-align: center; padding: 40px; color: #888; }
        .auto-refresh { display: flex; align-items: center; gap: 10px; }
        .auto-refresh input[type="checkbox"] { width: 18px; height: 18px; }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Nmap Scanner Logs</h1>
            <p class="subtitle">Real-time logging for Masscan and Nmap scan operations</p>
        </header>

        <div class="stats" id="stats">
            <div class="stat-item">
                <span class="stat-value" id="total-logs">-</span>
                <span class="stat-label">Total Logs</span>
            </div>
            <div class="stat-item">
                <span class="stat-value" id="info-count">-</span>
                <span class="stat-label">Info</span>
            </div>
            <div class="stat-item">
                <span class="stat-value" id="warning-count">-</span>
                <span class="stat-label">Warnings</span>
            </div>
            <div class="stat-item">
                <span class="stat-value" id="error-count">-</span>
                <span class="stat-label">Errors</span>
            </div>
        </div>

        <div class="controls">
            <div class="control-group">
                <label>Log Level</label>
                <select id="level">
                    <option value="">All Levels</option>
                    <option value="DEBUG">DEBUG</option>
                    <option value="INFO">INFO</option>
                    <option value="WARNING">WARNING</option>
                    <option value="ERROR">ERROR</option>
                    <option value="CRITICAL">CRITICAL</option>
                </select>
            </div>
            <div class="control-group">
                <label>Search</label>
                <input type="text" id="search" placeholder="Search logs...">
            </div>
            <div class="control-group">
                <label>Job ID</label>
                <input type="text" id="job_id" placeholder="Filter by job ID...">
            </div>
            <div class="control-group">
                <label>Limit</label>
                <select id="limit">
                    <option value="50">50 logs</option>
                    <option value="100" selected>100 logs</option>
                    <option value="200">200 logs</option>
                    <option value="500">500 logs</option>
                </select>
            </div>
            <div class="control-group">
                <label>Actions</label>
                <div style="display: flex; gap: 10px;">
                    <button onclick="loadLogs()">Refresh</button>
                    <button class="secondary" onclick="exportLogs()">Export</button>
                </div>
            </div>
            <div class="control-group auto-refresh">
                <label>Auto Refresh</label>
                <input type="checkbox" id="auto-refresh" checked>
                <span style="font-size: 12px; color: #888;">Every 3s</span>
            </div>
        </div>

        <div class="logs-container" id="logs">
            <div class="loading">Loading logs...</div>
        </div>
    </div>

    <script>
        let autoRefreshInterval = null;

        async function loadStats() {
            try {
                const response = await fetch('/logs/stats');
                const data = await response.json();
                document.getElementById('total-logs').textContent = data.stats.total_received;
                document.getElementById('info-count').textContent = data.stats.by_level.INFO;
                document.getElementById('warning-count').textContent = data.stats.by_level.WARNING;
                document.getElementById('error-count').textContent = data.stats.by_level.ERROR;
            } catch (error) {
                console.error('Failed to load stats:', error);
            }
        }

        async function loadLogs() {
            const level = document.getElementById('level').value;
            const search = document.getElementById('search').value;
            const job_id = document.getElementById('job_id').value;
            const limit = document.getElementById('limit').value;

            const params = new URLSearchParams();
            if (level) params.append('level', level);
            if (search) params.append('search', search);
            if (job_id) params.append('job_id', job_id);
            params.append('limit', limit);

            try {
                const response = await fetch(`/logs?${params}`);
                const data = await response.json();

                const logsContainer = document.getElementById('logs');
                if (data.logs.length === 0) {
                    logsContainer.innerHTML = '<div class="loading">No logs found matching filters</div>';
                    return;
                }

                logsContainer.innerHTML = data.logs.map(log => `
                    <div class="log-entry ${log.level}">
                        <div class="log-header">
                            <span class="log-level ${log.level}">${log.level}</span>
                            <span class="log-time">${new Date(log.timestamp).toLocaleString()}</span>
                            ${log.job_id ? `<span class="log-job">${log.job_id}</span>` : ''}
                        </div>
                        <div class="log-message">${escapeHtml(log.message)}</div>
                        <div class="log-meta">
                            ${log.logger} | ${log.module}.${log.function}:${log.line}
                        </div>
                    </div>
                `).join('');

                logsContainer.scrollTop = logsContainer.scrollHeight;
                await loadStats();
            } catch (error) {
                document.getElementById('logs').innerHTML = `
                    <div class="loading" style="color: #dc3545;">
                        Failed to load logs: ${error.message}
                    </div>
                `;
            }
        }

        async function exportLogs() {
            try {
                const response = await fetch('/logs/export');
                const blob = await response.blob();
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `nmap_logs_${new Date().toISOString().replace(/[:.]/g, '-')}.json`;
                a.click();
            } catch (error) {
                alert('Failed to export logs: ' + error.message);
            }
        }

        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }

        function setupAutoRefresh() {
            const checkbox = document.getElementById('auto-refresh');
            if (checkbox.checked) {
                autoRefreshInterval = setInterval(loadLogs, 3000);
            }
            checkbox.addEventListener('change', () => {
                if (checkbox.checked) {
                    autoRefreshInterval = setInterval(loadLogs, 3000);
                } else {
                    clearInterval(autoRefreshInterval);
                }
            });
        }

        // Initial load
        loadLogs();
        setupAutoRefresh();
    </script>
</body>
</html>'''
