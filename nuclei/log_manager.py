"""
Log Manager for Nuclei Runner Diagnostic Web Interface
Captures logs from nuclei scanning operations
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
    def __init__(self, record: logging.LogRecord):
        self.timestamp = datetime.fromtimestamp(record.created).isoformat()
        self.level = record.levelname
        self.logger = record.name
        self.message = record.getMessage()
        self.module = record.module
        self.function = record.funcName
        self.line = record.lineno
        self.job_id = None
        if '[' in self.message and ']' in self.message:
            start = self.message.find('[')
            end = self.message.find(']', start)
            if end > start and len(self.message[start+1:end]) >= 8:
                self.job_id = self.message[start+1:end]

    def to_dict(self) -> Dict:
        return {
            "timestamp": self.timestamp, "level": self.level, "logger": self.logger,
            "message": self.message, "module": self.module, "function": self.function,
            "line": self.line, "job_id": self.job_id
        }


class CircularLogHandler(logging.Handler):
    def __init__(self, max_size: int = 2000):
        super().__init__()
        self.max_size = max_size
        self.records = deque(maxlen=max_size)
        self._sync_lock = threading.Lock()
        self._async_lock: Optional[asyncio.Lock] = None
        self.stats = {"total_received": 0, "by_level": {"DEBUG": 0, "INFO": 0, "WARNING": 0, "ERROR": 0, "CRITICAL": 0}, "started_at": datetime.now().isoformat()}

    def _get_async_lock(self) -> asyncio.Lock:
        if self._async_lock is None: self._async_lock = asyncio.Lock()
        return self._async_lock

    def emit(self, record: logging.LogRecord):
        try:
            with self._sync_lock:
                self.records.append(LogRecord(record))
                self.stats["total_received"] += 1
                if record.levelname in self.stats["by_level"]: self.stats["by_level"][record.levelname] += 1
        except Exception: self.handleError(record)

    async def async_get_logs(self, level=None, limit=100, search=None, job_id=None) -> List[Dict]:
        async with self._get_async_lock():
            logs = list(self.records)
        if level: logs = [l for l in logs if l.level == level.upper()]
        if job_id: logs = [l for l in logs if l.job_id and job_id in l.job_id]
        if search: logs = [l for l in logs if search.lower() in l.message.lower()]
        return [l.to_dict() for l in logs[-limit:]]

    async def async_get_stats(self) -> Dict:
        async with self._get_async_lock():
            return {**self.stats, "current_buffer_size": len(self.records), "max_buffer_size": self.max_size}

    async def async_export_json(self) -> str:
        async with self._get_async_lock():
            return json.dumps({"logs": [l.to_dict() for l in self.records], "stats": {**self.stats, "current_buffer_size": len(self.records)}, "exported_at": datetime.now().isoformat()}, indent=2)


_log_handler = CircularLogHandler(max_size=2000)

def get_log_handler() -> CircularLogHandler: return _log_handler

def setup_log_capture():
    for name in ["root", "nuclei", "nuclei_runner"]:
        logger = logging.getLogger(name)
        if _log_handler not in logger.handlers:
            logger.addHandler(_log_handler)
            logger.setLevel(logging.INFO)
    logging.getLogger().addHandler(_log_handler)
    print(f"[nuclei-runner] Log capture initialized: max {_log_handler.max_size} records", file=sys.stderr)


LOGS_UI_HTML = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Nuclei Runner Logs</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', sans-serif; background: #1a1a1a; color: #e0e0e0; padding: 20px; }
        .container { max-width: 1400px; margin: 0 auto; }
        header { background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%); padding: 30px; border-radius: 10px; margin-bottom: 30px; }
        h1 { color: white; font-size: 28px; margin-bottom: 10px; }
        .subtitle { color: rgba(255,255,255,0.9); font-size: 14px; }
        .controls { background: #2a2a2a; padding: 20px; border-radius: 10px; margin-bottom: 20px; display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; }
        .control-group { display: flex; flex-direction: column; }
        label { font-size: 12px; color: #aaa; margin-bottom: 5px; text-transform: uppercase; }
        input, select { background: #1a1a1a; border: 1px solid #444; color: #e0e0e0; padding: 10px; border-radius: 5px; }
        button { background: #e74c3c; color: white; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer; }
        button:hover { background: #c0392b; }
        button.secondary { background: #6c757d; }
        .stats { background: #2a2a2a; padding: 15px 20px; border-radius: 10px; margin-bottom: 20px; display: flex; gap: 30px; flex-wrap: wrap; }
        .stat-item { display: flex; flex-direction: column; }
        .stat-value { font-size: 24px; font-weight: bold; color: #e74c3c; }
        .stat-label { font-size: 12px; color: #888; text-transform: uppercase; }
        .logs-container { background: #2a2a2a; border-radius: 10px; padding: 20px; max-height: 600px; overflow-y: auto; }
        .log-entry { background: #1a1a1a; border-radius: 5px; padding: 12px; margin-bottom: 8px; border-left: 4px solid #6c757d; }
        .log-entry.INFO { border-left-color: #e74c3c; }
        .log-entry.WARNING { border-left-color: #ffc107; }
        .log-entry.ERROR { border-left-color: #dc3545; }
        .log-header { display: flex; align-items: center; gap: 10px; margin-bottom: 8px; flex-wrap: wrap; }
        .log-level { padding: 2px 8px; border-radius: 3px; font-size: 11px; font-weight: bold; }
        .log-level.INFO { background: #e74c3c; color: white; }
        .log-level.WARNING { background: #ffc107; color: black; }
        .log-level.ERROR { background: #dc3545; color: white; }
        .log-time { color: #888; font-size: 12px; }
        .log-job { background: #2d2d2d; padding: 2px 6px; border-radius: 3px; font-size: 11px; color: #17a2b8; }
        .log-message { font-family: monospace; font-size: 13px; word-break: break-word; }
        .log-meta { color: #666; font-size: 11px; margin-top: 6px; }
        .auto-refresh { display: flex; align-items: center; gap: 10px; }
        .auto-refresh input[type="checkbox"] { width: 18px; height: 18px; }
    </style>
</head>
<body>
    <div class="container">
        <header><h1>Nuclei Runner Logs</h1><p class="subtitle">Real-time logging for Nuclei vulnerability scanning</p></header>
        <div class="stats" id="stats">
            <div class="stat-item"><span class="stat-value" id="total-logs">-</span><span class="stat-label">Total</span></div>
            <div class="stat-item"><span class="stat-value" id="info-count">-</span><span class="stat-label">Info</span></div>
            <div class="stat-item"><span class="stat-value" id="warning-count">-</span><span class="stat-label">Warnings</span></div>
            <div class="stat-item"><span class="stat-value" id="error-count">-</span><span class="stat-label">Errors</span></div>
        </div>
        <div class="controls">
            <div class="control-group"><label>Level</label><select id="level"><option value="">All</option><option value="INFO">INFO</option><option value="WARNING">WARNING</option><option value="ERROR">ERROR</option></select></div>
            <div class="control-group"><label>Search</label><input type="text" id="search" placeholder="Search..."></div>
            <div class="control-group"><label>Job ID</label><input type="text" id="job_id" placeholder="Filter by job..."></div>
            <div class="control-group"><label>Limit</label><select id="limit"><option value="50">50</option><option value="100" selected>100</option><option value="200">200</option></select></div>
            <div class="control-group"><label>Actions</label><div style="display:flex;gap:10px"><button onclick="loadLogs()">Refresh</button><button class="secondary" onclick="exportLogs()">Export</button></div></div>
            <div class="control-group auto-refresh"><label>Auto Refresh</label><input type="checkbox" id="auto-refresh" checked><span style="font-size:12px;color:#888">3s</span></div>
        </div>
        <div class="logs-container" id="logs"><div class="loading">Loading...</div></div>
    </div>
    <script>
        let autoRefreshInterval = null;
        async function loadStats() { try { const r = await fetch('/logs/stats'); const d = await r.json(); document.getElementById('total-logs').textContent = d.stats.total_received; document.getElementById('info-count').textContent = d.stats.by_level.INFO; document.getElementById('warning-count').textContent = d.stats.by_level.WARNING; document.getElementById('error-count').textContent = d.stats.by_level.ERROR; } catch(e) { console.error(e); } }
        async function loadLogs() { const p = new URLSearchParams(); ['level','search','job_id','limit'].forEach(k => { const v = document.getElementById(k).value; if(v) p.append(k,v); }); try { const r = await fetch(`/logs?${p}`); const d = await r.json(); const c = document.getElementById('logs'); if(!d.logs.length) { c.innerHTML = '<div style="text-align:center;padding:40px;color:#888">No logs</div>'; return; } c.innerHTML = d.logs.map(l => `<div class="log-entry ${l.level}"><div class="log-header"><span class="log-level ${l.level}">${l.level}</span><span class="log-time">${new Date(l.timestamp).toLocaleString()}</span>${l.job_id?`<span class="log-job">${l.job_id}</span>`:''}</div><div class="log-message">${l.message.replace(/</g,'&lt;')}</div><div class="log-meta">${l.logger} | ${l.module}.${l.function}:${l.line}</div></div>`).join(''); c.scrollTop = c.scrollHeight; await loadStats(); } catch(e) { document.getElementById('logs').innerHTML = `<div style="color:#dc3545;text-align:center;padding:40px">Error: ${e.message}</div>`; } }
        async function exportLogs() { const r = await fetch('/logs/export'); const b = await r.blob(); const a = document.createElement('a'); a.href = URL.createObjectURL(b); a.download = `nuclei_logs_${new Date().toISOString().replace(/[:.]/g,'-')}.json`; a.click(); }
        document.getElementById('auto-refresh').addEventListener('change', e => { if(e.target.checked) autoRefreshInterval = setInterval(loadLogs, 3000); else clearInterval(autoRefreshInterval); });
        loadLogs(); if(document.getElementById('auto-refresh').checked) autoRefreshInterval = setInterval(loadLogs, 3000);
    </script>
</body>
</html>'''
