import asyncio
import json
import logging
from fastapi import WebSocket

log = logging.getLogger("ws_hub")


class WSHub:
    def __init__(self):
        self._connections: list[WebSocket] = []
        self._lock = asyncio.Lock()

    async def connect(self, ws: WebSocket):
        await ws.accept()
        async with self._lock:
            self._connections.append(ws)
        log.info("WS client connected (%d total)", len(self._connections))

    async def disconnect(self, ws: WebSocket):
        async with self._lock:
            if ws in self._connections:
                self._connections.remove(ws)
        log.info("WS client disconnected (%d total)", len(self._connections))

    async def broadcast(self, event_type: str, data: dict):
        msg = json.dumps({"type": event_type, "data": data})
        async with self._lock:
            stale = []
            for ws in self._connections:
                try:
                    await ws.send_text(msg)
                except Exception:
                    stale.append(ws)
            for ws in stale:
                self._connections.remove(ws)

    @property
    def client_count(self) -> int:
        return len(self._connections)


hub = WSHub()
