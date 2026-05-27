"""Standalone API Tester — single container, no database."""

import os
from pathlib import Path
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from backend.store import JsonStore
from backend.routes import collections, sessions, execute, param_configs

DATA_DIR = os.environ.get("DATA_DIR", "/data")
store = JsonStore(DATA_DIR)

app = FastAPI(title="API Tester", version="1.0.0")

# Mount API routes
app.include_router(collections.router)
app.include_router(sessions.router)
app.include_router(execute.router)
app.include_router(param_configs.router)


@app.get("/health")
def health():
    return {"status": "ok"}


# Serve frontend static files (SPA fallback)
_static_dir = Path(__file__).parent.parent / "static"
if _static_dir.exists():
    app.mount("/assets", StaticFiles(directory=str(_static_dir / "assets")), name="assets")

    @app.get("/{full_path:path}")
    async def serve_spa(full_path: str):
        # Try to serve static file first
        file_path = _static_dir / full_path
        if file_path.is_file():
            return FileResponse(file_path)
        # Fallback to index.html for SPA routing
        return FileResponse(_static_dir / "index.html")
