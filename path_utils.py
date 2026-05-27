from __future__ import annotations
from pathlib import Path
import os

def project_root(start: Path | None = None, depth: int = 2) -> Path:
    """
    Compute the project root from this file (or a provided starting point).
    Increase/decrease depth so ROOT points to your repo root.
    """
    p = (start or Path(__file__).resolve()).parents[depth]
    return p

ROOT = project_root()

def resources(*parts: str) -> Path:
    """ROOT/src/main/resources/... (adjust to your layout)."""
    base = ROOT / "src" / "main" / "resources"
    return base.joinpath(*parts)

def data_dir(*parts: str) -> Path:
    """Writable data dir under project (or APP_DATA_DIR env override)."""
    base = Path(os.environ.get("APP_DATA_DIR", ROOT / "var" / "data"))
    base.mkdir(parents=True, exist_ok=True)
    return base.joinpath(*parts)

def ensure_parent(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    return path
