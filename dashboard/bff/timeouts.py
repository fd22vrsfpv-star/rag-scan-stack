"""Centralized HTTP timeout policy for BFF outbound calls.

Use the named tier closest to the operation's expected duration. Magic
numbers like `timeout=10` are discouraged — pick a tier so we can change
the policy in one place.

Tiers (seconds):
    FAST    — health checks, container status pings (3s)
    NORMAL  — typical CRUD / single-table queries (15s)
    LONG    — aggregations, search, embedding calls (60s)
    SCAN    — submitting/inspecting a long-running scan job (300s)
    LLM     — synchronous LLM chat / generation (600s)

Each tier is overridable via env: TIMEOUT_FAST=5 etc.
"""

from __future__ import annotations

import os


def _env(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except (TypeError, ValueError):
        return float(default)


TIMEOUT_FAST: float = _env("TIMEOUT_FAST", 3)
TIMEOUT_NORMAL: float = _env("TIMEOUT_NORMAL", 15)
TIMEOUT_LONG: float = _env("TIMEOUT_LONG", 60)
TIMEOUT_SCAN: float = _env("TIMEOUT_SCAN", 300)
TIMEOUT_LLM: float = _env("TIMEOUT_LLM", 600)

__all__ = [
    "TIMEOUT_FAST",
    "TIMEOUT_NORMAL",
    "TIMEOUT_LONG",
    "TIMEOUT_SCAN",
    "TIMEOUT_LLM",
]
