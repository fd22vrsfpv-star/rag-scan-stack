#!/usr/bin/env python3
"""Embed the RUNNER'S OWN RUNTIME into rag_documents, so the synthesiser writes
commands for the machine that will actually run them.

WHY THIS EXISTS
---------------
PoC commands execute on kali-listener via subprocess(shell=True), which uses
/bin/sh — and there /bin/sh is a symlink to DASH. The model naturally writes
bash: process substitution `<(...)`, `[[ ]]`, arrays. Those die in the shell
before a packet reaches the target, and the verdict then records a shell error
instead of anything about the exploit. 37 trace files in /app/poc_logs carry a
shell syntax error; "redirection unexpected" alone appears 24 times.

Setting `executable=` in the executor fixes the symptom. It does not tell the
MODEL anything, so the model keeps guessing — and the next environment fact
(which tools exist, what OS) has the same problem. CLAUDE.md:

    New knowledge should take effect by being loaded and embedded, not by
    editing branching logic.

So the runner reports itself at GET /runtime/profile (it is the authority —
same reasoning as /tools/capabilities), and this loader embeds that into the
RAG corpus where the planner and synthesiser already retrieve.

IDEMPOTENT: replaces everything under metadata.source='runner_profile'.

RUN IT
------
    docker exec rag-api python3 /app/etl/load_runner_profile.py

on change — a listener rebuild, a new tool installed, a base-image bump.
"""
from __future__ import annotations

import json
import logging
import os
import sys

log = logging.getLogger("load_runner_profile")
logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

SOURCE = "runner_profile"
LISTENER = os.environ.get("KALI_LISTENER_URL", "https://kali-listener:8019")
EMBED_URL = os.environ.get("EMBEDDER_URL", "http://embedder:8000")
DB_DSN = os.environ.get("DB_DSN", "")


def fetch_profile(timeout: int = 15) -> dict:
    """Ask the runner what it is. Returns {} when unreachable — an unreachable
    runner is not an empty runner (CLAUDE.md: unreachable is not absent), so the
    caller refuses rather than embedding a document claiming nothing exists."""
    import httpx
    try:
        with httpx.Client(verify=False, timeout=timeout) as c:
            r = c.get(f"{LISTENER.rstrip('/')}/runtime/profile")
            if r.status_code == 200:
                return r.json() or {}
            log.error("runtime profile HTTP %s: %s", r.status_code, r.text[:200])
    except Exception as e:  # noqa: BLE001
        log.error("runner unreachable at %s: %s", LISTENER, e)
    return {}


def render(p: dict) -> list[tuple[str, str]]:
    """Profile -> retrievable documents. Written as instructions to the command
    author, because that is who retrieves them."""
    shell = p.get("exec_shell") or "?"
    ver = p.get("exec_shell_version") or ""
    is_bash = "bash" in str(shell)
    present = ", ".join(p.get("binaries_present") or []) or "(none reported)"
    missing = ", ".join(p.get("binaries_missing") or []) or "(none)"

    shell_doc = (
        f"Commands you write are executed on {p.get('runner', 'the runner')} "
        f"({p.get('os', 'unknown OS')}) and parsed by {shell}"
        + (f" ({ver})" if ver else "") + ".\n\n"
        + ("This IS bash, so bash syntax is safe: process substitution <(...), "
           "[[ ]] tests, arrays, &> redirection.\n"
           if is_bash else
           "This is NOT bash. Write POSIX sh only: no process substitution "
           "<(...), no [[ ]], no arrays, no &>. Use `cmd > f 2>&1`, `[ ... ]`, "
           "and a temp file instead of a process substitution.\n")
        + (f"NOTE: /bin/sh on this runner is {p.get('sh_is')}, which is NOT bash. "
           "Anything executed through /bin/sh rather than the shell above will "
           "reject bash-only syntax.\n" if p.get("sh_is_dash") else "")
        + "\nA command that the shell cannot parse fails before any packet "
          "reaches the target, and the verdict then describes the shell, not "
          "the exploit."
    )

    tools_doc = (
        f"Programs available on {p.get('runner', 'the runner')} for PoC commands:\n"
        f"  PRESENT: {present}\n"
        f"  ABSENT:  {missing}\n\n"
        "Use only programs listed as PRESENT. A command naming an absent "
        "program is refused before dispatch by the pre-run tool check, which "
        "costs an iteration and reaches the target zero times. Prefer curl for "
        "HTTP and python3 for anything curl cannot express."
    )
    return [
        (f"Runner shell: {shell}", shell_doc),
        (f"Runner tools: {p.get('runner', 'kali-listener')}", tools_doc),
    ]


def embed(texts: list[str]) -> list[list[float]]:
    import httpx
    with httpx.Client(timeout=120) as c:
        r = c.post(f"{EMBED_URL.rstrip('/')}/embed", json={"texts": texts})
        r.raise_for_status()
        d = r.json()
    return d.get("embeddings") or d.get("vectors") or d


def main() -> int:
    prof = fetch_profile()
    if not prof or not prof.get("exec_shell"):
        log.error("no runner profile — refusing to embed. An unreachable "
                  "runner is not a runner with no shell.")
        return 2
    docs = render(prof)
    log.info("runner=%s shell=%s sh_is_dash=%s present=%d missing=%d",
             prof.get("runner"), prof.get("exec_shell"), prof.get("sh_is_dash"),
             len(prof.get("binaries_present") or []),
             len(prof.get("binaries_missing") or []))

    import psycopg2
    import psycopg2.extras as ex
    vectors = embed([f"{t}\n{b}" for t, b in docs])
    conn = psycopg2.connect(DB_DSN)
    try:
        cur = conn.cursor()
        cur.execute("DELETE FROM rag_documents WHERE metadata->>'source' = %s", (SOURCE,))
        rows = []
        for (title, text), vec in zip(docs, vectors):
            vec_str = "[" + ",".join(repr(float(x)) for x in vec) + "]"
            rows.append((title, text,
                         ex.Json({"source": SOURCE, "kind": "runtime",
                                  "runner": prof.get("runner"),
                                  "exec_shell": prof.get("exec_shell")}),
                         vec_str))
        ex.execute_values(
            cur,
            "INSERT INTO rag_documents (title, text_chunk, metadata, embedding) VALUES %s",
            rows, template="(%s, %s, %s, %s::vector)")
        conn.commit()
        cur.close()
    finally:
        conn.close()
    log.info("loaded %d runner-profile documents", len(docs))
    return 0


if __name__ == "__main__":
    sys.exit(main())
