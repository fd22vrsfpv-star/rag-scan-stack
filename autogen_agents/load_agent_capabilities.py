"""Load the agent's ACTIONS into rag_documents so the LLMs know what they can do.

The LLM is given tool schemas at call time, but it does not always connect a
situation ("ssh is open", "I have a shadow hash") to the action that handles it.
Embedding each action — and the end-to-end WORKFLOWS that chain them — into the
RAG corpus means the planner can retrieve "to get valid passwords, guess with
brutus then crack the hashes" the same way it retrieves any other knowledge.

Idempotent: replaces everything under metadata.source='agent_capability'.

    docker exec autogen-agents python3 /app/load_agent_capabilities.py
"""
import os
import sys
import logging

import httpx
import psycopg2

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
log = logging.getLogger("load_agent_capabilities")

DB_DSN = os.environ.get("DB_DSN", "postgresql://app:app@rag-postgres:5432/scans")
EMBEDDER_URL = os.environ.get("EMBEDDER_URL", "https://embedder:8030")
SOURCE = "agent_capability"

# End-to-end workflows — the knowledge that ties individual tools into an action
# the planner should take when it sees a situation. Written as retrievable facts.
WORKFLOWS = [
    ("Test default credentials on any login service",
     "When a login service is open (ssh, ftp, telnet, mysql, postgres, mssql, vnc, "
     "rdp, smb, redis, mongodb), TEST DEFAULT CREDENTIALS — do not stop at "
     "identifying the service. Call start_brutus (or let the login-service-credential-check "
     "enumeration rule queue it); it routes to the brutus multi-protocol tester and "
     "guesses the default credential set. Valid credentials are stored in "
     "credential_findings and become usable access. Finding ssh open and never "
     "guessing msfadmin:msfadmin is a miss."),
    ("Turn captured password hashes into usable credentials",
     "Post-exploitation dumps /etc/shadow as password HASHES ($1$/$5$/$6$/$2y$…). A "
     "hash is NOT a login — it is a crack target. To get usable passwords, crack the "
     "hashes: POST /crack/{target} on exploit-runner (add ?node_id=<id> to crack on a "
     "remote GPU node). It runs hashcat, stores each cracked plaintext as a real "
     "password credential (so the access model discovers and probes it), and writes a "
     "RAG document. Do this whenever shadow/SAM hashes are captured."),
    ("Access is measured, and includes credentials and services, not only shells",
     "Held access lives in obtained_access, MEASURED by probing (etl/access.py). It "
     "includes msf sessions, bind shells, ssh credentials, planted webshells AND any "
     "service credential (database, vnc, ftp, redis, telnet) via the generic "
     "'credential' transport. A valid credential to a service is durable access that "
     "survives a reboot. Rank by privilege and stability; run the post-enumeration "
     "checklist through the single best access."),
    ("Reconnect access after a host reboot",
     "When a host reboots, live shells die. The reconnect watcher re-probes access "
     "each cycle: credential-backed access (ssh/db/etc.) is re-established because the "
     "credential still works; a dead msf/bind shell needs persistence installed before "
     "the reboot. Access is recorded automatically after a successful exploit so the "
     "watcher has something to maintain. See /reconnect-watcher/status."),
    ("Exploits route through the engagement's node proxy and auto-correct on failure",
     "Every attack routes through a node SOCKS proxy (fail closed): the engagement's "
     "selected node first, else a node on the target's own network. An MSF module that "
     "fails as 'Invalid Module' is auto-corrected (module search / LLM diagnosis) and "
     "re-run; other failures (no session, timeout) are classified and retried. by-id "
     "metasploit exploits resolve their module from the title and delegate to "
     "/execute/msf so they get the proxy, classifier and auto-correct."),
    ("All target-connecting output is analysed",
     "Every tool and exploit that connects to a target has its output analysed — "
     "parsed into findings and run through post_enumeration.analyse, which queues "
     "scope-gated follow-ups. Tools without a dedicated parser fall back to the "
     "generic /ingest/tool-output structurer, so nothing is discarded."),
]


def _embed(texts):
    r = httpx.post(f"{EMBEDDER_URL.rstrip('/')}/embed", json={"texts": texts},
                   timeout=180, verify=False)
    r.raise_for_status()
    vecs = r.json()["embeddings"]
    if len(vecs) != len(texts):
        raise RuntimeError(f"embedder returned {len(vecs)} for {len(texts)} texts")
    return vecs


def _tool_docs():
    """(title, text) per registered agent action, from the tool registry."""
    try:
        from tool_registry import TOOL_SPECS
    except Exception as e:  # noqa: BLE001
        log.warning("tool_registry unavailable (%s) — workflows only", e)
        return []
    docs = []
    for t in TOOL_SPECS:
        name = getattr(t, "name", "") or ""
        desc = (getattr(t, "description", "") or "").strip()
        if not name:
            continue
        docs.append((f"Agent action: {name}",
                     f"Agent tool `{name}`. {desc} Call this action when the situation "
                     f"calls for it."))
    return docs


def main():
    docs = [(f"Agent workflow: {t}", body) for t, body in WORKFLOWS] + _tool_docs()
    if not docs:
        log.error("no capability documents to load")
        return 1
    titles = [d[0] for d in docs]
    texts = [d[1] for d in docs]
    vectors = _embed([f"{t}\n{x}" for t, x in docs])
    conn = psycopg2.connect(DB_DSN)
    try:
        import psycopg2.extras as ex
        cur = conn.cursor()
        cur.execute("DELETE FROM rag_documents WHERE metadata->>'source' = %s", (SOURCE,))
        rows = []
        for (title, text), vec in zip(docs, vectors):
            vec_str = "[" + ",".join(repr(float(x)) for x in vec) + "]"
            rows.append((title, text, ex.Json({"source": SOURCE, "kind": "capability"}), vec_str))
        ex.execute_values(
            cur,
            "INSERT INTO rag_documents (title, text_chunk, metadata, embedding) VALUES %s",
            rows, template="(%s, %s, %s, %s::vector)")
        conn.commit()
        cur.close()
    finally:
        conn.close()
    log.info("loaded %d agent-capability documents (%d workflows + %d tools)",
             len(docs), len(WORKFLOWS), len(docs) - len(WORKFLOWS))
    return 0


if __name__ == "__main__":
    sys.exit(main())
