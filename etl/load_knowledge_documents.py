"""Embed the knowledge/*.yaml catalogue into rag_documents so the planner can
RETRIEVE it (search_knowledge_base), per CLAUDE.md "Knowledge is RAG-first".

Each YAML defines what to scan / what to do next and was, until now, read only
deterministically. This module renders every live knowledge file into retrievable
text documents, embeds them via the embedder service, and upserts them into
rag_documents keyed by metadata.source = "knowledge_<stem>". Idempotent per file:
the source's rows are replaced on each run, so re-running after an edit refreshes
without duplicating.

One renderer per file — a "per-file loader" — turns that file's own shape into
(title, text) pairs. A file with no dedicated renderer is skipped and reported,
never silently embedded as raw YAML.

    docker exec rag-api python3 -m etl.load_knowledge_documents
    # or from the sync endpoint: POST /rag/knowledge/sync

The WSTG maps (wstg_map.yaml, wstg_coverage_map.yaml) are intentionally NOT here:
their guidance is already retrievable from exploit_chunks via get_wstg_guidance,
a separate corpus. seed_prompts.example.yaml is example material, not live
knowledge.
"""
import os
import sys
import glob
import logging
from typing import Any, Dict, List, Tuple

import httpx
import psycopg2
import psycopg2.extras as _ex

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
log = logging.getLogger("load_knowledge_documents")

DB_DSN = os.environ.get("DB_DSN", "postgresql://app:app@rag-postgres:5432/scans")
EMBEDDER_URL = os.environ.get("EMBEDDER_URL", "https://embedder:8030")
# Bind-mounted read-only into rag-api / autogen-agents / scan-recommender.
KNOWLEDGE_DIR = os.environ.get("KNOWLEDGE_DIR", "/knowledge")
if not os.path.isdir(KNOWLEDGE_DIR):
    _repo = os.path.join(os.path.dirname(__file__), "..", "knowledge")
    if os.path.isdir(_repo):
        KNOWLEDGE_DIR = _repo

Doc = Tuple[str, str]


def _s(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, (list, tuple)):
        return ", ".join(_s(x) for x in v)
    if isinstance(v, dict):
        return "; ".join(f"{k}={_s(x)}" for k, x in v.items())
    return str(v).strip()


# ── per-file renderers ───────────────────────────────────────────────────────

def _render_service_tools(data: Dict[str, Any]) -> List[Doc]:
    docs: List[Doc] = []
    for svc, spec in (data.get("services") or {}).items():
        if not isinstance(spec, dict):
            continue
        ports = _s(spec.get("ports"))
        desc = _s(spec.get("description"))
        tools = spec.get("tools") or []
        lines = []
        for t in tools:
            if isinstance(t, dict):
                lines.append(f"- {t.get('name','?')}: {_s(t.get('purpose'))}"
                             + (f" — `{t['command']}`" if t.get("command") else ""))
        msf = _s(spec.get("metasploit"))
        nuclei = _s(spec.get("nuclei_tags"))
        body = (f"Service tooling for {svc}"
                + (f" (ports {ports})" if ports else "") + ". "
                + (desc + " " if desc else "")
                + ("Recommended tools:\n" + "\n".join(lines) if lines else ""))
        if msf:
            body += f"\nMetasploit: {msf}."
        if nuclei:
            body += f"\nNuclei tags: {nuclei}."
        docs.append((f"Service tooling: {svc}", body.strip()))
    return docs


def _render_credential_followups(data: Dict[str, Any]) -> List[Doc]:
    docs: List[Doc] = []
    for proto, entries in (data.get("protocols") or {}).items():
        for e in entries or []:
            if not isinstance(e, dict):
                continue
            title = f"Credential follow-up ({proto}): {e.get('name','?')}"
            body = (f"When a valid {proto} credential is held, {e.get('purpose','')}. "
                    f"Command: `{e.get('command','')}`."
                    + (f" Why: {_s(e.get('why'))}" if e.get("why") else ""))
            docs.append((title, body.strip()))
    return docs


def _render_default_credentials(data: Dict[str, Any]) -> List[Doc]:
    docs: List[Doc] = []
    common = data.get("common") or {}
    if common:
        docs.append(("Default credentials: common",
                     "Default usernames tried on every service: "
                     f"{_s(common.get('usernames'))}. Default passwords: "
                     f"{_s(common.get('passwords'))}. username_as_password="
                     f"{data.get('username_as_password')}: also try each username "
                     "as its own password."))
    for svc, spec in (data.get("services") or {}).items():
        if not isinstance(spec, dict):
            continue
        body = (f"Default credentials to try for {svc}"
                + (f" (ports {_s(spec.get('ports'))})" if spec.get("ports") else "")
                + f". Usernames: {_s(spec.get('usernames'))}. "
                + f"Passwords: {_s(spec.get('passwords'))}."
                + (f" {_s(spec.get('notes'))}" if spec.get("notes") else ""))
        docs.append((f"Default credentials: {svc}", body.strip()))
    return docs


def _render_service_access_methods(data: Dict[str, Any]) -> List[Doc]:
    docs: List[Doc] = []
    for m in (data.get("methods") or []):
        if not isinstance(m, dict):
            continue
        ident = m.get("id") or m.get("service") or "method"
        svc = _s(m.get("service"))
        prod = _s(m.get("product"))
        title = f"Service access method: {ident}"
        body = (f"How to reach/exploit {svc}"
                + (f" ({prod})" if prod else "") + ": "
                + _s(m.get("summary") or m.get("method")) + ". "
                + (f"Steps: {_s(m.get('steps'))} " if m.get("steps") else "")
                + (f"Attempt: `{m['attempt']}`. " if m.get("attempt") else "")
                + (f"Metasploit: {m['msf']}. " if m.get("msf") else "")
                + (f"Success when: {_s(m.get('success'))}." if m.get("success") else ""))
        docs.append((title, body.strip()))
    return docs


def _render_cloud_scan_rules(data: Dict[str, Any]) -> List[Doc]:
    docs: List[Doc] = []
    for cat in ("bootstrap_rules", "finding_rules", "credential_rules"):
        for r in (data.get(cat) or []):
            if not isinstance(r, dict):
                continue
            recs = []
            for rec in (r.get("recommendations") or []):
                if isinstance(rec, dict):
                    recs.append(f"- {rec.get('tool','?')}: {_s(rec.get('action'))}"
                                + (f" (`{rec['command_hint']}`)" if rec.get("command_hint") else ""))
            title = f"Cloud rule: {r.get('name') or r.get('id')}"
            body = (f"Cloud {cat.replace('_rules','')} rule for provider "
                    f"{_s(r.get('provider')) or 'any'}: {_s(r.get('description'))}. "
                    + ("Recommendations:\n" + "\n".join(recs) if recs else ""))
            docs.append((title, body.strip()))
    return docs


def _render_port_profiles(data: Dict[str, Any]) -> List[Doc]:
    docs: List[Doc] = []
    for name, spec in (data.get("profiles") or {}).items():
        if not isinstance(spec, dict):
            continue
        body = (f"Port scan profile '{name}' ({_s(spec.get('label'))}): "
                f"{_s(spec.get('description'))} Ports: {_s(spec.get('ports'))[:400]}.")
        docs.append((f"Port profile: {name}", body.strip()))
    return docs


def _render_scan_parameters(data: Dict[str, Any]) -> List[Doc]:
    docs: List[Doc] = []
    for key, spec in (data.get("parameters") or {}).items():
        if not isinstance(spec, dict):
            continue
        body = (f"Scan parameter '{key}' (default {_s(spec.get('default'))}): "
                f"{_s(spec.get('description'))} "
                + (f"Influences: {_s(spec.get('influences'))}. " if spec.get("influences") else "")
                + (f"Why: {_s(spec.get('why'))}" if spec.get("why") else ""))
        docs.append((f"Scan parameter: {key}", body.strip()))
    return docs


def _render_tool_options(data: Dict[str, Any]) -> List[Doc]:
    docs: List[Doc] = []
    for tool, cats in (data.get("tools") or {}).items():
        if not isinstance(cats, dict):
            continue
        opts = [f"- {c}: `{tmpl}`" for c, tmpl in cats.items()
                if isinstance(tmpl, str)]
        if not opts:
            continue
        body = (f"Tool options for {tool} — how to restrict {tool} to what the "
                f"host advertised ({{values}} is the host's supported list):\n"
                + "\n".join(opts))
        docs.append((f"Tool options: {tool}", body.strip()))
    return docs


def _render_credential_spray_policy(data: Dict[str, Any]) -> List[Doc]:
    docs: List[Doc] = []
    for p in (data.get("policies") or []):
        if not isinstance(p, dict):
            continue
        title = f"Spray policy: {p.get('name') or p.get('id')}"
        body = (f"Password-spray policy '{p.get('id')}' — verdict: "
                f"{p.get('verdict', 'see below')}. {_s(p.get('rationale'))} "
                f"When to use: {_s(p.get('when_to_use'))} "
                f"Acceptable only when ALL hold: {_s(p.get('acceptable_when'))}. "
                f"Cap: {p.get('max_attempts_per_account')} attempts per account. "
                f"Tools: {_s(p.get('tools'))}. "
                f"NOT acceptable: {_s(p.get('not_acceptable'))}. "
                f"Enforced by: {_s(p.get('enforced_by'))}.")
        docs.append((title, body.strip()))
    return docs


def _render_web_profiles(data: Dict[str, Any]) -> List[Doc]:
    docs: List[Doc] = []
    for name, spec in (data.get("profiles") or {}).items():
        if not isinstance(spec, dict):
            continue
        body = (f"Web scan profile '{name}' ({_s(spec.get('label'))}): "
                f"{_s(spec.get('description'))} "
                f"Stages: {_s(spec.get('stages'))}. "
                + (f"Wordlist: {_s(spec.get('wordlist'))}. " if spec.get("wordlist") else "")
                + (f"Crawl depth: {_s(spec.get('crawl_depth'))}. " if spec.get("crawl_depth") else "")
                + (f"Nuclei severity: {_s(spec.get('nuclei_severity'))}." if spec.get("nuclei_severity") else ""))
        docs.append((f"Web profile: {name}", body.strip()))
    return docs


# filename stem -> renderer. The test_knowledge_rag_coverage RAG_LOADED map must
# stay in step with this set.
def _render_msf_learned_options(data: Dict[str, Any]) -> List[Doc]:
    """Learned best MSF module options -> one retrievable doc per module."""
    docs: List[Doc] = []
    for module, spec in (data.get("modules") or {}).items():
        if not isinstance(spec, dict):
            continue
        opts = spec.get("options") or {}
        svc = _s(spec.get("service"))
        title = f"Learned Metasploit options: {module}"
        text = (f"Best-known options for Metasploit module {module}"
                + (f" (service {svc})" if svc else "") + ": "
                + (_s(opts) or "module defaults")
                + f". Learned from {spec.get('learned_from', 1)} successful run(s). "
                + "Apply as msf_option_overrides when running this module; host, "
                + "port and callback options are set per target, not learned.")
        docs.append((title, text))
    return docs


RENDERERS = {
    "msf_learned_options": _render_msf_learned_options,
    "service_tools": _render_service_tools,
    "credential_followups": _render_credential_followups,
    "default_credentials": _render_default_credentials,
    "service_access_methods": _render_service_access_methods,
    "cloud_scan_rules": _render_cloud_scan_rules,
    "port_profiles": _render_port_profiles,
    "scan_parameters": _render_scan_parameters,
    "tool_options": _render_tool_options,
    "web_profiles": _render_web_profiles,
    "credential_spray_policy": _render_credential_spray_policy,
}


def _embed(texts: List[str]) -> List[List[float]]:
    r = httpx.post(f"{EMBEDDER_URL.rstrip('/')}/embed", json={"texts": texts},
                   timeout=180, verify=False)
    r.raise_for_status()
    vecs = r.json()["embeddings"]
    if len(vecs) != len(texts):
        raise RuntimeError(f"embedder returned {len(vecs)} for {len(texts)} texts")
    return vecs


def render_file(stem: str, data: Dict[str, Any]) -> List[Doc]:
    fn = RENDERERS.get(stem)
    if not fn:
        return []
    try:
        return [(t, b) for t, b in fn(data or {}) if b and b.strip()]
    except Exception as e:  # noqa: BLE001
        log.warning("renderer for %s failed: %s", stem, e)
        return []


def load_one(conn, stem: str, docs: List[Doc]) -> int:
    source = f"knowledge_{stem}"
    cur = conn.cursor()
    cur.execute("DELETE FROM rag_documents WHERE metadata->>'source' = %s", (source,))
    if not docs:
        conn.commit()
        cur.close()
        return 0
    vectors = _embed([f"{t}\n{b}" for t, b in docs])
    rows = []
    for (title, text), vec in zip(docs, vectors):
        vec_str = "[" + ",".join(repr(float(x)) for x in vec) + "]"
        rows.append((title, text,
                     _ex.Json({"source": source, "kind": "knowledge", "file": f"{stem}.yaml"}),
                     vec_str))
    _ex.execute_values(
        cur,
        "INSERT INTO rag_documents (title, text_chunk, metadata, embedding) VALUES %s",
        rows, template="(%s, %s, %s, %s::vector)")
    conn.commit()
    cur.close()
    return len(rows)


def sync_all() -> Dict[str, Any]:
    """Embed every renderable knowledge file; return per-file counts. Used by the
    POST /rag/knowledge/sync endpoint and by main()."""
    if yaml is None:
        raise RuntimeError("pyyaml not available")
    if not os.path.isdir(KNOWLEDGE_DIR):
        raise RuntimeError(f"knowledge dir not found: {KNOWLEDGE_DIR}")
    conn = psycopg2.connect(DB_DSN)
    out: Dict[str, Any] = {"files": {}, "total": 0}
    try:
        for stem in sorted(RENDERERS):
            path = os.path.join(KNOWLEDGE_DIR, f"{stem}.yaml")
            if not os.path.exists(path):
                out["files"][stem] = {"error": "missing"}
                continue
            with open(path, encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
            n = load_one(conn, stem, render_file(stem, data))
            out["files"][stem] = n
            out["total"] += n
    finally:
        conn.close()
    return out


def main() -> int:
    if yaml is None:
        log.error("pyyaml not available")
        return 1
    if not os.path.isdir(KNOWLEDGE_DIR):
        log.error("knowledge dir not found: %s", KNOWLEDGE_DIR)
        return 1
    conn = psycopg2.connect(DB_DSN)
    total = 0
    loaded_files = 0
    try:
        for stem in sorted(RENDERERS):
            path = os.path.join(KNOWLEDGE_DIR, f"{stem}.yaml")
            if not os.path.exists(path):
                log.warning("missing knowledge file: %s", path)
                continue
            with open(path, encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
            docs = render_file(stem, data)
            n = load_one(conn, stem, docs)
            total += n
            loaded_files += 1
            log.info("%-24s -> %d documents", f"{stem}.yaml", n)
    finally:
        conn.close()
    log.info("embedded %d knowledge documents from %d files into rag_documents",
             total, loaded_files)
    return 0


if __name__ == "__main__":
    sys.exit(main())
