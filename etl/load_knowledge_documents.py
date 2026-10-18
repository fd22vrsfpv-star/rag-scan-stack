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
import re
import sys
import glob
import logging
from typing import Any, Dict, List, Tuple

import httpx
import psycopg2
import psycopg2.extras as _ex

from etl import vuln_classes as _vuln_classes

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

# (title, body) or (title, body, extra_metadata)
Doc = Tuple[str, ...]


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
        docs.append((f"Service tooling: {svc}", body.strip(),
                     {"service": svc, "doc_type": "service_tooling"}))
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
        docs.append((title, body.strip(),
                     {"service": svc, "doc_type": "service_access_method",
                      "mutates": bool(m.get("mutates"))}))
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


def _render_dos_exploit_overrides(data: Dict[str, Any]) -> List[Doc]:
    """Operator DoS overrides -> one doc each, so the exemption is discoverable."""
    docs: List[Doc] = []
    for o in (data.get("overrides") or []):
        m = o.get("match") if isinstance(o, dict) else o
        if not m:
            continue
        reason = (o.get("reason") if isinstance(o, dict) else "") or ""
        docs.append((f"DoS override: {m}",
                     f"Exploit {m} is an operator-approved DoS override: it may be "
                     f"recommended, queued and executed despite being tagged "
                     f"denial-of-service. Reason: {reason or 'operator-approved'}."))
    return docs


def _render_enumeration_extractors(data: Dict[str, Any]) -> List[Doc]:
    """Output->fact extractors -> one doc each, so the planner can retrieve what
    shapes the platform reads out of raw command/scan output (which token and
    secret kinds it recognises) without parsing the regexes."""
    docs: List[Doc] = []
    for ex in (data.get("extractors") or []):
        if not isinstance(ex, dict):
            continue
        xid = ex.get("id") or ""
        emit = ex.get("emit") or {}
        fact = emit.get("fact") or "fact"
        kind = emit.get("kind")
        why = (ex.get("why") or "").strip()
        label = f"{fact}/{kind}" if kind else fact
        docs.append((
            f"Enumeration extractor: {xid} ({label})",
            f"When raw command or scan output matches the {xid} pattern, the "
            f"platform emits a `{label}` fact that the enumeration rules can act "
            f"on. {why}".strip()))
    return docs


def _render_postex_commands(data: Dict[str, Any]) -> List[Doc]:
    """Post-exploitation command sets -> one doc per command, so the planner can
    retrieve what the platform runs through a held shell (baseline info-gathering
    and per-service local-database probes) as knowledge, not only as code."""
    docs: List[Doc] = []
    for step in (data.get("info_commands") or []):
        if not isinstance(step, dict):
            continue
        docs.append((
            f"Post-ex info command: {step.get('id') or step.get('title')}",
            f"Through a held shell the platform runs `{step.get('command')}` "
            f"({step.get('title')}) as baseline post-exploitation enumeration."))
    for svc, spec in (data.get("local_database_probes") or {}).items():
        if not isinstance(spec, dict):
            continue
        for c in (spec.get("commands") or []):
            docs.append((
                f"Local DB probe ({svc}): {c.get('title')}",
                f"When {svc} is found listening only on loopback, the platform "
                f"runs `{c.get('command')}` ({c.get('title')}) through the local "
                f"shell to enumerate it — {spec.get('why', '')}".strip()))
    return docs


def _render_postex_web(data: Dict[str, Any]) -> List[Doc]:
    """Web post-exploitation ('loot') -> one doc per vuln class, so the planner can
    retrieve HOW to weaponize a CONFIRMED web exploit (dump the DB, read the file,
    drop a webshell) as gated follow-on knowledge, separate from the read-only prove
    methodology."""
    docs: List[Doc] = []
    for cid, entry in (data.get("classes") or {}).items():
        if not isinstance(entry, dict):
            continue
        docs.append((
            f"Web post-exploitation ({cid})",
            f"Once a {cid} exploit is CONFIRMED, weaponize it (GATED/impactful, "
            f"follow-on lane): {entry.get('objective', '')} {entry.get('weaponize', '')} "
            f"Proof = {entry.get('proof', '')}".strip()))
    # The class-agnostic error-analysis / correction / collection methodology (two-phase
    # weaponization) + each deterministic error fix, as retrievable knowledge.
    ea = data.get("error_analysis") or {}
    if ea.get("methodology"):
        docs.append(("Web exploit error-analysis & correction methodology",
                     f"Weaponize in two phases (correct then collect). {ea['methodology']}"))
    for row in (ea.get("error_fixes") or []):
        if isinstance(row, dict) and row.get("fix"):
            docs.append((f"Exploit error fix: {row['fix'][:60]}",
                         f"When a web-exploit command's output matches `{row.get('match', '')}`, "
                         f"the fix is: {row['fix']}"))
    for row in (ea.get("tweaks") or []):
        if isinstance(row, dict) and row.get("tweak"):
            docs.append((f"Exploit output tweak: {row['tweak'][:60]}",
                         f"When the output matches `{row.get('match', '')}`, improve it: {row['tweak']}"))
    # The staged data-collection methodology (tables -> columns -> row counts -> data).
    coll = data.get("collection") or {}
    if coll.get("methodology"):
        docs.append(("Web data-collection methodology (staged)",
                     f"After correcting a web exploit, collect data in stages: {coll['methodology']}"))
    for st in (coll.get("plan") or []):
        if isinstance(st, dict) and st.get("stage"):
            docs.append((f"Collection stage: {st['stage']}",
                         f"Stage '{st['stage']}' — {st.get('goal', '')}. Subquery: "
                         f"{st.get('subquery', '')}".strip()))
    # Truncation signals — first-class post-analysis signals that drive auto-page.
    for row in (ea.get("truncation_signals") or []):
        if isinstance(row, dict) and row.get("action"):
            docs.append((f"Post-analysis: truncation signal {row.get('id', '')}",
                         f"When output matches `{row.get('match', '')}`, "
                         f"{row.get('action', '')}. Captures: {row.get('captures', '')}"))
    # Volume gate — the "don't pull terabytes" safety policy.
    vg = coll.get("volume_gate") or {}
    if vg.get("purpose"):
        docs.append(("Post-ex volume gate (safety policy)",
                     f"{vg['purpose']} Defaults: max_rows={vg.get('default_max_rows')}, "
                     f"hard_max_rows={vg.get('hard_max_rows')}, warn_bytes={vg.get('warn_bytes')}, "
                     f"hard_max_bytes={vg.get('hard_max_bytes')}. Policy: {vg.get('policy', {})}"))
    # Composable POST-EX PRIMITIVES — the small chainable skills the collect agent invokes.
    prims = data.get("primitives") or {}
    if prims.get("purpose"):
        docs.append(("Post-ex primitives — purpose",
                     f"Composable post-exploitation skills. {prims['purpose']}"))
    for pname, p in prims.items():
        if pname == "purpose" or not isinstance(p, dict):
            continue
        docs.append((f"Post-ex primitive: {pname}",
                     f"{p.get('description', '')} Args: {p.get('args')}. "
                     f"Returns: {p.get('returns')}. Chain: {p.get('chain')}".strip()))
    return docs


def _render_msf_readonly_scanners(data: Dict[str, Any]) -> List[Doc]:
    """Read-only MSF auxiliary scanners -> one doc each, so the planner can
    retrieve WHICH Metasploit scanner modules are purely informational (and the
    safe non-MSF command that runs them) as knowledge — the classification that
    keeps a robots.txt fetch out of the human-approval lane."""
    docs: List[Doc] = []
    for row in (data.get("read_only_scanners") or []):
        if not isinstance(row, dict):
            continue
        module = row.get("module")
        if not module:
            continue
        docs.append((
            f"Read-only MSF scanner: {module}",
            f"The Metasploit module {module} ({row.get('purpose', 'info scan')}) "
            f"is purely read-only — it retrieves information and changes nothing. "
            f"The platform runs it in the SAFE autonomous lane via "
            f"`{row.get('safe_command')}` (category {row.get('category')}) instead "
            f"of an approval-gated Metasploit session."))
    return docs


def _render_owasp_param_tests(data: Dict[str, Any]) -> List[Doc]:
    """OWASP parameter-test specs -> one doc each, so the planner can retrieve
    which app-layer probe (SQLi/XSS/LFI/SSI/HPP/IDOR) the surface phase runs per
    crawled parameter, and with what payload/assertion, as knowledge not code."""
    docs: List[Doc] = []
    for row in (data.get("param_tests") or []):
        if not isinstance(row, dict):
            continue
        cat = row.get("category")
        if not cat:
            continue
        docs.append((
            f"OWASP param test: {cat} ({row.get('tool','curl')})",
            f"For a crawled parameter the surface phase runs `{row.get('command')}` "
            f"({row.get('wstg','WSTG')}, {'impactful' if row.get('impactful') else 'safe'}) "
            f"to test {cat}"
            + (f", restricted to {row.get('param_set')} parameters" if row.get('param_set') else "")
            + "."))
    for row in (data.get("service_tests") or []):
        if not isinstance(row, dict) or not row.get("category"):
            continue
        docs.append((
            f"OWASP service test: {row['category']} ({row.get('tool','curl')})",
            f"Per web service the surface phase runs `{row.get('command')}` "
            f"({row.get('wstg','WSTG')}, safe) to test {row['category']}"
            + (" (TLS only)" if row.get('tls_only') else "") + "."))
    return docs


def _render_safe_service_probes(data: Dict[str, Any]) -> List[Doc]:
    """Safe read-only surface-probe specs -> one doc per (family, probe), so the
    planner can retrieve which safe probe (http_probe/nuclei_detect/dir_enum/
    tls_check/version_probe/banner) the surface phase runs per open service and
    the default command, as knowledge not code."""
    docs: List[Doc] = []
    for fam in (data.get("safe_service_probes") or []):
        if not isinstance(fam, dict) or not fam.get("family"):
            continue
        family = fam["family"]
        services = fam.get("services") or []
        who = "any web service" if "_web_family" in services else (
            ", ".join(str(s) for s in services) if services
            else "any service with no more specific probe")
        for p in (fam.get("probes") or []):
            if not isinstance(p, dict) or not p.get("category"):
                continue
            docs.append((
                f"Safe surface probe: {p['category']} ({p.get('tool','nmap')}) for {family} services",
                f"For an open {who} the surface phase runs the safe read-only probe "
                f"`{p.get('command')}` ({p.get('wstg','WSTG')}) to test {p['category']}"
                + (" (TLS only)" if p.get('tls_only') else "") + "."))
    return docs


def _render_directory_followup(data: Dict[str, Any]) -> List[Doc]:
    """Directory-discovery followup -> docs so the planner can retrieve the method:
    on discovering a directory, run gobuster with a docs/backup wordlist enriched
    by site-harvested (cewl) words, to surface leaked documents/backups a
    link-only crawl walks past."""
    d = data.get("directory_followup")
    if not isinstance(d, dict):
        return []
    exts = ", ".join(str(e) for e in (d.get("extensions") or []))
    srcs = []
    for s in (d.get("wordlist_sources") or []):
        if isinstance(s, dict):
            if s.get("repo_list"): srcs.append("a docs/backup wordlist")
            if s.get("site_corpus"): srcs.append("site-harvested corpus words")
            if s.get("cewl_live") is not None: srcs.append("live cewl words (when installed)")
    return [(
        "Enumeration followup: discovered directory -> docs/backup gobuster (cewl-enriched)",
        "When a directory is discovered (a listing, or a crawled folder URL), a "
        "standard SAFE-lane followup runs gobuster over it with a wordlist built "
        f"from {', '.join(srcs) or 'a docs/backup list'} and the extensions "
        f"[{exts}], to surface leaked documents and backups a link-only crawl "
        "misses. Scope-gated, bounded, tagged as a follow-up "
        f"(scanner='{d.get('followup_tag','dir_followup')}').")]


def _render_default_cred_check(data: Dict[str, Any]) -> List[Doc]:
    """Default-credential check -> a doc so the planner can retrieve the method:
    on a discovered login form, try documented default credentials; auto-fire when
    the candidate count is at/below the setting, else queue for approval; on
    success record the credential and auto-populate an Auth Profile."""
    d = data.get("default_cred_check")
    if not isinstance(d, dict):
        return []
    return [(
        "Enumeration followup: discovered login form -> default-credential check",
        "When a login form is discovered, a standard followup tries documented "
        "default credentials (from default_credentials.yaml + app_login extras). "
        f"It auto-fires on the safe lane when the candidate count is <= "
        f"max_auto_attempts ({d.get('max_auto_attempts')}), and is queued for "
        "operator approval above that; bounded, lockout-aware, scope-gated, tagged "
        f"'{d.get('followup_tag','default_cred_check')}'. On success it records the "
        "working credential and auto-populates an Auth Profile (the on-ramp to "
        "authenticated scanning). CSRF-protected forms are left for manual review.")]


def _render_ajax_spider_signals(data: Dict[str, Any]) -> List[Doc]:
    """Ajax-spider gating -> a doc so the planner can retrieve WHEN to run the
    (expensive) browser spider: only on JS-heavy targets, decided by observed
    signals (XHR endpoint count, SPA framework, websockets), when the operator
    setting zap.ajax_spider is 'auto'."""
    d = data.get("ajax_spider_signals")
    if not isinstance(d, dict):
        return []
    sig = d.get("signals") or {}
    xhr = (sig.get("xhr_endpoints") or {}).get("min_count")
    fw = ", ".join((sig.get("js_frameworks") or {}).get("names") or [])
    return [(
        "Web scan tuning: when to run the ZAP ajax (browser) spider",
        "The ajax spider is expensive and OFF by default; it is enabled only for "
        "JS-heavy / SPA targets, decided by enumeration signals when zap.ajax_spider "
        f"= 'auto': >= {xhr} katana XHR/fetch endpoints, OR an SPA framework "
        f"({fw}), OR any websocket usage. Surfaced as a post-enumeration web_tech "
        "fact (js_heavy). Server-rendered apps stay on the cheaper katana + link "
        "crawl + IDOR probe path. Even when enabled the spider stays bounded "
        "(1-4 browsers, capped crawl states).")]


def _render_business_logic_tests(data: Dict[str, Any]) -> List[Doc]:
    """Business-logic web tests -> a doc so the planner can retrieve the method:
    authenticated probes for object-reference access (IDOR/BOLA incl. POST bodies)
    and business-VALUE tampering (negative amounts / price / qty), driven by
    param-name patterns + tamper value-sets + a response oracle."""
    d = data.get("business_logic_tests")
    if not isinstance(d, dict):
        return []
    vt = ", ".join((d.get("value_tamper") or {}).get("values") or [])
    return [(
        "Business-logic web testing: object-reference access + value tampering",
        "Authenticated probes (single credential, run in the crawl) cover classes "
        "a scanner misses: IDOR/BOLA on GET and POST-body object-reference params "
        "(mutate the id, compare to the owned-value baseline), and WSTG-BUSL-01/03 "
        f"business-value tampering — resubmit monetary/quantity params with values "
        f"[{vt}] and flag a successful (non-validation-error) response to a "
        "negative/zero/oversized value. Object-ref vs value params and the "
        "success/error/blocked oracle are data in business_logic_tests.yaml. "
        "Findings are potential flags for manual triage.")]


def _render_content_discovery(data: Dict[str, Any]) -> List[Doc]:
    """Content-discovery tool selection + custom-attack recipes -> RAG docs so the
    planner/test-synth can (a) know which brute tool is selected and (b) retrieve
    fuzzer-based CUSTOM ATTACK recipes (param discovery/injection, vhost, login
    brute, 403 bypass, subdomain, recursive deep) to construct beyond dir discovery."""
    d = data.get("content_discovery")
    out: List[Doc] = []
    if isinstance(d, dict):
        tools = ", ".join((d.get("tools") or {}).keys())
        out.append((
            "Content discovery: which directory-brute tool runs",
            f"Directory/file discovery uses ONE tool ({tools}); default "
            f"{d.get('default_tool','gobuster')}, overridden by the operator setting "
            f"{d.get('setting_key','content_discovery.tool')}. gobuster~ffuf for a flat "
            "brute; feroxbuster recurses + extracts links (deeper, slower, needs "
            "--filter-size 0). All reuse the persisted authenticated session cookie."))
    # The concrete sources for the {*_wordlist} placeholders. Embedded as its own
    # doc because the recipes tell the planner to "fill the placeholders at run
    # time" and, without this, the only way to fill one was to guess a path — and
    # a path that does not exist makes ffuf exit immediately, which reads as "the
    # attack found nothing" rather than "the attack never ran".
    ws = data.get("wordlist_sources")
    if isinstance(ws, dict) and ws:
        lines = []
        for placeholder, val in ws.items():
            if isinstance(val, dict):
                for kind, paths in val.items():
                    lines.append(f"{{{placeholder}}} for {kind}: " + ", ".join(paths or []))
            elif isinstance(val, list):
                lines.append(f"{{{placeholder}}}: " + ", ".join(val))
        out.append((
            "Content discovery: which wordlist to use for each placeholder",
            "Concrete on-disk sources for the {placeholder} wordlists in the custom "
            "attack recipes, verified present in the kali-listener image. Choose the "
            "payload list by INJECTION CLASS — a SQLi list proves nothing about XSS. "
            + " | ".join(lines)))

    # one doc per custom-attack recipe (data.get at TOP level, sibling of content_discovery)
    for r in (data.get("custom_attacks") or []):
        if not isinstance(r, dict) or not r.get("name"):
            continue
        imp = " (IMPACTFUL — approval-gated)" if r.get("impactful") else ""
        out.append((
            f"Custom attack recipe: {r['name']} ({r.get('tool','ffuf')})",
            f"{r.get('purpose','')}. WSTG {r.get('wstg','')}, fuzz={r.get('fuzz','')}{imp}. "
            f"Command template: {r.get('template','')}. Fill the {{placeholders}} at run "
            "time; a cookie_flag injects the authenticated session."))
    return out


def _render_ad_attacks(data: Dict[str, Any]) -> List[Doc]:
    """Active Directory attack methodology (OCD mindmap) -> one RAG doc per
    technique so the planner / test-synth can retrieve the right AD attack +
    command for the current foothold (no-creds -> user -> DA), with its tool,
    MITRE id, and safe/impactful tier."""
    d = data.get("ad_attacks")
    if not isinstance(d, dict):
        return []
    out: List[Doc] = []
    src = d.get("source", "AD mindmap")
    for ph in (d.get("phases") or []):
        if not isinstance(ph, dict):
            continue
        pname = ph.get("name", ph.get("id", ""))
        for t in (ph.get("techniques") or []):
            if not isinstance(t, dict) or not t.get("name"):
                continue
            tier = t.get("tier", "safe")
            gate = " (IMPACTFUL — approval-gated)" if tier == "impactful" else " (safe/read-only)"
            out.append((
                f"AD attack [{pname}]: {t['name']} ({t.get('tool','')})",
                f"{t.get('note','') or t['name']}. Phase: {pname}. Tool: {t.get('tool','')}, "
                f"MITRE {t.get('mitre','')}, tier={tier}{gate}. Command: {t.get('command','')}. "
                f"Source: {src}. Authorized engagements only."))
    return out


def _render_vuln_class_methodology(data: Dict[str, Any]) -> List[Doc]:
    """Per-vuln-class exploitation methodology -> one retrievable doc per class,
    so the planner can recall "how do I test/exploit an SQLi/SSRF/..." by
    similarity too. The SAME file is read deterministically by-name at exploit
    time via common/vuln_skills.py; this renderer only adds the RAG copy."""
    classes = (data or {}).get("classes")
    if not isinstance(classes, dict):
        return []
    out: List[Doc] = []
    for cid, entry in classes.items():
        if not isinstance(entry, dict):
            continue
        wh = str(entry.get("web_hint") or "").strip()
        sm = str(entry.get("synth_methodology") or "").strip()
        aliases = ", ".join(str(a) for a in (entry.get("aliases") or []))
        out.append((
            f"Exploitation methodology: {cid}",
            f"Vulnerability class '{cid}' (aliases: {aliases}). "
            f"Web testing/exploitation: {wh} Proving impact: {sm}"))
    return out


def _render_common_web_paths(data: Dict[str, Any]) -> List[Doc]:
    """Embed the common-web-paths seed list as ONE doc so retrievers can find
    it when the operator asks "what paths should we probe?". The runtime
    reader (api.load_common_web_paths) still reads the YAML directly for
    speed; the embed is for RAG recall."""
    paths = [p for p in (data.get("common_web_paths") or []) if isinstance(p, str)]
    if not paths:
        return []
    body = ("Common web-path seeds probed by the 404-cluster escalation hook "
            "when a PoC build hits consecutive 404s. These are the paths most "
            "web apps expose; probing them finds the real attack surface when "
            "the LLM is guessing paths that don't exist.\n\n" + "\n".join(paths))
    return [("Common web paths — PoC 404-escalation seeds", body)]


def _render_http_status_fingerprints(data: Dict[str, Any]) -> List[Doc]:
    """Embed each HTTP status tier (404/401/403/500) as a doc so retrievers
    can recall the remediation guidance by status code. api._match_http_status_tier
    reads the YAML directly at verdict time."""
    docs: List[Doc] = []
    for t in (data.get("tiers") or []):
        method = t.get("method")
        rem = (t.get("remediation") or "").strip()
        patterns = t.get("patterns") or []
        if not method:
            continue
        body = (f"PoC verifier tier: {method}\n\n"
                f"Fingerprint patterns (any match triggers the tier):\n  "
                + "\n  ".join(patterns) + "\n\n"
                f"Remediation guidance for refine:\n{rem}")
        docs.append((f"HTTP status cluster — {method}", body))
    return docs


def _render_web_auth_templates(data: Dict[str, Any]) -> List[Doc]:
    """Embed each product's auth-chain template so the build-poc extractor can
    retrieve the SHAPE of a login + anti-CSRF chain for a product by RAG
    lookup rather than the model guessing. The extractor queries
    rag_documents WHERE metadata->>'source'='knowledge' AND title LIKE
    'Web auth template - %s%%' at pre_requests derivation time."""
    docs: List[Doc] = []
    for t in (data.get("templates") or []):
        prod = _s(t.get("product"))
        if not prod:
            continue
        aliases = t.get("aliases") or []
        login = t.get("login_shape") or {}
        csrf_steps = t.get("csrf_shape") or []
        use = t.get("exploit_use") or {}
        import json as _j
        body = (
            f"Product: {prod}  (aliases: {', '.join(aliases) or 'none'})\n\n"
            f"LOGIN step (pre_request #1):\n"
            f"  method: {_s(login.get('method'))}  path: {_s(login.get('path'))}\n"
            f"  content_type: {_s(login.get('content_type'))}\n"
            f"  body_fields: {_j.dumps(login.get('body_fields') or {}, sort_keys=True)}\n"
            f"  captures: {_j.dumps(login.get('captures') or [], sort_keys=True)}\n\n"
            f"CSRF/token step(s) (pre_request #2+):\n"
        )
        for i, step in enumerate(csrf_steps, start=1):
            if step.get("note"):
                body += f"  [{i}] NOTE: {_s(step.get('note'))}\n"
                continue
            body += (
                f"  [{i}] method: {_s(step.get('method'))}  "
                f"path: {_s(step.get('path'))}\n"
                f"      headers: {_j.dumps(step.get('headers') or {}, sort_keys=True)}\n"
                f"      captures: {_j.dumps(step.get('captures') or [], sort_keys=True)}\n"
            )
        body += (
            f"\nEXPLOIT request uses these captured names:\n"
            f"  body_fields: {_j.dumps(use.get('body_fields') or {}, sort_keys=True)}\n"
            f"  headers: {_j.dumps(use.get('headers') or {}, sort_keys=True)}\n\n"
            f"Notes: {_s(t.get('notes'))}"
        )
        docs.append((f"Web auth template - {prod}", body))
    return docs


def _render_app_request_contracts(data: Dict[str, Any]) -> List[Doc]:
    """Embed each app request contract so retrievers + synth can recall the
    KNOWN request shape (action endpoint, method, anti-CSRF param name + token
    source, injection param) instead of the model guessing it. api runtime reads
    the YAML directly via _app_request_contract(); this embed is for RAG recall."""
    docs: List[Doc] = []
    for c in (data.get("contracts") or []):
        prod = _s(c.get("product"))
        if not prod:
            continue
        csrf = c.get("csrf") or {}
        body = (f"Product: {prod}\n"
                f"Action endpoint: {_s(c.get('action_endpoint'))}  "
                f"Method: {_s(c.get('method'))}\n"
                f"Anti-CSRF param: {_s(csrf.get('param')) or '(none)'}  "
                f"(wrong names to avoid: {', '.join(csrf.get('aliases') or []) or 'n/a'})\n"
                f"CSRF token source: {_s(csrf.get('token_source'))}\n"
                f"Injection param: {_s(c.get('injection_param')) or '(varies)'}\n\n"
                f"{_s(c.get('notes'))}")
        docs.append((f"App request contract — {prod}", body))
    return docs


def _render_exploitation_tools(data: Dict[str, Any]) -> List[Doc]:
    """Embed the vuln-class → specialist-tool map so the planner (and the build-
    poc tool-handoff) can recall which tool takes a PoC further (SQLi → sqlmap,
    command-injection → commix, SSTI → tplmap, …)."""
    docs: List[Doc] = []
    for t in (data.get("tools") or []):
        cls = _s(t.get("class"))
        tool = _s(t.get("tool"))
        if not cls or not tool:
            continue
        m = t.get("match") or {}
        body = (f"Vulnerability class: {cls}\nSpecialist tool: {tool} "
                f"(binary: {_s(t.get('binary')) or tool})\n"
                f"Recognized by payload markers: "
                f"{', '.join(m.get('payload_contains') or []) or 'n/a'}\n"
                f"Confirm markers (tool output proves it): "
                f"{', '.join(t.get('confirm_markers') or []) or 'n/a'}\n\n"
                f"{_s(t.get('notes'))}")
        docs.append((f"Exploitation tool — {cls} → {tool}", body))
    return docs


def _render_exploit_building_blocks(data: Dict[str, Any]) -> List[Doc]:
    """Embed the building-block checklist so the challenge (and the planner) can
    recall which lightweight checks validate each piece of an exploit."""
    docs: List[Doc] = []
    for b in (data.get("blocks") or []):
        bid = _s(b.get("id"))
        if not bid:
            continue
        body = (f"Building block: {bid}\nValidates: {_s(b.get('validates'))}\n"
                f"Cost: {_s(b.get('cost'))}\nConfirms: {_s(b.get('confirms'))}\n"
                f"Quick check: {_s(b.get('suggest'))}")
        docs.append((f"Exploit building block — {bid}", body))
    return docs


def _render_cve_exploit_specs(data: Dict[str, Any]) -> List[Doc]:
    """Embed each per-CVE exploit recipe so the planner/build can recall the
    concrete endpoint + vector + payload for a known CVE."""
    docs: List[Doc] = []
    for s in (data.get("specs") or []):
        cve = _s(s.get("cve"))
        if not cve:
            continue
        req = s.get("request") or {}
        inj = s.get("injection") or {}
        body = (f"CVE: {cve}  product: {_s(s.get('product'))}  class: {_s(s.get('vuln_class'))}\n"
                f"Request: {_s(req.get('method'))} {_s(req.get('path'))} "
                f"({_s(req.get('content_type')) or 'n/a'})\n"
                f"Injection payload: {_s(inj.get('payload_template'))}\n\n"
                f"{_s(s.get('notes'))}")
        docs.append((f"CVE exploit spec — {cve}", body))
    return docs


def _render_fact_contradictions(data: Dict[str, Any]) -> List[Doc]:
    """One document per contradiction rule.

    Embedded so the planner can RECALL why a derived fact was challenged —
    `etl/fact_contradictions.py` makes the decision deterministically, this
    makes the reasoning retrievable. The `why` text is the valuable part: each
    rule exists because a real build recorded a wrong fact at high confidence.
    """
    docs: List[Doc] = []
    for r in (data.get("rules") or []):
        if not isinstance(r, dict):
            continue
        rid = r.get("id") or "?"
        title = f"Fact contradiction ({r.get('severity','medium')}): {rid}"
        body = (f"Check `{r.get('check','?')}` flags derived intelligence when: "
                f"{_s(r.get('message'))}. "
                f"Why this rule exists: {_s(r.get('why'))}")
        if r.get("remedy"):
            body += f" What to do instead: {_s(r.get('remedy'))}"
        docs.append((title, " ".join(body.split())))
    return docs


def _render_craft_guidance(data: Dict[str, Any]) -> List[Doc]:
    """One document per class: how to craft it and what proves it.

    The crafter reads this table DETERMINISTICALLY (etl/craft_guidance.py ->
    `_CRAFT_CLASS_GUIDANCE`). Embedding it is the recall half: a planner asking
    "how is an SSRF proven" retrieves the same text the crafter is handed,
    filterable by the `vuln_class` column.
    """
    docs: List[Doc] = []
    for cls, text in ((data or {}).get("guidance") or {}).items():
        t = str(text or "").strip()
        if not t:
            continue
        docs.append((f"Craft guidance: {cls}", t,
                     {"vuln_class": str(cls), "doc_type": "craft_guidance"}))
    return docs


def _render_vuln_classes(data: Dict[str, Any]) -> List[Doc]:
    """One document per vulnerability class.

    Embedded so the planner and the synthesiser can RECALL a class by
    similarity — "the advisory says arbitrary file read, what is that and how
    is it proven" — while `etl/vuln_classes.py` answers the GATES by exact
    lookup. CLAUDE.md requires both and they are not the same mechanism.

    The reference ids (CWE + its official name, OWASP Top 10, WSTG, ATT&CK) go
    in the body so a retrieved document can be reported in whichever
    vocabulary the reader already uses.
    """
    docs: List[Doc] = []
    for c in (data.get("classes") or []):
        if not isinstance(c, dict) or not c.get("name"):
            continue
        name = c["name"]
        title = f"Vulnerability class: {c.get('title') or name} ({name})"
        pts = _s(c.get("injects_via")) or "no injection point"
        body = [f"Also written as: {_s(c.get('aliases')) or '(no aliases)'}.",
                f"Injects via {pts}."]
        if c.get("injects_via") == ["path"]:
            body.append("The URL PATH is the injection point — there is no "
                        "parameter to find, and parameter discovery cannot help.")
        if c.get("file_read"):
            body.append("Can read files from the target.")
        if c.get("needs_oob_sink"):
            body.append("Needs an out-of-band sink to prove.")
        if c.get("blind_capable"):
            body.append("Can be blind — absence of output is not absence of the bug.")
        if c.get("proof"):
            body.append(f"Proven by: {_s(c.get('proof'))}.")
        if c.get("owasp"):
            body.append(f"OWASP Top 10: {_s(c.get('owasp'))}.")
        if c.get("wstg"):
            body.append(f"OWASP WSTG tests: {_s(c.get('wstg'))}.")
        if c.get("mitre"):
            body.append(f"MITRE ATT&CK: {_s(c.get('mitre'))}.")
        if c.get("graded_goals"):
            body.append(f"On a graded target, aims at: {_s(c.get('graded_goals'))}.")
        _rh = c.get("reading_hints") or {}
        if _rh.get("look_for"):
            body.append("Reading a description of this class, look for: "
                        + "; ".join(str(x) for x in _rh["look_for"]) + ".")
        if _rh.get("implies"):
            body.append("What that means: " + "; ".join(str(x) for x in _rh["implies"]) + ".")
        for cw in (c.get("cwes") or []):
            if isinstance(cw, dict) and cw.get("id"):
                body.append(f"{cw['id']}: {_s(cw.get('name'))}.")
        # The keys a PoC build already HOLDS: the CVE's CWE ids, and the class
        # name once classified. Without them this document is reachable only by
        # similarity — the planner cannot ASK for it, so a CWE-89 CVE has no
        # deterministic way to land on the sqli class.
        _cwe_ids = [str(cw.get("id")) for cw in (c.get("cwes") or [])
                    if isinstance(cw, dict) and cw.get("id")]
        docs.append((title, " ".join(" ".join(body).split()),
                     {"vuln_class": name, "cwes": _cwe_ids,
                      "owasp": c.get("owasp"), "class_kind": c.get("kind"),
                      "doc_type": "vuln_class"}))
    return docs


def _render_payload_variants(data: Dict[str, Any]) -> List[Doc]:
    """One document per (class, target-shape) variant, plus the detection rules.

    Embedded so the planner can RECALL "what do I send at an IIS box for a path
    traversal" by similarity; `etl/payload_variants.py` answers the CRAFTER by
    exact lookup. Both are needed and they are not the same mechanism.
    """
    docs: List[Doc] = []
    for cls, entries in (data.get("variants") or {}).items():
        for e in (entries or []):
            if not isinstance(e, dict):
                continue
            shape = " ".join(x for x in (
                ("os " + _s(e.get("os"))) if e.get("os") else "",
                ("runtime " + _s(e.get("runtime"))) if e.get("runtime") else "") if x)
            title = f"Payload variant: {cls} on {shape or 'any target'}"
            body = [f"For a {cls} against {shape or 'any target'}, send: "
                    f"{_s(e.get('payloads'))}."]
            if e.get("proof"):
                body.append("Proven by content only the real result has: "
                            + "; ".join(f"{k} -> /{v}/" for k, v in (e["proof"] or {}).items())
                            + ".")
            if e.get("note"):
                body.append(_s(e.get("note")))
            docs.append((title, " ".join(" ".join(body).split()),
                         {"vuln_class": cls, "doc_type": "payload_variant",
                          "os": e.get("os"), "runtime": e.get("runtime")}))
    for r in (data.get("detection") or []):
        if not isinstance(r, dict):
            continue
        what = " and ".join(x for x in (
            ("os=" + _s(r.get("os"))) if r.get("os") else "",
            ("runtime=" + _s(r.get("runtime"))) if r.get("runtime") else "") if x)
        docs.append((
            f"Target fingerprint: {r.get('id')}",
            " ".join((f"When the {_s(r.get('where'))} "
                      f"{_s(r.get('header')) or ''} matches /{_s(r.get('pattern'))}/, "
                      f"the target is {what}. Confidence tier: "
                      f"{_s(r.get('provenance'))}.").split())))
    return docs


RENDERERS = {
    "app_request_contracts": _render_app_request_contracts,
    "exploitation_tools": _render_exploitation_tools,
    "exploit_building_blocks": _render_exploit_building_blocks,
    "cve_exploit_specs": _render_cve_exploit_specs,
    "common_web_paths": _render_common_web_paths,
    "http_status_fingerprints": _render_http_status_fingerprints,
    "vuln_class_methodology": _render_vuln_class_methodology,
    "msf_learned_options": _render_msf_learned_options,
    "ajax_spider_signals": _render_ajax_spider_signals,
    "business_logic_tests": _render_business_logic_tests,
    "content_discovery": _render_content_discovery,
    "ad_attacks": _render_ad_attacks,
    "safe_service_probes": _render_safe_service_probes,
    "directory_followups": _render_directory_followup,
    "default_cred_check": _render_default_cred_check,
    "msf_readonly_scanners": _render_msf_readonly_scanners,
    "owasp_param_tests": _render_owasp_param_tests,
    "dos_exploit_overrides": _render_dos_exploit_overrides,
    "enumeration_extractors": _render_enumeration_extractors,
    "postex_commands": _render_postex_commands,
    "postex_web": _render_postex_web,
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
    "web_auth_templates": _render_web_auth_templates,
    "fact_contradictions": _render_fact_contradictions,
    "vuln_classes": _render_vuln_classes,
    "craft_guidance": _render_craft_guidance,
    "payload_variants": _render_payload_variants,
}


_TOOL_SERVICE_CACHE = {}


def _services_for_tool(tool: str) -> List[str]:
    """Which services a tool probes, inverted from knowledge/service_tools.yaml.

    Extractor specs are keyed by TOOL and `rag_documents.service` by SERVICE,
    so without this the extractor documents carry no key the search can
    filter on — reachable only by similarity, which is the gap the columns
    were added to close.

    Inverted from the operator-editable catalogue (97 services, 103 tools)
    rather than a second hand-kept map: adding a tool to a service there makes
    its extractor findable by that service on the next sync, no code change.
    """
    if not _TOOL_SERVICE_CACHE:
        try:
            with open(os.path.join(KNOWLEDGE_DIR, "service_tools.yaml"),
                      encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
            for svc, spec in (data.get("services") or {}).items():
                for key in ("tools", "primary", "secondary", "commands"):
                    for t in ((spec or {}).get(key) or []):
                        nm = t if isinstance(t, str) else \
                            (t or {}).get("tool") or (t or {}).get("name")
                        if nm:
                            _TOOL_SERVICE_CACHE.setdefault(
                                str(nm).split()[0].lower(), set()).add(svc)
        except Exception as e:  # noqa: BLE001
            log.warning("tool->service map unavailable: %s", e)
            _TOOL_SERVICE_CACHE["__tried__"] = set()
    return sorted(_TOOL_SERVICE_CACHE.get(str(tool).lower(), ()))


_SERVICE_CATALOGUE: Dict[str, Any] = {}


def _service_catalogue() -> Dict[str, Any]:
    """{"names": {service}, "ports": {port: service}} from service_tools.yaml.

    The same operator-editable catalogue `_services_for_tool` inverts, read the
    other way round: by its own service names and by its port_hints table. A
    service added there becomes derivable here on the next sync with no code
    change — the RAG-first rule applied to the retrieval KEY as well as to the
    text.

    Returns an EMPTY catalogue when the file is unreadable, and logs that it
    did. Nothing resolves then, which is the fail-closed answer: a key that
    could not be derived must not read as a key that does not apply.
    """
    if not _SERVICE_CATALOGUE:
        _SERVICE_CATALOGUE["names"] = set()
        _SERVICE_CATALOGUE["ports"] = {}
        try:
            with open(os.path.join(KNOWLEDGE_DIR, "service_tools.yaml"),
                      encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
            _SERVICE_CATALOGUE["names"] = {
                str(s).lower() for s in (data.get("services") or {})}
            _SERVICE_CATALOGUE["ports"] = {
                str(p): str(s).lower()
                for p, s in (data.get("port_hints") or {}).items() if s}
        except Exception as e:  # noqa: BLE001
            log.warning("service catalogue unavailable: %s", e)
    return _SERVICE_CATALOGUE


def _services_named(text: str) -> List[str]:
    """Which catalogue services a heading names — by whole token, then by port.

    `MySQL/MariaDB (Port 3306)` -> ["mysql"]; `SMB Relay Attacks` -> ["smb"];
    `Microsoft SQL Server (Port 1433)` -> ["mssql"], where no word in the prose
    is a catalogue name but the port is.

    Whole tokens only, never substrings: `Technology Fingerprinting` must not
    match the `finger` service. A NAME beats a PORT because a port is shared —
    `NFS (Port 2049/111)` names nfs and mentions 111, which port_hints calls
    rpc, and taking both would file the phase under a service it never
    discusses.
    """
    cat = _service_catalogue()
    toks = [t for t in re.split(r"[^a-z0-9]+", str(text or "").lower()) if t]
    named = [t for t in toks if t in cat["names"]]
    if named:
        return sorted(set(named))
    return sorted({cat["ports"][t] for t in toks if t in cat["ports"]})


def _render_extractor_spec(data: Dict[str, Any], name: str = "") -> List[Doc]:
    """One document per tool extractor spec.

    What facts a tool's output yields IS "what to do next" knowledge, so
    CLAUDE.md's RAG-first rule applies — but `app/rag-api/extractor_specs.py`
    read these deterministically and nothing embedded them. They were invisible
    to the coverage guard too, because its glob was flat.

    The GATES keep reading the YAML by exact lookup; this is the recall half,
    so an agent can ask "what does feroxbuster output tell me" and get the
    answer without the spec being wired into a prompt by hand.
    """
    tool = str(data.get("tool") or name or "").strip()
    if not tool:
        return []
    desc = str(data.get("description") or "").strip()
    fields = sorted((data.get("deterministic") or {}).keys())
    notable = data.get("notable") or []
    lines = [f"Tool: {tool}"]
    if desc:
        lines.append(desc)
    if fields:
        lines.append("Facts extracted from its output: " + ", ".join(fields))
    for rule in notable:
        if not isinstance(rule, dict):
            continue
        fid = rule.get("finding_type") or rule.get("id") or "finding"
        sev = rule.get("severity") or "info"
        why = str(rule.get("title") or rule.get("message") or "").strip()
        lines.append(f"Notable [{sev}] {fid}: {why}".rstrip(": "))
    prompt = str(data.get("prompt") or "").strip()
    if prompt:
        lines.append("Analyst guidance: " + prompt)
    title = f"Tool output extractor: {tool}"
    # `service` is the key a caller already holds: they just ran a tool
    # against a port whose service is known. One service => the column; several
    # (hydra covers 16) => metadata only, because the column takes ONE value
    # and picking the first would misreport the other fifteen.
    _svcs = _services_for_tool(tool)
    _meta = {"tool": tool, "doc_type": "extractor_spec"}
    if _svcs:
        _meta["services"] = _svcs
        if len(_svcs) == 1:
            _meta["service"] = _svcs[0]
    return [(title, "\n".join(l for l in lines if l), _meta)]


def _playbook_keys(title: str, phase: str,
                   step_titles: List[str]) -> Dict[str, Any]:
    """The retrieval keys a playbook phase can HONESTLY claim.

    76 playbook_phase documents carried none, so they were reachable by
    similarity and never by filter. The rules below are deliberately narrow:
    a wrong key is worse than none, because it makes a document findable under
    a class it does not describe, and the operator has no way to see that the
    key was guessed.

    service — from the phase heading first, else from the playbook title.
        A service scope NESTS: every phase of "SSH Penetration Testing
        Methodology" is ssh work, including the one called
        "Post-Exploitation". Several services named (none today, but
        `MySQL/MariaDB` is one rename away) -> metadata `services` list and NO
        column, the same rule the extractor specs use, because the column
        takes one value and picking the first misreports the rest.

    vuln_class — from the PHASE heading only, never the playbook title, and
        never when the heading also names a service.
        * Not from the title, because a class is a CLAIM and claims do not
          nest the way a scope does. `code-injection` is an alias of `rce`, so
          "Code Injection & Process Injection Techniques" would file all three
          of its phases — CreateRemoteThread, shellcode, APC injection — as
          remote code execution, and a PoC build asking for an RCE playbook
          would be handed Windows process injection.
        * Not when a service is named, because in a service methodology the
          class word belongs to a PRODUCT name. "Microsoft SQL Server (Port
          1433)" resolves to `sqli` on the `sql` alias — the same mistake
          `vuln_classes._strip_locators` fixes for paths, one level up.

    vuln_classes — metadata only, never the column: the classes the phase's
        own STEP titles name. "Manual Testing" names six, "Post-Exploitation"
        names `upload` from one step of two. That is a true statement about
        the steps and a false one about the phase, so it informs a reader
        without ever being filtered on as the phase's subject.
    """
    svcs = _services_named(phase) or _services_named(title)
    out: Dict[str, Any] = {}
    if svcs:
        out["services"] = svcs
        if len(svcs) == 1:
            out["service"] = svcs[0]
    if not svcs:
        r = _vuln_classes.resolve(phase)
        if r.get("basis") == "name" and not r.get("ambiguous") \
                and r.get("class") != _vuln_classes.UNKNOWN:
            out["vuln_class"] = r["class"]
    step_cls = []
    for st in step_titles:
        r = _vuln_classes.resolve(st)
        if r.get("class") != _vuln_classes.UNKNOWN and not r.get("ambiguous") \
                and r["class"] not in step_cls:
            step_cls.append(r["class"])
    if step_cls:
        out["vuln_classes"] = sorted(step_cls)
    return out


def _render_playbook(data: Dict[str, Any], name: str = "") -> List[Doc]:
    """One document per playbook PHASE, not per file.

    A playbook is a long ordered document; embedding it whole gives one
    enormous chunk that matches everything weakly. Per phase keeps each
    document about one thing, which is what similarity search needs.

    `mutates` is carried into the text deliberately: a retrieved step that
    CHANGES the target reads identically to one that only looks, and the
    operator should see which is which before acting on a recalled step.

    The `service` / `vuln_class` keys come from `_playbook_keys`, which states
    what may be derived and what may not.
    """
    pb = str(data.get("title") or data.get("name") or name or "").strip()
    if not pb:
        return []
    docs: List[Doc] = []
    for phase in (data.get("phases") or []):
        if not isinstance(phase, dict):
            continue
        pname = str(phase.get("name") or phase.get("id") or "").strip()
        if not pname:
            continue
        steps = [st for st in (phase.get("steps") or []) if isinstance(st, dict)]
        lines = [f"Playbook: {pb}", f"Phase: {pname}"]
        for st in steps:
            t = str(st.get("title") or st.get("id") or "").strip()
            if not t:
                continue
            bits = [f"  - {t}"]
            if st.get("mutates"):
                bits.append("[MUTATES the target]")
            acc = st.get("access_required")
            if acc and str(acc).lower() != "none":
                bits.append(f"[requires {acc}]")
            lines.append(" ".join(bits))
        if len(lines) <= 2:
            continue
        meta = {"playbook": pb, "phase": pname,
                "doc_type": "playbook_phase",
                # A retrieved step that CHANGES the target reads
                # identically to one that only looks; the operator
                # should be able to filter on that before acting.
                "mutates": any(bool(st.get("mutates")) for st in steps)}
        meta.update(_playbook_keys(
            pb, pname,
            [str(st.get("title") or st.get("id") or "") for st in steps]))
        docs.append((f"Playbook {pb} - {pname}", "\n".join(lines), meta))
    return docs


# Renderers that apply to EVERY file in a knowledge subdirectory, rather than
# to one named top-level file. `sync_all` globs the directory and renders each
# file with the same function, so a new spec or playbook is embedded by being
# added — no registry edit, which is the point of RAG-first knowledge.
DIR_RENDERERS = {
    "extractors": _render_extractor_spec,
    "playbooks": _render_playbook,
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
    if "/" in stem:
        # subdirectory file: one renderer serves the whole directory
        d, base = stem.split("/", 1)
        fn = DIR_RENDERERS.get(d)
        if not fn:
            return []
        try:
            return [d for d in fn(data or {}, base) if d[1] and d[1].strip()]
        except Exception as e:  # noqa: BLE001
            log.warning("renderer for %s failed: %s", stem, e)
            return []
    fn = RENDERERS.get(stem)
    if not fn:
        return []
    try:
        return [d for d in fn(data or {}) if d[1] and d[1].strip()]
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
    # A doc is (title, body) or (title, body, extra_metadata). The third slot
    # is what makes a knowledge row JOINABLE: every row used to carry only
    # {source, kind, file}, so the class/CWE data sat in the BODY text and a
    # PoC build for a CWE-89 CVE could reach the sqli document by similarity
    # alone — never by asking for it. Structured keys (vuln_class, cwes, tool)
    # let a reader FILTER, which is the deterministic half CLAUDE.md wants
    # beside retrieval.
    norm = [(d[0], d[1], (d[2] if len(d) > 2 and isinstance(d[2], dict) else {}))
            for d in docs]
    vectors = _embed([f"{t}\n{b}" for t, b, _ in norm])
    rows = []
    for (title, text, extra), vec in zip(norm, vectors):
        vec_str = "[" + ",".join(repr(float(x)) for x in vec) + "]"
        meta = {"source": source, "kind": "knowledge", "file": f"{stem}.yaml"}
        meta.update({k: v for k, v in (extra or {}).items() if v not in (None, "", [])})
        # vuln_class and cve are COLUMNS, not just metadata keys, so a reader
        # can filter or join on them instead of digging through jsonb. Kept in
        # the metadata too: the jsonb stays the complete record of the doc.
        rows.append((title, text, _ex.Json(meta), vec_str,
                     (extra or {}).get("vuln_class") or None,
                     (extra or {}).get("cve") or None,
                     (extra or {}).get("service") or None))
    _ex.execute_values(
        cur,
        "INSERT INTO rag_documents (title, text_chunk, metadata, embedding,"
        " vuln_class, cve, service) VALUES %s",
        rows, template="(%s, %s, %s, %s::vector, %s, %s, %s)")
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
        stems = [(stem, os.path.join(KNOWLEDGE_DIR, f"{stem}.yaml"))
                 for stem in sorted(RENDERERS)]
        # Subdirectory knowledge: every file in a DIR_RENDERERS directory.
        # Discovered rather than registered, so adding a playbook or an
        # extractor spec embeds it without a code change — the whole point of
        # "new knowledge takes effect by being loaded, not by editing logic".
        for d in sorted(DIR_RENDERERS):
            ddir = os.path.join(KNOWLEDGE_DIR, d)
            if not os.path.isdir(ddir):
                continue
            for fn in sorted(os.listdir(ddir)):
                if not fn.endswith((".yaml", ".yml")) or fn.startswith("_"):
                    continue
                base = fn.rsplit(".", 1)[0]
                stems.append((f"{d}/{base}", os.path.join(ddir, fn)))
        for stem, path in stems:
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
