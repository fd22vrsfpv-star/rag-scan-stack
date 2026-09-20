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


RENDERERS = {
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
