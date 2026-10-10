"""LangGraph refactor of `_build_poc_core` (in api.py).

Why this module exists: the build-poc pipeline in api.py grew to ~300 lines of hand-
wired conditionals (10 recon phases + hints + auth + research + strategist + plan
verifier + synth + refine loop + verify guards + save). New signals we add (like the
next feature — mining every response for bypass clues) risk being lost between phases
because every consumer reads from ONE hand-composed guidance string.

This module makes state explicit: every node reads from and writes to a `BuildPocState`
dict. Nodes are the existing helpers in api.py (called via lazy import to avoid a
circular dep — api.py imports this module). The final `guidance` string handed to
synth is composed by a dedicated `assemble_guidance` node using the SAME concatenation
order and formatting as today's code — parity-tested byte-for-byte.

Rollout: `BUILD_POC_LANGGRAPH` env flag (default off). When on, `_build_poc_core`
calls `invoke_build_poc(state)`; when off, the existing monolith runs unchanged.
"""

from __future__ import annotations

import logging
import operator
import os
import time
from typing import Annotated, Any, Dict, List, Optional, TypedDict


# ── state ──────────────────────────────────────────────────────────────────────
class BuildPocState(TypedDict, total=False):
    # Immutable inputs (set at graph start; never mutated by nodes)
    cve: str
    ip: str
    port: int
    product: Optional[str]
    version: Optional[str]
    eid: Optional[str]
    max_iters: int
    model: Optional[str]
    research: bool
    recon_first: bool
    recon_source: str
    hint: Optional[str]
    run_id: str
    t0: float

    # Recon accumulators — each recon node appends into these. `segments` is the
    # ordered list of guidance strings; `assemble_guidance` joins them into the
    # final string handed to synth. Every accumulator uses operator.add so the
    # graph runtime merges concurrent-node contributions correctly (we're
    # sequential today but this keeps the door open for a fan-out later).
    segments: Annotated[List[str], operator.add]
    recon_metrics: Dict[str, Dict[str, Any]]
    intel_list: List[Dict[str, Any]]
    zap_paths: List[str]
    arjun_discovered: List[str]       # arjun's live-found URLs for the focused ZAP active scan
    focused_urls: List[str]           # operator-supplied URLs (BuildPocBody.focused_urls)
    precond_result: Dict[str, Any]    # resolved/confirmed/unmet from precondition enumeration
    access_inventory: Dict[str, Any]  # objects enumerated post-login (hosts, scripts, users…)
    tool_handoff: Dict[str, Any]      # derived specialist tool(s) + test result (sqlmap…)
    readiness_blocked: bool           # strict-gate: hard blocker → skip the run-refine loop
    readiness_blockers: List[str]     # why it was blocked (for the result)
    gather_blocked: bool              # strict gather check: required facts missing → skip synth + refine
    deep_recon_done: bool             # one deeper-recon pass per run (gaps / early stop)
    deep_recon: Dict[str, Any]        # what the pass ran and found
    gather_manifest: Dict[str, Any]   # the manifest (items/missing/follow_ups/facts) for the result
    cred_hints: List[str]
    admin_paths_mined: List[str]
    detected_frameworks: List[str]
    waf_family: Optional[str]
    waf_characterization: Dict[str, Any]

    # Hint / auth / research
    auth: Dict[str, Any]
    auth_guidance: str
    session_info: Optional[Dict[str, Any]]
    hint_guidance: str
    hint_parts: List[str]
    research_out: Optional[Dict[str, Any]]

    # Strategy / synth
    recon_guidance: str
    strategy: str
    plan_verdicts: Dict[str, str]
    id_pool: Dict[str, Any]           # ids seen in recon/enumeration, for templated paths
    guidance: str
    guidance_base: str                # pre-gather guidance; pass 2 composes from this, not from pass 1's output
    built: Optional[Dict[str, Any]]

    # Refine loop state
    command: str
    assertion: Dict[str, Any]
    canary: Optional[str]
    origin_family: Optional[tuple]
    llm_model: Optional[str]
    output: str
    success: bool
    drifted: bool
    iters: int
    escalated: bool
    escalation_guidance: str
    metrics: Dict[str, Any]

    # Cross-round command dedup: signatures from the first run_refine pass
    # survive into the second pass (after deep_recon go-around) so the dup
    # detector catches round 2 re-synthesizing a command that already failed
    # in round 1.
    prior_cmd_signatures: List[str]

    # Final verdict
    verified: bool
    reflection: bool
    off_target: bool
    exploit_store_id: Optional[str]
    result: Dict[str, Any]
    failure_analysis: Dict[str, Any]   # end-of-attempt analysis (unverified runs); also persisted to build_poc_attempts


def enabled() -> bool:
    """True when the LangGraph build path should be used. Env-flag default off."""
    return os.environ.get("BUILD_POC_LANGGRAPH", "0").lower() in ("1", "true", "yes", "on")


def initial_state(cve: str, ip: str, port: int, product=None, version=None, eid=None,
                  max_iters: int = 3, research: bool = True, model=None, auth=None,
                  recon_first: bool = False, recon_source: str = "basic",
                  hint: Optional[str] = None,
                  focused_urls: Optional[List[str]] = None) -> BuildPocState:
    """Build the initial state dict handed to the graph. Mirrors the argument shape
    of _build_poc_core so the wrapper is trivial."""
    # Supplied credentials are the FIRST cred_hint so node_auto_login logs in
    # before the ZAP/Playwright/Arjun recon runs (authenticated crawl), not only
    # at node_auth_establish afterwards (analysis 2026-10-09, fix #2).
    _supplied = []
    if auth and auth.get("username") and auth.get("password"):
        _supplied = [f"{auth['username']}:{auth['password']}"]
    return {
        "cve": cve, "ip": ip, "port": port,
        "product": product, "version": version, "eid": eid,
        "max_iters": max_iters, "model": model, "research": research,
        "recon_first": recon_first, "recon_source": recon_source, "hint": hint,
        "run_id": f"{cve}_{ip}_{int(time.time())}",
        "t0": time.time(),
        "segments": [], "recon_metrics": {}, "intel_list": [],
        "zap_paths": [], "arjun_discovered": [], "focused_urls": list(focused_urls or []),
        "cred_hints": _supplied, "admin_paths_mined": [],
        "detected_frameworks": [], "waf_family": None, "waf_characterization": {},
        "auth": auth or {}, "auth_guidance": "", "session_info": None,
        "hint_guidance": "", "hint_parts": [], "research_out": None,
        "recon_guidance": "", "strategy": "", "plan_verdicts": {}, "guidance": "", "guidance_base": "",
        "built": None,
        "command": "", "assertion": {}, "canary": None, "origin_family": None,
        "llm_model": None, "output": "",
        "success": False, "drifted": False, "iters": 0, "escalated": False,
        "escalation_guidance": "", "metrics": {},
        "verified": False, "reflection": False, "off_target": False,
        "exploit_store_id": None, "result": {}, "failure_analysis": {},
    }


# ── source-flag helpers (mirror the monolith exactly) ─────────────────────────
def _want(sources: str, kind: str) -> bool:
    """Reproduce the monolith's want_basic/want_arjun/want_zap logic exactly so
    conditional edges branch on the same rule the monolith used."""
    s = str(sources or "basic").lower()
    if kind == "basic":  return ("basic" in s) or (s in ("both", "full", "params"))
    if kind == "arjun":  return ("arjun" in s) or (s in ("params", "full"))
    if kind == "zap":    return ("zap" in s) or (s == "full")
    if kind == "active": return "active" in s
    return False


# ── recon nodes ────────────────────────────────────────────────────────────────
# Each node is (state) -> partial-state-update dict. Nodes read the target/config
# from state, call the existing helper in api.py (lazy import to break the cycle),
# emit the same _poc_trace phase the monolith emitted, and return the pieces to
# fold into state via the TypedDict reducers.

def node_port_sweep(state: BuildPocState) -> Dict[str, Any]:
    from api import _scout_open_ports, _poc_trace
    _t0 = time.time()
    ps = _scout_open_ports(state["ip"], state["port"])
    metrics = {"port_sweep": {"seconds": round(time.time() - _t0, 2),
                              "chars_added": len(ps or ""),
                              "signal": "open-port list + banners"}}
    seg = []
    if ps:
        seg.append(ps)
        _poc_trace(state["run_id"], "recon:port_sweep", response=ps[:1200])
    return {"segments": seg, "recon_metrics": {**state.get("recon_metrics", {}), **metrics}}


def node_waf_detect(state: BuildPocState) -> Dict[str, Any]:
    from api import _scout_waf, _poc_trace
    import re as _re
    _t0 = time.time()
    waf_line = _scout_waf(state["ip"], state["port"])
    metrics = {"waf": {"seconds": round(time.time() - _t0, 2),
                       "chars_added": len(waf_line or ""),
                       "signal": "WAF fingerprint + evasion family"}}
    seg = []
    waf_family = None
    if waf_line:
        seg.append(waf_line)
        _poc_trace(state["run_id"], "recon:waf", response=waf_line[:1200])
        m = _re.search(r"WAF FAMILY:\s*([a-z_]+)", waf_line)
        if m:
            waf_family = m.group(1)
    return {"segments": seg, "waf_family": waf_family,
            "recon_metrics": {**state.get("recon_metrics", {}), **metrics}}


def node_waf_characterize(state: BuildPocState) -> Dict[str, Any]:
    from api import _characterize_waf, _poc_trace
    fam = state.get("waf_family")
    if not fam:
        return {}
    _t0 = time.time()
    try:
        char_line, char_data = _characterize_waf(state["ip"], state["port"], fam)
    except Exception:  # noqa: BLE001
        char_line, char_data = "", {}
    metrics = {"waf_characterize": {"seconds": round(time.time() - _t0, 2),
                                    "chars_added": len(char_line or ""),
                                    "signal": "proven-passable evasion variants (empirical)"}}
    seg = []
    if char_line:
        seg.append(char_line)
        _poc_trace(state["run_id"], "recon:waf_characterize",
                   response=char_line[:1500],
                   extra={"proven": char_data.get("proven", {})})
    return {"segments": seg, "waf_characterization": char_data,
            "recon_metrics": {**state.get("recon_metrics", {}), **metrics}}


def node_basic_recon(state: BuildPocState) -> Dict[str, Any]:
    from api import _scout_url_recon, _poc_trace
    _t0 = time.time()
    b = _scout_url_recon(state["ip"], state["port"])
    metrics = {"basic": {"seconds": round(time.time() - _t0, 2),
                         "chars_added": len(b or ""),
                         "signal": "landing page HREFs + forms + robots"}}
    seg = []
    if b:
        seg.append(b)
        _poc_trace(state["run_id"], "recon:basic", response=b[:1200])
    # Lab-only (2026-10-07): if the challenge's own source is on disk, read its
    # routes + request field names and put them ahead of everything else the
    # strategist sees. CVE-2024-34359's target documented its two routes in
    # 40 lines of Flask; recon never looked and 50 iterations hit the wrong
    # path. Fail-soft; no-op when no local source dir exists.
    try:
        from api import _local_source_routes
        ls = _local_source_routes(state["cve"])
        if ls.get("found"):
            if ls.get("text"):
                seg.insert(0, ls["text"])
            _poc_trace(state["run_id"], "recon:local_source", response=(ls.get("text") or "")[:1500],
                       extra={"dir": ls.get("dir"), "routes": ls.get("routes"), "fields": ls.get("fields"),
                              "files": ls.get("files")})
            metrics["local_source"] = {"routes": len(ls.get("routes") or []),
                                       "fields": len(ls.get("fields") or []),
                                       "signal": "literal routes + request fields from target source on disk"}
    except Exception as _lse:  # noqa: BLE001
        _poc_trace(state["run_id"], "recon:local_source", response=f"(skipped: {type(_lse).__name__}: {_lse})")
    return {"segments": seg,
            "recon_metrics": {**state.get("recon_metrics", {}), **metrics}}


def node_product_identification(state: BuildPocState) -> Dict[str, Any]:
    """EARLY product/version identification — runs right after basic_recon so
    the rest of the pipeline (discovered-knowledge recall, research, synth)
    knows WHAT it's attacking. Fingerprints the product + version from the
    live HTML/headers, extracts plausible release dates, and BACK-FILLS
    state.product / state.version when the build was invoked without them
    (cve+ip+port only). When a product is identified and the build has a
    real CVE, also kicks the AI deep-dive research early so advisory +
    public-PoC intel is available to synth instead of discovered late.

    Operator ask: 'a skill to help review the content for the product, even
    looking through the html, pull possible dates for versions, and kick off
    the ai deep dive — earlier in the process, right after scans and recon.'
    """
    from api import _identify_product_from_target, _poc_trace
    _t0 = time.time()
    had_product = bool(state.get("product"))
    # Only run the (slower) deep dive when we DON'T already have research in
    # hand and the build carries a real CVE to research.
    want_deep = (bool(state.get("research", True))
                 and bool(state.get("cve"))
                 and not str(state.get("cve", "")).startswith("NOCVE-"))
    info = _identify_product_from_target(
        state["ip"], state["port"],
        run_deep_dive=want_deep,
        cve=state.get("cve"), eid=state.get("eid"), model=state.get("model"))
    upd: Dict[str, Any] = {}
    seg = []
    if info.get("product") and not had_product:
        upd["product"] = info["product"]
        if info.get("version") and not state.get("version"):
            upd["version"] = info["version"]
    # Build a guidance segment describing what we identified.
    bits = []
    if info.get("product"):
        v = f" {info['version']}" if info.get("version") else ""
        conf = info.get("version_confidence", 0)
        bits.append(f"Identified product: {info['product']}{v} "
                    f"(version confidence {conf}).")
    if info.get("secondary_products"):
        sp = "; ".join(
            f"{s['product']}{(' ' + s['version']) if s.get('version') else ''}"
            f" ({s.get('source','')})"
            for s in info["secondary_products"])
        bits.append("Secondary products (own attack surface — web server / "
                    "language runtime / extra frameworks): " + sp
                    + ". Consider their CVEs too if the primary app proves hard.")
    if info.get("dates"):
        bits.append("Release-era dates found: " + ", ".join(info["dates"])
                    + " — use these to rule out implausible version lines.")
    if info.get("evidence"):
        bits.append("Fingerprint evidence: " + info["evidence"])
    # Persist secondary products as discovered facts so they're reusable
    # (keyed under the primary product or the cve fallback).
    try:
        from api import _ensure_discovered_app_knowledge_table, get_db
        import json as _json
        sp_list = info.get("secondary_products") or []
        if sp_list:
            _ensure_discovered_app_knowledge_table()
            pkey = (state.get("product") or info.get("product")
                    or (f"cve:{state.get('cve')}" if state.get("cve") else None))
            if pkey:
                with get_db() as _c, _c.cursor() as _cur:
                    for s in sp_list:
                        _cur.execute("""
                            INSERT INTO public.discovered_app_knowledge
                                (product, version, fact_type, fact_value,
                                 confidence, discovered_from, source_run_id,
                                 engagement_id)
                            VALUES (%s,%s,'secondary_product',%s,0.7,%s,%s,%s)
                        """, (pkey, state.get("version"),
                              f"{s['product']}"
                              + (f" {s['version']}" if s.get('version') else "")
                              + f" (via {s.get('source','')})",
                              state.get("cve"), state["run_id"],
                              state.get("eid")))
                    _c.commit()
    except Exception as _spe:  # noqa: BLE001
        logging.debug("secondary product persist failed: %s", _spe)
    # Fold the early deep-dive analysis into guidance + research_out so synth
    # and the research node reuse it instead of re-fetching.
    deep = info.get("deep_dive")
    if deep and isinstance(deep, dict):
        analysis = deep.get("analysis") or {}
        if analysis.get("summary"):
            bits.append("EARLY DEEP-DIVE (AI research, pre-synth): "
                        + str(analysis["summary"])[:600])
        upd["research_out"] = deep  # research node will see it's already done
    if bits:
        g = "\n".join(bits)
        seg.append(g)
        _poc_trace(state["run_id"], "recon:product_identification",
                   response=g[:1600],
                   extra={"product": info.get("product"),
                          "version": info.get("version"),
                          "dates": info.get("dates"),
                          "backfilled": not had_product and bool(info.get("product")),
                          "deep_dive_fired": bool(deep)})
    metrics = {"product_identification": {
        "seconds": round(time.time() - _t0, 2),
        "chars_added": len("\n".join(bits)),
        "signal": f"product={info.get('product')} version={info.get('version')}"}}
    upd["segments"] = seg
    upd["recon_metrics"] = {**state.get("recon_metrics", {}), **metrics}
    return upd


def node_product_cve_enumeration(state: BuildPocState) -> Dict[str, Any]:
    """Per-product CVE-enumeration loop. Operator ask: 'for each product/
    plugin discovered, have a separate loop added to the LangGraph — but
    start with product specifics first.'

    Processing ORDER (product specifics first):
      1. PRIMARY product (the identified app + version) — the thing the
         build is actually about; its version-specific CVEs lead.
      2. SECONDARY products (web server, language runtime) — own CVE surface.
      3. PLUGINS / extensions — each its own product.

    For each, runs _enumerate_cves_for_product which writes matched CVEs to
    follow_up_items (rule_id='software_known_cve'). Those flow into
    /software/cves-without-poc and become one-click Build-PoC candidates —
    so every discovered product gets its OWN exploit path without blocking
    this build. This node ENUMERATES; it does not fan out 30-iter builds
    inline (that would be unbounded). The per-product builds are queued as
    candidates the operator / auto-approve path turns into real builds.
    """
    from api import (_identify_product_from_target, _enumerate_cves_for_product,
                     _poc_trace)
    _t0 = time.time()
    # Reuse identification already done by node_product_identification when
    # possible; otherwise identify now.
    primary = state.get("product")
    primary_ver = state.get("version")
    # Pull the full identification (secondary + plugins) — cheap, cached HTML
    info = {}
    try:
        info = _identify_product_from_target(state["ip"], state["port"],
                                              run_deep_dive=False)
    except Exception as e:  # noqa: BLE001
        logging.debug("product enumeration identify failed: %s", e)
    # Build the ordered work list: primary first, then secondary, then plugins.
    targets = []
    if primary:
        targets.append({"product": primary, "version": primary_ver, "tier": "primary"})
    elif info.get("product"):
        targets.append({"product": info["product"], "version": info.get("version"),
                        "tier": "primary"})
    for s in info.get("secondary_products") or []:
        targets.append({"product": s["product"], "version": s.get("version"),
                        "tier": "secondary"})
    for p in info.get("plugins") or []:
        targets.append({"product": p["product"], "version": p.get("version"),
                        "tier": f"plugin:{p.get('kind','')}"})
    results = []
    seg = []
    for t in targets[:12]:  # bound the fan-out
        try:
            r = _enumerate_cves_for_product(
                t["product"], t.get("version"),
                store_as_followup=True, ip=state["ip"], eid=state.get("eid"))
            r["tier"] = t["tier"]
            results.append(r)
            if r["cve_ids"]:
                seg.append(f"{t['tier']} {t['product']}"
                           + (f" {t['version']}" if t.get('version') else "")
                           + f": known CVEs {', '.join(r['cve_ids'][:8])}")
        except Exception as e:  # noqa: BLE001
            logging.debug("enumerate %s failed: %s", t.get("product"), e)
    if seg:
        g = ("Per-product CVE enumeration (each is a separate Build-PoC "
             "candidate in cves-without-poc; product specifics first):\n  "
             + "\n  ".join(seg))
        _poc_trace(state["run_id"], "recon:product_cve_enumeration",
                   response=g[:1600],
                   extra={"products_enumerated": len(results),
                          "total_cves": sum(len(r["cve_ids"]) for r in results)})
        seg = [g]
    metrics = {"product_cve_enum": {
        "seconds": round(time.time() - _t0, 2),
        "chars_added": len(seg[0]) if seg else 0,
        "signal": f"{len(results)} products, "
                   f"{sum(len(r['cve_ids']) for r in results)} CVEs queued"}}
    return {"segments": seg,
            "recon_metrics": {**state.get("recon_metrics", {}), **metrics}}


def node_response_mine(state: BuildPocState) -> Dict[str, Any]:
    from api import _scout_response_mine, _poc_trace
    _t0 = time.time()
    try:
        mine_line, intel_list = _scout_response_mine(state["ip"], state["port"])
    except Exception:  # noqa: BLE001
        mine_line, intel_list = "", []
    metrics = {"response_mine": {"seconds": round(time.time() - _t0, 2),
                                 "chars_added": len(mine_line or ""),
                                 "signal": "headers/cookies/comments/errors/hidden inputs/info-disclosure"}}
    seg = []
    if mine_line:
        seg.append(mine_line)
        _poc_trace(state["run_id"], "recon:response_mine", response=mine_line[:1500])
    # Extract cred_hints, admin_paths_mined, detected_frameworks — same logic as monolith
    cred_hints = []
    admin_paths = []
    for x in intel_list:
        cred_hints.extend(x.get("credential_hints", []) or [])
        admin_paths.extend(x.get("admin_paths", []) or [])
    # Supplied pair (seeded by initial_state) stays first; mined ones follow.
    cred_hints = list(dict.fromkeys(list(state.get("cred_hints") or []) + cred_hints))
    admin_paths = list(dict.fromkeys(admin_paths))
    detected_frameworks = list(dict.fromkeys(
        x.get("framework") for x in intel_list if x.get("framework")))
    # Embed curated observed facts into rag_documents (Option 2). No-op when the
    # RAG_OBSERVED_FACTS flag is off. Best-effort — failure here doesn't affect
    # the response-mine output the rest of the pipeline uses.
    try:
        from api import _embed_response_mine_intel
        prod = detected_frameworks[0] if detected_frameworks else None
        _embed_response_mine_intel(state["ip"], intel_list,
                                    engagement_id=state.get("eid"), product=prod)
    except Exception:  # noqa: BLE001
        pass
    return {"segments": seg,
            "intel_list": intel_list,
            "cred_hints": cred_hints,
            "admin_paths_mined": admin_paths,
            "detected_frameworks": detected_frameworks,
            "recon_metrics": {**state.get("recon_metrics", {}), **metrics}}


def node_auto_login(state: BuildPocState) -> Dict[str, Any]:
    from api import _try_mined_credentials, _poc_trace
    cred_hints = state.get("cred_hints") or []
    if not cred_hints:
        return {}
    _t0 = time.time()
    try:
        login = _try_mined_credentials(state["ip"], state["port"],
                                        cred_hints, state.get("admin_paths_mined") or [])
    except Exception:  # noqa: BLE001
        login = None
    metrics = {"auto_login": {"seconds": round(time.time() - _t0, 2),
                              "chars_added": 0,
                              "signal": "auto-login attempt with mined credentials"}}
    seg = []
    auth = dict(state.get("auth") or {})
    if login and login.get("cookie_header"):
        _a = state.get("auth") or {}
        _src = ("supplied" if (_a.get("username") and _a.get("password")
                               and login.get("cred") == f"{_a['username']}:{_a['password']}") else "mined")
        note = (f"AUTO-LOGIN SUCCESS with {_src} creds {login['cred']} at "
                f"{login['path']} (fields {login['u_field']}/"
                f"{login['p_field']}, signal={login['signal']}). "
                f"Session cookie: {login['cookie_header'][:200]}. "
                "Synth: send this Cookie header on every exploit request.")
        seg.append(note)
        _poc_trace(state["run_id"], "recon:auto_login",
                   response=note[:1200],
                   extra={"path": login["path"], "cred": login["cred"]})
        auth.setdefault("_auto_cookie", login["cookie_header"])
        auth.setdefault("_auto_login_path", login["path"])
        metrics["auto_login"]["chars_added"] = len(note)
    elif login and login.get("skipped"):
        note = (f"AUTO-LOGIN SKIPPED: {login['reason']}. "
                f"Captcha-guarded paths: {login.get('captcha_paths', [])}. "
                f"Mined credentials {cred_hints[:3]} available — operator "
                "should log in manually and add the session cookie as an "
                "operator hint, or seed a bypass technique.")
        seg.append(note)
        _poc_trace(state["run_id"], "recon:auto_login",
                   response=note[:1200],
                   extra={"skipped": True, "captcha_paths": login.get("captcha_paths")})
        metrics["auto_login"]["chars_added"] = len(note)
    else:
        _poc_trace(state["run_id"], "recon:auto_login",
                   response=f"tried {len(cred_hints)} cred(s) × candidate paths — no working login")
    return {"segments": seg, "auth": auth,
            "recon_metrics": {**state.get("recon_metrics", {}), **metrics}}


def node_framework_deep_enum(state: BuildPocState) -> Dict[str, Any]:
    from api import _deep_enum_framework, _poc_trace
    frameworks = state.get("detected_frameworks") or []
    if not frameworks:
        return {}
    seg = []
    metrics = {}
    for fw in frameworks[:2]:  # cap at 2, matches monolith
        _t0 = time.time()
        try:
            fw_line = _deep_enum_framework(state["ip"], state["port"], fw, state.get("intel_list"))
        except Exception:  # noqa: BLE001
            fw_line = ""
        metrics[f"deep_enum:{fw}"] = {"seconds": round(time.time() - _t0, 2),
                                       "chars_added": len(fw_line or ""),
                                       "signal": f"{fw}-specific known-CVE-bearing paths"}
        if fw_line:
            seg.append(fw_line)
            _poc_trace(state["run_id"], f"recon:deep_enum:{fw}", response=fw_line[:1200])
    return {"segments": seg,
            "recon_metrics": {**state.get("recon_metrics", {}), **metrics}}


def node_zap_recon(state: BuildPocState) -> Dict[str, Any]:
    from api import _zap_recon, _extract_zap_paths, _poc_trace
    _t0 = time.time()
    active = _want(state.get("recon_source", "basic"), "active")
    z = _zap_recon(state["ip"], state["port"], active_scan=active)
    key = "zap_active" if active else "zap"
    metrics = {key: {"seconds": round(time.time() - _t0, 2),
                     "chars_added": len(z or ""),
                     "signal": ("spider + passive + active scan"
                                if active else "spider + passive alerts")}}
    seg = []
    zap_paths = []
    if z:
        seg.append(z)
        _poc_trace(state["run_id"], "recon:zap" + ("_active" if active else ""),
                   response=z[:1200])
        zap_paths = _extract_zap_paths(z)
    return {"segments": seg, "zap_paths": zap_paths,
            "recon_metrics": {**state.get("recon_metrics", {}), **metrics}}


def node_discovered_knowledge_recon(state: BuildPocState) -> Dict[str, Any]:
    """Pull previously-discovered app facts for this (product, version) so
    iter 1 starts with knowledge from past builds instead of rediscovering.
    Zero-cost DB read; empty when no prior builds for this product."""
    from api import _recon_discovered_knowledge, _poc_trace
    _t0 = time.time()
    g = _recon_discovered_knowledge(state.get("product"), state.get("version"))
    metrics = {"discovered_knowledge": {
        "seconds": round(time.time() - _t0, 2),
        "chars_added": len(g or ""),
        "signal": "prior-build facts for this product"
                   if g else "no prior facts recorded for this product"}}
    seg = []
    if g:
        seg.append(g)
        _poc_trace(state["run_id"], "recon:discovered_knowledge",
                   response=g[:1600])
    return {"segments": seg,
            "recon_metrics": {**state.get("recon_metrics", {}), **metrics}}


def node_openapi_recon(state: BuildPocState) -> Dict[str, Any]:
    """Probe common OpenAPI/Swagger paths and parse the first spec we find.
    When present, this is the REAL attack surface for API-first apps the
    HTML spider can't see (SPAs, FastAPI, Prefect, Zabbix, etc.). Discovered
    endpoints feed synth guidance + the escalation's focused ZAP active
    scan via arjun_discovered."""
    from api import _openapi_discover, _poc_trace
    _t0 = time.time()
    guidance, api_urls = _openapi_discover(state["ip"], state["port"],
                                           auth=state.get("auth"))
    metrics = {"openapi": {"seconds": round(time.time() - _t0, 2),
                           "chars_added": len(guidance or ""),
                           "signal": "machine-readable API surface"
                                     if api_urls else "no OpenAPI spec published"}}
    seg = []
    if guidance:
        seg.append(guidance)
        _poc_trace(state["run_id"], "recon:openapi", response=guidance[:1600])
    # Merge discovered API URLs into arjun_discovered so the focused active
    # scan escalation attacks them specifically (not just the HTML spider's
    # static-chunk haul).
    merged_arjun = list(state.get("arjun_discovered") or [])
    for u in api_urls:
        if u and u not in merged_arjun:
            merged_arjun.append(u)
    return {"segments": seg,
            "arjun_discovered": merged_arjun,
            "recon_metrics": {**state.get("recon_metrics", {}), **metrics}}


def node_playwright_recon(state: BuildPocState) -> Dict[str, Any]:
    """Headless-browser crawl when ZAP spider only turned up static assets
    (classic SPA problem). Logs in (when auth supplied), navigates, captures
    the XHR URLs the SPA fires — discovers the real app routes. Discovered
    URLs feed synth guidance + the focused active scan via arjun_discovered.
    Skipped when the HTML spider already found rich dynamic surface."""
    from api import _playwright_sitemap, _poc_trace
    # Heuristic: ZAP spider saw mostly static chunks → SPA → run Playwright.
    # Also run when ZAP found nothing at all (dead spider).
    zap_paths = state.get("zap_paths") or []
    static_markers = ("_next", "/static/", "/chunks/", "/assets/", "/dist/", ".js", ".css", ".map")
    static_count = sum(1 for p in zap_paths if any(m in p for m in static_markers))
    is_spa = (len(zap_paths) == 0) or (static_count / max(1, len(zap_paths)) > 0.5)
    if not is_spa:
        return {}
    _t0 = time.time()
    guidance, discovered = _playwright_sitemap(state["ip"], state["port"],
                                                auth=state.get("auth"))
    metrics = {"playwright": {"seconds": round(time.time() - _t0, 2),
                              "chars_added": len(guidance or ""),
                              "signal": "SPA XHR routes + JS-rendered links"
                                        if discovered else "playwright found nothing"}}
    seg = []
    if guidance:
        seg.append(guidance)
        _poc_trace(state["run_id"], "recon:playwright", response=guidance[:4000])
    merged_arjun = list(state.get("arjun_discovered") or [])
    for u in discovered:
        if u and u not in merged_arjun:
            merged_arjun.append(u)
    return {"segments": seg,
            "arjun_discovered": merged_arjun,
            "recon_metrics": {**state.get("recon_metrics", {}), **metrics}}


def node_arjun_recon(state: BuildPocState) -> Dict[str, Any]:
    from api import _scout_arjun, _scout_arjun_paths, _poc_trace
    _t0 = time.time()
    zap_paths = state.get("zap_paths") or []
    arjun_discovered: List[str] = []
    scheme = "https" if int(state.get("port") or 80) in (443, 8443) else "http"
    host_prefix = f"{scheme}://{state['ip']}:{state.get('port') or 80}"
    if zap_paths:
        a, per_path = _scout_arjun_paths(state["ip"], state["port"], zap_paths)
        signal = f"honored params per endpoint (fanned across {len(per_path)} paths)"
        # Each arjun-attacked path becomes a focused-active-scan candidate.
        # per_path maps path -> list of params; a path landing in per_path
        # means arjun actually probed it (even if 0 params honored).
        for p in (per_path or {}).keys():
            if p: arjun_discovered.append(host_prefix + (p if p.startswith("/") else "/" + p))
    else:
        a = _scout_arjun(state["ip"], state["port"])
        signal = "honored param names (single URL, no zap paths)"
    metrics = {"arjun": {"seconds": round(time.time() - _t0, 2),
                         "chars_added": len(a or ""),
                         "signal": signal}}
    seg = []
    if a:
        seg.append(a)
        _poc_trace(state["run_id"], "recon:arjun", response=a[:1400])
    return {"segments": seg,
            "arjun_discovered": arjun_discovered,
            "recon_metrics": {**state.get("recon_metrics", {}), **metrics}}


# ── auth / hints / research ────────────────────────────────────────────────────
def node_auth_establish(state: BuildPocState) -> Dict[str, Any]:
    """Establish an authenticated session when the operator supplied creds OR when
    auto_login already captured a cookie. Matches the monolith exactly."""
    from api import _establish_session_for_build, _poc_trace
    auth = state.get("auth") or {}
    auth_guidance = ""
    session_info = None
    if auth and (auth.get("username") or auth.get("bruteforce")):
        try:
            session_info = _establish_session_for_build(
                state["ip"], state["port"], auth, state.get("eid"),
                product=state.get("product"), segments=state.get("segments") or [])
            ch = (session_info or {}).get("cookie_header")
            if ch:
                auth_guidance = (f"AUTH: an authenticated session exists — send this cookie in "
                                 f"EVERY exploit request: Cookie: {ch}. (user "
                                 f"{session_info.get('username')}). ")
            _poc_trace(state["run_id"], "recon:auth_establish",
                       response=f"method={(session_info or {}).get('method')} ok={bool(ch)} "
                                f"user={(session_info or {}).get('username')} "
                                f"note={str((session_info or {}).get('note') or '')[:300]}",
                       extra={"auth_ok": bool(ch), "auth_method": (session_info or {}).get("method"),
                              "login_url": (session_info or {}).get("login_url")})
            if not ch:
                # A failed attempt used to be returned as a session_info with
                # cookie_header="" — downstream "session exists" checks were
                # fooled. Keep it None; the trace above records the attempt.
                session_info = None
        except Exception as e:  # noqa: BLE001
            logging.debug("build auth step failed: %s", e)
            _poc_trace(state["run_id"], "recon:auth_establish",
                       response=f"error {type(e).__name__}: {str(e)[:300]}",
                       extra={"auth_ok": False, "auth_method": "error"})
            session_info = None
    if auth and auth.get("_auto_cookie") and not auth_guidance:
        auth_guidance = (f"AUTH (auto-login from mined creds): send this cookie in EVERY "
                         f"exploit request: Cookie: {auth['_auto_cookie']}. "
                         f"Logged in at {auth.get('_auto_login_path', '?')} with the supplied "
                         "or mined credentials — the app is now AUTHENTICATED, target the "
                         "admin backend for post-auth CVEs.")
    return {"auth_guidance": auth_guidance, "session_info": session_info}


def node_load_hints(state: BuildPocState) -> Dict[str, Any]:
    from api import _load_hints_for, _poc_trace
    hint_parts = []
    if state.get("hint") and str(state["hint"]).strip():
        hint_parts.append(str(state["hint"]).strip())
    persistent = _load_hints_for(state["cve"], state["ip"], state["port"])
    if persistent:
        hint_parts.append(persistent)
    hint_guidance = ""
    if hint_parts:
        hint_guidance = ("OPERATOR HINT (authoritative — follow this exactly, "
                         "it overrides any conflicting recon/research): "
                         + " | ".join(hint_parts) + ". ")
        _poc_trace(state["run_id"], "operator_hint",
                   response=f"applied {len(hint_parts)} hint(s): "
                            + " | ".join(hp[:200] for hp in hint_parts))
    return {"hint_guidance": hint_guidance, "hint_parts": hint_parts}


def node_access_enumeration(state: BuildPocState) -> Dict[str, Any]:
    """BASIC post-access enumeration — runs right after auth is established.
    Once we have a confirmed session, inventory WHAT that access gives us
    (hosts, scripts, users, dashboards, datasources…) app-aware. The result
    feeds the precondition check + synth + is persisted to confirmed_facts so
    every attack and the operator see the foothold's reach. Operator ask:
    'that should have been a basic step to enumerate available info after
    confirming access.'"""
    from api import _enumerate_access_inventory, _poc_trace
    si = state.get("session_info") or {}
    cookie = si.get("cookie_header") if isinstance(si, dict) else None
    auth = state.get("auth") or {}
    # Only enumerate when we actually have access (a session or creds).
    if not cookie and not (auth.get("username") and auth.get("password")):
        return {}
    _t0 = time.time()
    try:
        inv = _enumerate_access_inventory(
            state["ip"], state["port"], product=state.get("product"),
            auth=auth, session_cookie=cookie)
    except Exception as e:  # noqa: BLE001
        logging.debug("access enumeration node failed: %s", e)
        return {}
    if not inv:
        return {}
    bits = ["POST-ACCESS INVENTORY (objects this authenticated account can use "
            "— USE these real ids, don't invent):"]
    for otype, items in inv.items():
        sample = ", ".join(f"{it['id']}({it.get('name','')})" if it.get('name') else str(it['id'])
                           for it in items[:8])
        bits.append(f"  - {otype}: {sample}")
    g = "\n".join(bits)
    _poc_trace(state["run_id"], "recon:access_enumeration", response=g[:1600],
               extra={"object_types": list(inv.keys()),
                      "counts": {k: len(v) for k, v in inv.items()}})
    return {"segments": [g],
            "access_inventory": inv,
            "recon_metrics": {**state.get("recon_metrics", {}),
                              "access_enum": {"seconds": round(time.time() - _t0, 2),
                                              "chars_added": len(g),
                                              "signal": f"{sum(len(v) for v in inv.values())} objects"}}}


def node_precondition_enumeration(state: BuildPocState) -> Dict[str, Any]:
    """FIND-FIRST precondition enumeration. Operator ask: 'did we confirm
    access to a host to run a script? that should be an enumeration step —
    this should be a step to find first.'

    Runs after auth + research (so we have both an authenticated session AND
    the advisory-derived preconditions) but BEFORE synth — so the exploit is
    built with VERIFIED, concrete prerequisite values (a real hostid the user
    can operate on) instead of invented ones. If a precondition can't be met
    (e.g. the account has no host access), that's surfaced to synth too so it
    doesn't waste iterations on an impossible path."""
    from api import _enumerate_exploit_preconditions, _poc_trace
    research_out = state.get("research_out") or {}
    analysis = research_out.get("analysis") if isinstance(research_out, dict) else None
    if not analysis:
        return {}  # nothing to resolve without research preconditions
    session_info = state.get("session_info") or {}
    cookie = session_info.get("cookie_header") if isinstance(session_info, dict) else None
    if not cookie:
        # auto-login cookie fallback
        auth = state.get("auth") or {}
        cookie = auth.get("_auto_cookie")
    _t0 = time.time()
    try:
        pre = _enumerate_exploit_preconditions(
            state["ip"], state["port"], analysis, session_cookie=cookie,
            product=state.get("product"), auth=state.get("auth"),
            access_inventory=state.get("access_inventory"))
    except Exception as e:  # noqa: BLE001
        logging.debug("precondition enumeration node failed: %s", e)
        return {}
    # Stash the structured result so the readiness gate can judge it without
    # re-enumerating.
    _precond_result = pre
    seg = []
    if pre.get("guidance"):
        seg.append(pre["guidance"])
        _poc_trace(state["run_id"], "recon:precondition_enumeration",
                   response=pre["guidance"][:1600],
                   extra={"resolved": pre.get("resolved"),
                          "confirmed_count": len(pre.get("confirmed") or []),
                          "unmet_count": len(pre.get("unmet") or [])})
    metrics = {"precondition_enum": {
        "seconds": round(time.time() - _t0, 2),
        "chars_added": len(pre.get("guidance") or ""),
        "signal": f"resolved={list((pre.get('resolved') or {}).keys())} "
                   f"unmet={len(pre.get('unmet') or [])}"}}
    return {"segments": seg,
            "precond_result": _precond_result,
            "recon_metrics": {**state.get("recon_metrics", {}), **metrics}}


def node_readiness_gate(state: BuildPocState) -> Dict[str, Any]:
    """CHALLENGE SKILL — the readiness gate. After preconditions are enumerated
    (and session validated), review whether ALL the pieces are actually in
    hand before the run-refine loop hammers iterations. Operator ask: 'a
    challenge skill to review and check for preconditions to ensure all the
    pieces are available before hammering away on incomplete data.'

    Behaviour (env BUILD_POC_PRECONDITION_GATE: strict|warn|off, default warn):
      - strict: a HARD blocker (dead session on an auth-required exploit,
        unreachable target) sets state.readiness_blocked so run_refine
        short-circuits with a BLOCKED result instead of looping.
      - warn (default): never blocks the loop, but injects the blockers
        prominently into synth guidance so the LLM/operator sees what's
        missing — and records the verdict in metrics + trace.
      - off: skip entirely.
    """
    mode = (os.environ.get("BUILD_POC_PRECONDITION_GATE", "warn") or "warn").lower()
    if mode == "off":
        return {}
    from api import _assess_exploit_readiness, _poc_trace
    research_out = state.get("research_out") or {}
    analysis = research_out.get("analysis") if isinstance(research_out, dict) else None
    # precond result was folded into segments; re-derive the structured bits
    # by re-running the lightweight assess with what state carries.
    _t0 = time.time()
    try:
        # Vendor-doc validation is a slow (DDG+fetch+LLM) rigor add-on — run it
        # only in strict mode (operator opted into max rigor). The deterministic
        # checks (session probe, endpoint existence, version-in-advisory,
        # reachability, enumerated ids) already enforce "no assumptions" fast.
        # Reuse the advisory already gathered by the research/deep-dive node so
        # the version check doesn't re-fetch it.
        _ro = state.get("research_out") or {}
        _adv = ""
        if isinstance(_ro, dict):
            _adv = (_ro.get("advisory_text")
                    or (_ro.get("sources") or {}).get("advisory_text") or "")
        rd = _assess_exploit_readiness(
            state["ip"], state["port"], analysis or {},
            session_info=state.get("session_info"),
            precond_result=state.get("precond_result"),
            product=state.get("product"), model=state.get("model"),
            version=state.get("version"), cve=state.get("cve"),
            validate_vendor_docs=(mode == "strict"),
            advisory_text=_adv,
            access_inventory=state.get("access_inventory"),
            llm_challenge=(mode == "strict"))
    except Exception as e:  # noqa: BLE001
        logging.debug("readiness gate failed: %s", e)
        return {}
    seg = []
    guidance = ""
    if rd.get("blockers"):
        guidance = ("EXPLOIT READINESS CHALLENGE — the following preconditions "
                    "are NOT satisfied; resolve them or the exploit cannot "
                    "land:\n  - " + "\n  - ".join(rd["blockers"]))
        if rd.get("satisfied"):
            guidance += ("\nAlready satisfied:\n  - " + "\n  - ".join(rd["satisfied"]))
        seg.append(guidance)
    # BUILD-IN-PIECES: walk the lightweight building-block checklist — run the
    # cheap checks that aren't confirmed yet, and SUGGEST the heavier ones — so
    # synth assembles the exploit from verified parts. Operator: "suggest quick
    # and easy checks to validate specific items ... if they are lightweight."
    try:
        from api import _run_challenge_checks
        _si = state.get("session_info") or {}
        _blocks = _run_challenge_checks(
            state["ip"], state["port"], state.get("product"), analysis or {},
            auth=state.get("auth"),
            session_cookie=(_si.get("cookie_header") if isinstance(_si, dict) else None),
            run_lightweight=True, advisory_text=_adv)
        if _blocks.get("guidance"):
            seg.append(_blocks["guidance"])
            _poc_trace(state["run_id"], "challenge_building_blocks",
                       response=_blocks["guidance"][:1200],
                       extra={"confirmed": [b["id"] for b in _blocks.get("confirmed", [])],
                              "missing": [b["id"] for b in _blocks.get("missing", [])]})
    except Exception as e:  # noqa: BLE001
        logging.debug("building-block checks failed: %s", e)
    _poc_trace(state["run_id"], "readiness_gate",
               response=(guidance or "all preconditions satisfied")[:1200],
               extra={"ready": rd.get("ready"), "hard_blocked": rd.get("hard_blocked"),
                      "score": rd.get("score"), "blockers": rd.get("blockers"),
                      "mode": mode})
    upd = {"segments": seg,
           "recon_metrics": {**state.get("recon_metrics", {}),
                             "readiness": {"seconds": round(time.time() - _t0, 2),
                                           "chars_added": len(guidance),
                                           "signal": f"ready={rd.get('ready')} "
                                                     f"blockers={len(rd.get('blockers') or [])}"}}}
    # Strict mode: a hard blocker short-circuits the loop.
    if mode == "strict" and rd.get("hard_blocked"):
        upd["readiness_blocked"] = True
        upd["readiness_blockers"] = rd.get("blockers")
    return upd


def node_research(state: BuildPocState) -> Dict[str, Any]:
    """Fetch reference-PoC material from MSF/ExploitDB/NVD. Returns the analysis
    dict but does NOT compose the guidance string — that's assemble_guidance's job.

    After the research is in hand, run the AGENT-DRIVEN SPEC DERIVATION pipeline
    (operator ask: "the agent should do the work, not have you create hints"):
    fetch patch commit diffs → LLM extracts a structured recipe → LIVE-VERIFY on
    the target → fuzz-fallback → persist the VERIFIED spec in derived_cve_specs.
    The spec then flows into node_synth via _cve_exploit_spec() so the loop
    STARTS from an assembled, confirmed exploit."""
    if not state.get("research"):
        return {"research_out": None}
    # If the early product-identification node already ran the deep-dive
    # research (research_out populated), reuse it — don't pay for a second
    # identical _research_exploit call.
    research_out = state.get("research_out")
    if not research_out:
        from api import _research_exploit
        try:
            research_out = _research_exploit(
                state["cve"], state["ip"], state["port"],
                state.get("product"), state.get("version"), state.get("eid"),
                model=state.get("model"))
        except Exception as e:  # noqa: BLE001
            logging.debug("build research step failed: %s", e)
            research_out = None
    # Agent-driven spec derivation. Skip if a hand-curated YAML spec already exists
    # or env BUILD_POC_AUTO_DERIVE=off.
    if (os.environ.get("BUILD_POC_AUTO_DERIVE", "on") or "on").lower() != "off":
        try:
            from api import _cve_exploit_spec, _derive_cve_spec, _poc_trace, _load_cve_exploit_specs
            # Only auto-derive when the YAML has NO entry for this CVE.
            cu = str(state["cve"]).upper()
            yaml_hit = any(str(s.get("cve", "")).upper() == cu
                           for s in _load_cve_exploit_specs())
            if not yaml_hit:
                derived = _derive_cve_spec(
                    state["cve"], state.get("product"), state.get("version"),
                    state["ip"], state["port"], model=state.get("model"),
                    auth=state.get("auth"), engagement_id=state.get("eid"))
                _poc_trace(state["run_id"], "cve_spec_derivation",
                           response=f"verified={derived.get('verified')} "
                                    f"source={derived.get('source')} "
                                    f"evidence={(derived.get('evidence') or '')[:200]}",
                           extra={"verified": derived.get("verified"),
                                  "source": derived.get("source")})
        except Exception as e:  # noqa: BLE001
            logging.debug("spec derivation failed: %s", e)
    return {"research_out": research_out}


# ── guidance assembly (parity-critical) ────────────────────────────────────────
def node_assemble_guidance(state: BuildPocState) -> Dict[str, Any]:
    """Compose the final `guidance` string handed to synth. This is the ONE place
    the concatenation order is defined; parity with the monolith is verified
    byte-for-byte in test_build_poc_graph.py::test_guidance_parity.

    Monolith order (line-by-line reproduction of api.py:16058-16101):
      1. recon_guidance = " ".join(segments)
      2. guidance = hint + (recon_guidance + " " + auth_guidance).strip()  if recon else hint + auth
      3. if research: guidance = (auth_guidance + " " + " ".join(research_parts)).strip()
    """
    recon_guidance = " ".join(state.get("segments") or [])
    hint_guidance = state.get("hint_guidance") or ""
    auth_guidance = state.get("auth_guidance") or ""
    if recon_guidance:
        guidance = hint_guidance + (recon_guidance + " " + auth_guidance).strip()
    else:
        guidance = hint_guidance + auth_guidance
    # Research overrides — same as monolith: when research_out is present, rebuild
    # guidance from (auth_guidance + " " + " ".join(research_parts)).strip()
    research_out = state.get("research_out")
    if state.get("research") and research_out:
        a = research_out.get("analysis") or {}
        src = research_out.get("sources") or {}
        parts = []
        if a:
            parts.append("Reference exploit analysis (use this concrete material, adapt to the "
                         f"target): summary={a.get('summary')}; endpoint={a.get('target_endpoint')}; "
                         f"method={a.get('http_method')}; params={a.get('params')}; "
                         f"payload={a.get('payload')}; success_signal={a.get('success_signal')}."
                         + (f" Seed command to adapt: {a.get('seed_command')}" if a.get('seed_command') else ""))
        if src.get("msf"):
            parts.append(f"Metasploit module(s) for this CVE: {', '.join([m for m in src['msf'] if m])}.")
        ref = research_out.get("reference_poc")
        if ref:
            parts.append("Public ExploitDB PoC (adapt the request/payload to the target):\n"
                         + str(ref)[:3500])
        # CRITICAL: keep the challenge/recon segments. recon_guidance carries the
        # challenge output — resolved preconditions, confirmed building blocks,
        # the probed injection vector, the known request contract, research-on-
        # assumption — which are VERIFIED facts for THIS target. The research
        # override used to drop them (it predates the challenge nodes), so none of
        # that reached synth on a research run. Lead with the verified facts, then
        # the generic reference material.
        guidance = (auth_guidance + " " + recon_guidance + " " + " ".join(parts)).strip()
    return {"recon_guidance": recon_guidance, "guidance": guidance}


# ── strategist + plan verifier ─────────────────────────────────────────────────
def node_strategist(state: BuildPocState) -> Dict[str, Any]:
    from api import _recon_strategist
    if not (state.get("recon_guidance") or state.get("hint_guidance") or state.get("research_out")):
        return {"strategy": ""}
    try:
        strategy = _recon_strategist(
            state["cve"], state.get("product"), state.get("version"),
            recon_guidance=state.get("recon_guidance"),
            hint_guidance=state.get("hint_guidance"),
            research_analysis=(state.get("research_out") or {}).get("analysis")
                              if state.get("research") else None,
            model=state.get("model"), run_id=state["run_id"])
    except Exception as e:  # noqa: BLE001
        logging.debug("recon strategist skipped: %s", e)
        strategy = ""
    return {"strategy": strategy}


def node_plan_verify(state: BuildPocState) -> Dict[str, Any]:
    from api import _verify_strategist_plan, _poc_trace, _collect_id_pool
    strategy = state.get("strategy") or ""
    if not strategy:
        return {}
    try:
        _auto_cookie = (state.get("auth") or {}).get("_auto_cookie")
        # ids already seen (recon text, enumeration output) resolve templated
        # paths like /dtale/test-filter/{data_id} before they are probed
        _ids = _collect_id_pool(" ".join(state.get("segments") or [])[:30000],
                                state.get("access_inventory"), state.get("precond_result"))
        strategy_verified, verdicts = _verify_strategist_plan(
            state["ip"], state["port"], strategy, session_cookie=_auto_cookie, id_pool=_ids)
        if verdicts:
            _poc_trace(state["run_id"], "recon:plan_verified",
                       response=f"verdicts: {verdicts}",
                       extra={"verdicts": verdicts})
            strategy = strategy_verified
    except Exception as e:  # noqa: BLE001
        logging.debug("plan verification skipped: %s", e)
        verdicts = {}
    # Prepend verified strategy to guidance — same rule the monolith uses
    guidance = state.get("guidance") or ""
    if strategy:
        guidance = strategy + " " + guidance
    return {"strategy": strategy, "plan_verdicts": verdicts, "guidance": guidance, "id_pool": _ids if strategy else {}}


def node_gather_check(state: BuildPocState) -> Dict[str, Any]:
    """2026-10-07 (operator ask): "make sure everything is actually gathered
    and ready before creating a payload." Runs after plan_verify (LIVE/FAKE
    verdicts exist) and before synth. Strict by default
    (BUILD_POC_GATHER_CHECK=strict|warn|off): a missing REQUIRED item halts
    the run with the manifest + follow-ups as the result instead of letting
    synth guess. warn: inject the manifest into guidance and continue. The
    manifest's confirmed facts (endpoint/method/field) are injected into
    guidance in every mode so synth crafts against verified facts."""
    from api import (_gather_manifest, _gather_manifest_text, _record_gather_manifest,
                     _BUILD_POC_GATHER_CHECK, _poc_trace)
    mode = _BUILD_POC_GATHER_CHECK
    if mode == "off":
        return {}
    try:
        man = _gather_manifest(
            state["cve"], state["ip"], state["port"], state.get("product"), state.get("version"),
            state.get("eid"), plan_text=state.get("strategy") or "",
            plan_verdicts=state.get("plan_verdicts") or {},
            session_info=state.get("session_info"), auth=state.get("auth"),
            analysis=((state.get("research_out") or {}).get("analysis")
                      if isinstance(state.get("research_out"), dict) else None),
            recon_text=" ".join(state.get("segments") or [])[:20000],
            run_id=state["run_id"], id_pool=state.get("id_pool") or {},
            segments=list(state.get("segments") or []))
    except Exception as e:  # noqa: BLE001
        _poc_trace(state["run_id"], "gather_check", response=f"(skipped: {type(e).__name__}: {e})")
        return {}
    if state.get("deep_recon"):
        # second pass after deep recon: carry what was tried + the proposed
        # solutions into the manifest so the follow-up row answers "what do I
        # need" AND "what could get it" (operator ask 2026-10-07)
        dr = state.get("deep_recon") or {}
        man["deep_recon"] = {k: v for k, v in dr.items() if k in ("ran", "seconds", "skipped", "solutions")}
        if dr.get("solutions"):
            man["follow_ups"] = (man.get("follow_ups") or []) + [
                f"[{g}] " + "; ".join(x.get("solution", "") for x in (v or [])[:3])
                for g, v in dr["solutions"].items() if g in (man.get("missing") or [])]
    rec = _record_gather_manifest(man, state["cve"], state["ip"], state["port"],
                                  eid=state.get("eid"), run_id=state["run_id"])
    # Pass 2 (after deep_recon) must not prepend a second manifest onto pass 1's
    # output: compose from the pre-gather guidance captured on pass 1.
    base = state.get("guidance_base") if state.get("guidance_base") else (state.get("guidance") or "")
    guidance = (_gather_manifest_text(man) + "\n" + base).strip()
    upd: Dict[str, Any] = {"guidance": guidance, "guidance_base": base,
                           "gather_manifest": {**man, "follow_up_id": rec.get("follow_up_id")},
                           "recon_metrics": {**state.get("recon_metrics", {}),
                                             "gather_check": {"ready": man.get("ready"),
                                                              "missing": man.get("missing"),
                                                              "signal": man.get("summary")}}}
    if mode == "strict" and not man.get("ready"):
        upd["gather_blocked"] = True
    return upd


def node_deep_recon(state: BuildPocState) -> Dict[str, Any]:
    """2026-10-07 (operator ask): when the gather check leaves gaps, or the run
    stops at 0 / early iterations without success, run a deeper recon and a
    broader set of scans targeted at the gaps (default-credential check +
    limited spray, authenticated crawl, access inventory, ZAP spider, arjun,
    verb sweep), then go around ONCE more: gather_check → synth → run_refine."""
    from api import _deep_recon_for_gaps, _poc_trace
    man = state.get("gather_manifest") or {}
    res = _deep_recon_for_gaps(
        state["cve"], state["ip"], state["port"], state.get("product"), state.get("eid"), state["run_id"], man,
        auth=state.get("auth"), session_info=state.get("session_info"),
        cred_hints=state.get("cred_hints"), admin_paths=state.get("admin_paths_mined"),
        recon_text=" ".join(state.get("segments") or [])[:30000], id_pool=state.get("id_pool") or {})
    _poc_trace(state["run_id"], "deep_recon",
               response=f"ran={res.get('ran')} ids={list((res.get('id_pool') or {}).keys())[:8]} "
                        f"paths={len(res.get('candidate_paths') or [])} session={bool((res.get('auth') or {}).get('_auto_cookie'))} "
                        f"seconds={res.get('seconds')} skipped={res.get('skipped')}",
               extra={"deep_recon": {k: v for k, v in res.items() if k != "segments"}})
    from api import _BUILD_POC_SECOND_PASS_ITERS
    upd: Dict[str, Any] = {"deep_recon_done": True, "deep_recon": {k: v for k, v in res.items() if k != "segments"},
                           # the go-around is a SECOND chance, not a second budget (round 11: 50 more iterations)
                           "max_iters": min(int(state.get("max_iters") or 0) or _BUILD_POC_SECOND_PASS_ITERS, _BUILD_POC_SECOND_PASS_ITERS),
                           "segments": res.get("segments") or [],
                           "id_pool": {**(state.get("id_pool") or {}), **(res.get("id_pool") or {})},
                           "gather_blocked": False,
                           "recon_metrics": {**state.get("recon_metrics", {}),
                                             "deep_recon": {"seconds": res.get("seconds"), "steps": res.get("ran"),
                                                            "signal": "deeper recon after a gap / early stop"}}}
    if res.get("auth"):
        upd["auth"] = res["auth"]
    if res.get("session_info"):
        upd["session_info"] = res["session_info"]
    return upd


# ── synth + run-refine loop ────────────────────────────────────────────────────
def node_synth(state: BuildPocState) -> Dict[str, Any]:
    # Route through the shadow wrapper (B rollout). Legacy result is returned
    # unchanged; when BUILD_POC_DECOMPOSED is shadow/on the decomposed synth
    # also runs and both land in build_poc_shadow_runs. Fix 2026-10-07: the
    # overnight batch recorded ZERO synthesize rows because this LangGraph
    # node bypassed the wrapper — the only wired call site was a different
    # flow. See CHANGES_MADE.
    from api import (_synthesize_cve_poc_with_shadow, _assemble_confirmed_poc_command,
                     _assemble_from_cve_spec, _poc_trace)
    if state.get("gather_blocked"):
        man = state.get("gather_manifest") or {}
        _poc_trace(state["run_id"], "synth_skipped_gather_incomplete", response=man.get("summary"))
        return {"built": {"command": "# gather_incomplete — " + (man.get("summary") or ""),
                          "assertion": {}, "synth_kind": "gather_incomplete",
                          "gather_blocked": True, "gather_manifest": man,
                          "canary": None, "metrics": {}}}
    built = _synthesize_cve_poc_with_shadow(
        state["cve"], state["ip"], state["port"],
        state.get("product"), state.get("version"), state.get("eid"),
        run_id=state["run_id"], guidance_extra=state.get("guidance") or "",
        model=state.get("model"))
    # ENHANCEMENT 1: seed the loop with a command auto-assembled from a KNOWN
    # recipe. Precedence: a per-CVE exploit spec (endpoint+vector+payload, for
    # unauth web CVEs) first, then a command built from confirmed-probe facts.
    try:
        asm = _assemble_from_cve_spec(state["cve"], state["ip"], state["port"],
                                      built.get("canary"))
        if not (asm and asm.get("command")):
            asm = _assemble_confirmed_poc_command(
                state["ip"], state["port"], state.get("product"),
                built.get("canary"), auth=state.get("auth"))
        if asm and asm.get("command"):
            _poc_trace(state["run_id"], "synth_seeded_from_confirmed",
                       response=asm["command"][:600],
                       extra={"origin": asm.get("origin"), "assertion": asm.get("assertion")})
            built = {**built, "command": asm["command"], "assertion": asm["assertion"],
                     "origin_family": None}
    except Exception as e:  # noqa: BLE001
        logging.debug("confirmed-command assembly failed: %s", e)
    return {"built": built,
            "command": built["command"], "assertion": built["assertion"],
            "canary": built.get("canary"), "origin_family": built.get("origin_family"),
            "llm_model": built.get("llm_model"),
            "metrics": built.get("metrics") or {}}


def node_run_refine(state: BuildPocState) -> Dict[str, Any]:
    """Bundles the run-refine loop as a single node. The monolith's _run_refine_poc
    is a tight for-loop with internal drift/precondition/waf-block/escalation
    branches — decomposing it into cyclic-edge nodes doubles the code without
    making the flow more debuggable (each iteration is one HTTP call to the
    listener; branches all fire from the same output). Keeping it as one node
    body preserves the exact same behaviour and every internal _poc_trace still
    fires from inside _run_refine_poc.
    Recon-source-used is threaded in so the zap-active escalation knows whether
    zap-active already ran as primary recon."""
    from api import _run_refine_poc, _poc_trace, _gather_manifest_text
    # Readiness short-circuit (strict gate): a hard precondition blocker means
    # the exploit cannot land no matter how many iterations we run. Refuse to
    # hammer — return a BLOCKED result naming what's missing so the operator
    # resolves it (fix login, grant host access) rather than burning the loop.
    if state.get("readiness_blocked"):
        blockers = state.get("readiness_blockers") or []
        _poc_trace(state["run_id"], "run_refine_skipped_blocked",
                   extra={"blockers": blockers})
        return {"result": {"ok": True, "success": False, "verified": False,
                           "blocked": True, "blockers": blockers,
                           "reason": "readiness gate: preconditions not met — "
                                     + "; ".join(blockers),
                           "iterations": 0, "metrics": state.get("built", {}).get("metrics") or {}},
                "verified": False, "success": False, "iters": 0,
                "off_target": False, "reflection": False}
    built = state.get("built") or {}
    if state.get("gather_blocked") or built.get("gather_blocked"):
        man = state.get("gather_manifest") or built.get("gather_manifest") or {}
        _poc_trace(state["run_id"], "run_refine_skipped_gather_incomplete",
                   response=man.get("summary"), extra={"missing": man.get("missing"),
                                                      "follow_up_id": man.get("follow_up_id")})
        return {"result": {"ok": True, "success": False, "verified": False, "blocked": True,
                           "verification_method": "gather_incomplete",
                           "gather_manifest": man, "follow_up_id": man.get("follow_up_id"),
                           "reason": "gather check (strict): " + (man.get("summary") or "required facts missing"),
                           "iterations": 0, "metrics": built.get("metrics") or {}},
                "verified": False, "success": False, "iters": 0,
                "off_target": False, "reflection": False}
    # 2026-10-07: synth halted because the sink is fed by a FILE the operator
    # must supply (artifact_required). Nothing to refine — return the
    # requirements + follow-ups as the run's result instead of 50 iterations.
    if built.get("artifact_required"):
        req = built.get("artifact_requirements") or {}
        _poc_trace(state["run_id"], "run_refine_skipped_artifact_required",
                   response=req.get("summary"), extra={"artifact_requirements": req,
                                                       "follow_up_id": built.get("follow_up_id")})
        return {"result": {"ok": True, "success": False, "verified": False, "blocked": True,
                           "verification_method": "artifact_required",
                           "artifact_required": True, "artifact_requirements": req,
                           "follow_up_id": built.get("follow_up_id"),
                           "reason": "artifact required: " + (req.get("summary") or "see artifact_requirements"),
                           "iterations": 0, "metrics": built.get("metrics") or {}},
                "verified": False, "success": False, "iters": 0,
                "off_target": False, "reflection": False}
    result = _run_refine_poc(
        state["cve"], state["ip"], state["port"],
        built["command"], built["assertion"], state.get("eid"),
        state["run_id"], rationale=built.get("rationale", ""),
        product=state.get("product"), version=state.get("version"),
        max_iters=state["max_iters"],
        canary=built.get("canary"), origin_family=built.get("origin_family"),
        llm_model=built.get("llm_model"),
        model=state.get("model"),
        recon_source_used=state.get("recon_source"),
        # Hand arjun's live findings + any operator-supplied focused URLs
        # (BuildPocBody.focused_urls) to the escalation path, which runs a
        # per-URL ZAP active scan on them in addition to the generic
        # host-level scan. Catches URLs ZAP's own spider would never reach.
        arjun_discovered=state.get("arjun_discovered"),
        focused_urls_from_body=state.get("focused_urls"),
        gather_facts=(_gather_manifest_text(state["gather_manifest"]) if state.get("gather_manifest") else None),
        metrics={**(built.get("metrics") or {}),
                 "_session_cookie_header": ((state.get("session_info") or {}).get("cookie_header")
                                            or (state.get("auth") or {}).get("_auto_cookie") or "")},
        # Resolved object-ids from the login's post-access inventory /
        # precondition enumeration — enforced into every command so the model
        # can't substitute an invented id for one the login actually proved.
        resolved_ids=(state.get("precond_result") or {}).get("resolved"),
        prior_cmd_signatures=state.get("prior_cmd_signatures"))
    return {"result": result,
            "verified": bool(result.get("verified")),
            "reflection": bool(result.get("reflection")),
            "off_target": bool(result.get("off_target")),
            "iters": int(result.get("iterations", 0)),
            "success": bool(result.get("success")),
            "prior_cmd_signatures": result.get("cmd_signatures") or []}


def node_failure_analysis(state: BuildPocState) -> Dict[str, Any]:
    """End-of-attempt analysis, fired exactly once at the true end of every run
    (after run_refine, after any deep-recon go-around, before save_store) with
    the full state in hand. Verified runs get an attempts row only; unverified
    runs get the deterministic analysis + one routed LLM narrative, persisted
    to build_poc_attempts, traced, filed as a follow-up and emitted as a
    webhook. Operator ask 2026-10-09: "when an attempt fails at the end conduct
    an analysis and save this information so that it can be added to the
    markdown file for manual review, or viewed in the poc summary attempt".
    Whole body is fail-soft — it must never block save_store."""
    from api import (_build_failure_analysis, _failure_analysis_llm, _record_build_poc_attempt,
                     _poc_trace, _poc_run_file)
    result = state.get("result") or {}
    run_id = state["run_id"]
    log_path = result.get("log_path") or _poc_run_file(run_id)
    man = state.get("gather_manifest") or result.get("gather_manifest") or {}
    live = (man.get("facts") or {}).get("live_recon") if isinstance(man, dict) else None
    try:
        if result.get("verified"):
            _record_build_poc_attempt(
                run_id=run_id, cve=state["cve"], ip=state["ip"], port=state.get("port"), eid=state.get("eid"),
                verified=True, stage_reached="verified", stop_reason=result.get("stop_reason") or "success",
                missing=[], gather_manifest=man or None, live_recon=live,
                poc_log_path=log_path, llm_model=result.get("llm_model"))
            return {}
        auth = state.get("auth") or {}
        state_bits = {
            "segments": list(state.get("segments") or []),
            "deep_recon": state.get("deep_recon") or {},
            "session_info": state.get("session_info") or None,
            "auth": {"username": auth.get("username")} if auth.get("username") else {},
            "plan_verdicts": state.get("plan_verdicts") or {},
            "strategy": (state.get("strategy") or "")[:2000],
            "recon_metrics": state.get("recon_metrics") or {},
            "built_kind": (state.get("built") or {}).get("synth_kind"),
        }
        fa = _build_failure_analysis(run_id, log_path, result, gather_manifest=man, state_bits=state_bits)
        llm = None
        try:
            llm = _failure_analysis_llm(state["cve"], state["ip"], state.get("port"), run_id, fa)
        except Exception as e:  # noqa: BLE001
            logging.debug("failure_analysis llm wrapper failed: %s", e)
        if llm:
            fa["narrative"] = llm.get("narrative")
            fa["ranked_next_steps"] = llm.get("ranked_next_steps") or []
            fa["confidence"] = llm.get("confidence")
            fa["llm_model"] = llm.get("model")
        else:
            fa["narrative"] = None
            fa["ranked_next_steps"] = [{"step": s, "why": "deterministic rule", "how": ""} for s in (fa.get("next_steps_deterministic") or [])[:5]]
            fa["confidence"] = None
            fa["llm_model"] = None
        try:
            summary_for_row = None
            from api import _read_trace_file, _summarize_build_trace
            summary_for_row = _summarize_build_trace(_read_trace_file(log_path))
        except Exception:  # noqa: BLE001
            summary_for_row = None
        _record_build_poc_attempt(
            run_id=run_id, cve=state["cve"], ip=state["ip"], port=state.get("port"), eid=state.get("eid"),
            verified=False, stage_reached=fa.get("stage_reached"), stop_reason=fa.get("stop_reason"),
            missing=fa.get("missing") or [], gather_manifest=man or None, live_recon=live,
            summary=summary_for_row, failure_analysis=fa, poc_log_path=log_path,
            llm_model=fa.get("llm_model") or result.get("llm_model"))
        steps_txt = "\n".join(f"{i + 1}. {s.get('step')}" + (f" — {s.get('why')}" if s.get("why") else "")
                              for i, s in enumerate(fa.get("ranked_next_steps") or []))
        _poc_trace(run_id, "failure_analysis",
                   response=(f"stage={fa.get('stage_reached')} stop={fa.get('stop_reason')} missing={fa.get('missing')}\n"
                             f"{fa.get('narrative') or '(no narrative)'}\n{steps_txt}")[:4000],
                   llm_model=fa.get("llm_model"), extra={"failure_analysis": fa})
        # Follow-up row — the operator's queue is where manual continuation starts.
        follow_up_id = None
        try:
            import uuid as _u
            from psycopg2.extras import Json
            from api import get_db, _redact_attempt_blob
            title = f"Build-PoC {state['cve']}: failure analysis ({fa.get('stage_reached')}) on {state['ip']}:{state.get('port')}"
            notes = (fa.get("narrative") or "") + ("\n\n" if fa.get("narrative") else "") + steps_txt
            with get_db() as conn, conn.cursor() as cur:
                # A leaked transaction elsewhere (2026-10-09: osint_agent left
                # idle-in-transaction sessions holding follow_up_items for
                # hours) must fail this insert fast, never hang the build.
                cur.execute("SET LOCAL lock_timeout = '5s'")
                cur.execute("""INSERT INTO follow_up_items
                    (id, finding_source, title, target, severity, reason, priority, flagged_by, rule_id,
                     confidence, tags, notes, engagement_id, metadata)
                    VALUES (%s,'build_poc',%s,%s,'medium',%s,'high','build_poc_failure_analysis','build_poc_failure_analysis',
                            %s,%s,%s,%s,%s)
                    ON CONFLICT (title, COALESCE(target,''), COALESCE(rule_id,''))
                    DO UPDATE SET metadata = EXCLUDED.metadata, notes = EXCLUDED.notes,
                                  reason = EXCLUDED.reason, updated_at = now()
                    RETURNING id""",
                    (str(_u.uuid4()), title, f"{state['ip']}:{state.get('port')}",
                     f"stage={fa.get('stage_reached')} stop={fa.get('stop_reason')}",
                     (fa.get("confidence") if fa.get("confidence") is not None else 0.5),
                     ["build-poc", "failure-analysis", str(fa.get("stage_reached") or "")] + [str(m) for m in (fa.get("missing") or [])],
                     notes[:8000], (str(state.get("eid")) if state.get("eid") else None),
                     Json(_redact_attempt_blob({"run_id": run_id, "stage_reached": fa.get("stage_reached"),
                                                "stop_reason": fa.get("stop_reason"), "blockers": fa.get("blockers"),
                                                "ranked_next_steps": fa.get("ranked_next_steps"),
                                                "confidence": fa.get("confidence")}))))
                row = cur.fetchone(); conn.commit()
                follow_up_id = str(row[0]) if row else None
        except Exception as e:  # noqa: BLE001
            logging.warning("failure_analysis follow-up write failed: %s", e)
        try:
            from webhooks import emit_webhook
            emit_webhook("build_poc_failure_analysis", "build_poc", {
                "engagement_id": str(state.get("eid")) if state.get("eid") else None,
                "cve": state["cve"], "target": f"{state['ip']}:{state.get('port')}", "run_id": run_id,
                "stage_reached": fa.get("stage_reached"), "stop_reason": fa.get("stop_reason"),
                "missing": fa.get("missing"), "follow_up_id": follow_up_id,
                "confidence": fa.get("confidence"), "llm_model": fa.get("llm_model")})
        except Exception:  # noqa: BLE001
            pass
        return {"failure_analysis": fa}
    except Exception as e:  # noqa: BLE001
        logging.warning("node_failure_analysis failed run=%s: %s", run_id, e)
        try:
            _poc_trace(run_id, "failure_analysis_error", response=f"{type(e).__name__}: {str(e)[:400]}",
                       extra={"reason": "node exception"})
        except Exception:  # noqa: BLE001
            pass
        return {}


def node_save_store(state: BuildPocState) -> Dict[str, Any]:
    """Save the built PoC + emit webhook. Store verified/unverified — the
    unverified rows stay for operator inspection (same as monolith).

    Also CAPTURE any credentials/tokens/IDs the exploit's output leaked and file
    them into credential_findings so they appear in the asset's Credentials
    section + exports (operator: "when we get creds and IDs from a PoC exploit
    they should go into the credentials captured part of the assets")."""
    from api import (_save_exploit_store, _extract_credentials_from_poc_output,
                     _store_captured_credentials, _poc_trace)
    from webhooks import emit_webhook
    built = state.get("built") or {}
    result = state.get("result") or {}
    research_out = state.get("research_out")
    recon_metrics = state.get("recon_metrics") or {}
    metrics = result.get("metrics") or {}
    metrics["build_seconds"] = round(time.time() - state["t0"], 1)
    metrics["researched"] = bool(research_out and (
        research_out.get("analysis") or research_out.get("sources", {}).get("has_public_module")))
    if recon_metrics:
        metrics["recon_comparison"] = recon_metrics
        metrics["recon_source"] = state.get("recon_source")
        metrics["recon_seconds_total"] = round(
            sum(v.get("seconds", 0) for v in recon_metrics.values()), 2)
    store_id = None
    try:
        if result.get("final_command"):
            store_id = _save_exploit_store(
                name=f"PoC {state['cve']} on {state['ip']}"
                     + (" (verified)" if result.get("verified") else " (unverified)"),
                cve=state["cve"], kind="web",
                target_host=state["ip"], target_port=state["port"],
                product=state.get("product"), version=state.get("version"),
                command=result.get("final_command"),
                assertion=result.get("final_assertion"),
                rationale=built.get("rationale", ""),
                verified=bool(result.get("verified")), source="cve_poc_builder",
                security_test_id=result.get("security_test_id"),
                poc_log_path=result.get("log_path"),
                llm_model=result.get("llm_model"), built_at=result.get("built_at"),
                eid=state.get("eid"),
                metadata={"off_target": result.get("off_target"),
                          "drifted": result.get("drifted"),
                          "reflection": result.get("reflection"),
                          "iterations": result.get("iterations"),
                          "metrics": metrics,
                          "research": (research_out or {}).get("analysis"),
                          "research_sources": (research_out or {}).get("sources"),
                          "failure_analysis": state.get("failure_analysis") or None,
                          "attempt_run_id": state.get("run_id")})
        elif state.get("failure_analysis"):
            # No final command — the run FAILED (blocked, gather-incomplete, or
            # every iteration unverified). Operator (2026-10-10): "at the end of
            # failed runs ... add the analysis ... stored with the exploit
            # workbench for review." Store a `failed_poc` row carrying the full
            # failure analysis so it shows in the Exploit workbench next to the
            # real PoCs, and its review.md export has the ## Failure analysis
            # section. kind='failed_poc' + verified=False so the UI can filter it.
            fa = state.get("failure_analysis") or {}
            tried = fa.get("tried") or []
            last_cmd = (tried[-1].get("command_head") if tried else None) \
                or "(no command reached the target — see failure analysis)"
            stage = fa.get("stage_reached") or "unknown"
            stop = fa.get("stop_reason") or result.get("stop_reason") or "failed"
            store_id = _save_exploit_store(
                name=f"PoC {state['cve']} on {state['ip']} (failed — {stage})",
                cve=state["cve"], kind="failed_poc",
                target_host=state["ip"], target_port=state["port"],
                product=state.get("product"), version=state.get("version"),
                command=last_cmd, assertion=None,
                rationale=(fa.get("narrative") or built.get("rationale", "")),
                verified=False, source="cve_poc_builder",
                poc_log_path=result.get("log_path") or fa.get("poc_log_path"),
                llm_model=result.get("llm_model") or fa.get("llm_model"),
                built_at=result.get("built_at"), eid=state.get("eid"),
                created_by="cve_poc_builder",
                metadata={"failed_attempt": True,
                          "stage_reached": stage, "stop_reason": stop,
                          "missing": fa.get("missing") or [],
                          "iterations": result.get("iterations"),
                          "metrics": metrics,
                          "research": (research_out or {}).get("analysis"),
                          "research_sources": (research_out or {}).get("sources"),
                          "failure_analysis": fa,
                          "attempt_run_id": state.get("run_id")})
    except Exception as _sse:  # noqa: BLE001
        logging.warning("node_save_store: exploit_store write failed run=%s: %s",
                        state.get("run_id"), _sse)
    if store_id:
        try:
            from api import _link_attempt_to_store
            _link_attempt_to_store(state["run_id"], store_id)
        except Exception:  # noqa: BLE001
            pass
    # CAPTURED CREDENTIALS — scan the exploit's output for leaked creds/tokens/
    # IDs and file them into credential_findings so the asset's Credentials
    # section shows them. Only on verified exploits (unverified output is
    # noise). Also runs for unverified when env BUILD_POC_CAPTURE_UNVERIFIED=on.
    try:
        _run_output = (result.get("final_output") or result.get("output") or "")
        _should_capture = bool(result.get("verified")) or (
            os.environ.get("BUILD_POC_CAPTURE_UNVERIFIED", "off").lower() == "on")
        if _run_output and _should_capture:
            captured = _extract_credentials_from_poc_output(_run_output)
            if captured:
                n = _store_captured_credentials(
                    state["ip"], state["port"], state.get("eid"),
                    captured, cve=state["cve"], source="cve_poc_builder")
                _poc_trace(state["run_id"], "poc_captured_credentials",
                           response=f"captured {len(captured)} credential(s) from "
                                    f"PoC output; stored {n} into credential_findings",
                           extra={"count": n, "cve": state["cve"],
                                  "ip": state["ip"], "exploit_store_id": store_id})
                try:
                    emit_webhook("poc_credentials_captured", "cve_poc_builder", {
                        "cve": state["cve"], "target": state["ip"],
                        "port": state["port"], "count": n,
                        "exploit_store_id": store_id,
                        "engagement_id": state.get("eid")})
                except Exception:  # noqa: BLE001
                    pass
    except Exception as e:  # noqa: BLE001
        logging.debug("poc credential capture failed: %s", e)
    try:
        emit_webhook("cve_poc_built", "software",
                     {"cve": state["cve"], "target": state["ip"],
                      "success": result.get("success"),
                      "verified": result.get("verified"),
                      "off_target": result.get("off_target"),
                      "drifted": result.get("drifted"),
                      "llm_model": result.get("llm_model"),
                      "iterations": result.get("iterations"),
                      "exploit_store_id": store_id,
                      "security_test_id": result.get("security_test_id")})
    except Exception:  # noqa: BLE001
        pass
    # Auto-hint feedback: on an unverified build, extract the strongest signals we
    # already collected (framework, WAF, LIVE/SUSPECT endpoints, honored params,
    # dead endpoints to avoid, mined creds) and persist as a poc_hint so the next
    # rebuild picks them up. Closes the loop: fail once -> analyze -> hint -> retry.
    if store_id and not result.get("verified"):
        try:
            from api import (_read_trace_entries, _summarize_build_trace,
                              _derive_auto_hint, _auto_save_recon_hint, _poc_trace)
            entries = _read_trace_entries(store_id)
            summary = _summarize_build_trace(entries)
            hint_text = _derive_auto_hint(summary)
            if hint_text:
                hid = _auto_save_recon_hint(state["cve"], state["ip"], state["port"],
                                             hint_text, state.get("eid"))
                if hid:
                    _poc_trace(state["run_id"], "auto_hint_saved",
                               response=f"persisted auto-hint {hid} for next rebuild "
                                        f"({len(hint_text)} chars from prior recon)",
                               extra={"hint_id": str(hid), "hint_len": len(hint_text)})
        except Exception:  # noqa: BLE001
            pass
    return {"exploit_store_id": store_id}


def node_tool_handoff(state: BuildPocState) -> Dict[str, Any]:
    """POST-POC TOOL DERIVATION + TEST. Once a PoC exists, look up which
    specialist tool can take it further (SQLi → sqlmap), BUILD the call, and —
    scope-gated + bounded — RUN it to confirm the tool reproduces the finding.
    Operator ask: "once we have a poc it should look up what tools could do this,
    derive sqlmap, create that call and test it." Results persist on the stored
    exploit row (metadata.tool_handoff) and emit a webhook."""
    if (os.environ.get("BUILD_POC_TOOL_HANDOFF", "on") or "on").lower() == "off":
        return {}
    from api import _derive_tools_for_poc, _run_tool_validation, _poc_trace
    from webhooks import emit_webhook
    result = state.get("result") or {}
    cmd = result.get("final_command")
    if not cmd:
        return {}
    try:
        tools = _derive_tools_for_poc(cmd, assertion=result.get("final_assertion"),
                                      product=state.get("product"), cve=state["cve"])
    except Exception as e:  # noqa: BLE001
        logging.debug("tool derivation failed: %s", e)
        return {}
    if not tools:
        return {}
    tested = []
    for te in tools:
        entry = {"tool": te["tool"], "class": te["class"],
                 "command": te.get("command"), "available": None,
                 "ran": False, "confirmed": False}
        if te.get("command"):
            try:
                v = _run_tool_validation(state["ip"], state["port"], te,
                                         eid=state.get("eid"))
                entry.update({"available": v.get("available"), "ran": v.get("ran"),
                              "confirmed": v.get("confirmed"),
                              "seconds": v.get("seconds"), "refusal": v.get("refusal"),
                              "command": v.get("command")})
            except Exception as e:  # noqa: BLE001
                entry["refusal"] = f"validation error: {e}"
            tested.append(entry)
            break  # bounded: test ONE tool per build
        tested.append(entry)
    handoff = {"derived": [{"tool": t["tool"], "class": t["class"],
                            "command": t.get("command")} for t in tools],
               "tested": tested}
    _poc_trace(state["run_id"], "tool_handoff",
               response=(f"derived {[t['tool'] for t in tools]}; "
                         f"tested={[(e['tool'], e.get('confirmed')) for e in tested]}")[:800],
               extra=handoff)
    try:
        emit_webhook("poc_tool_handoff", "cve_poc_builder", {
            "cve": state["cve"], "target": state["ip"],
            "derived_tools": [t["tool"] for t in tools],
            "tested": [{"tool": e["tool"], "confirmed": e.get("confirmed"),
                        "ran": e.get("ran"), "available": e.get("available")}
                       for e in tested],
            "exploit_store_id": state.get("exploit_store_id")})
    except Exception:  # noqa: BLE001
        pass
    store_id = state.get("exploit_store_id")
    if store_id:
        try:
            from api import get_db
            import json as _json
            with get_db() as c, c.cursor() as cur:
                cur.execute("UPDATE exploit_store SET metadata = jsonb_set("
                            "COALESCE(metadata,'{}'::jsonb), '{tool_handoff}', %s::jsonb), "
                            "updated_at=now() WHERE id=%s",
                            (_json.dumps(handoff), store_id))
                c.commit()
        except Exception:  # noqa: BLE001
            pass
    return {"tool_handoff": handoff}


# ── conditional edges (routers) ────────────────────────────────────────────────
def _route_after_start(state: BuildPocState) -> str:
    """recon_first? -> port_sweep, else -> auth_establish (skip recon)."""
    return "port_sweep" if state.get("recon_first") else "auth_establish"


def _route_after_waf(state: BuildPocState) -> str:
    return "waf_characterize" if state.get("waf_family") else "post_waf"


def _route_after_response_mine(state: BuildPocState) -> str:
    """When mining found creds, run auto_login first. Otherwise go straight to
    framework deep-enum (if any) or the next recon step."""
    if state.get("cred_hints"):
        return "auto_login"
    if state.get("detected_frameworks"):
        return "framework_deep_enum"
    return "post_mine"


def _route_after_auto_login(state: BuildPocState) -> str:
    return "framework_deep_enum" if state.get("detected_frameworks") else "post_mine"


def _route_post_waf(state: BuildPocState) -> str:
    """After the WAF phase, branch on want_basic (which controls both basic + mine)."""
    return "basic_recon" if _want(state.get("recon_source", "basic"), "basic") else "post_mine"


def _route_post_mine(state: BuildPocState) -> str:
    """After basic/mine/auto-login/deep-enum block, branch on want_zap then want_arjun.
    When neither is wanted we STILL route via openapi_recon so API-first apps
    (where the HTML spider is useless) get their spec parsed and the real
    attack surface fed to synth."""
    if _want(state.get("recon_source", "basic"), "zap"):
        return "zap_recon"
    if _want(state.get("recon_source", "basic"), "arjun"):
        return "openapi_recon"
    return "openapi_recon"


def _route_post_zap(state: BuildPocState) -> str:
    return "arjun_recon" if _want(state.get("recon_source", "basic"), "arjun") else "auth_establish"


# ── graph builder ──────────────────────────────────────────────────────────────
def _traced(name: str, fn):
    """Wrap a node so an exception inside it leaves a `node_error:<name>` trace
    row (with traceback) before propagating. CVE-2024-22120 (2026-10-08) died
    between `operator_hint` and the next node with nothing in the JSONL."""
    def _run(state):
        try:
            return fn(state)
        except Exception as e:  # noqa: BLE001
            import traceback as _tb
            try:
                from api import _poc_trace
                _poc_trace(state.get("run_id"), f"node_error:{name}",
                           response=f"{type(e).__name__}: {str(e)[:400]}\n{_tb.format_exc()[-3500:]}",
                           extra={"node": name, "error_type": type(e).__name__})
            except Exception:  # noqa: BLE001
                pass
            raise
    _run.__name__ = getattr(fn, "__name__", name)
    return _run


def _add_node(g, name: str, fn):
    g.add_node(name, _traced(name, fn))


def build_graph():
    """Assemble the full StateGraph. Structure:
       START -> [recon block if recon_first]
              -> auth_establish -> load_hints -> research
              -> assemble_guidance -> strategist -> plan_verify
              -> synth -> run_refine -> save_store -> END
    """
    from langgraph.graph import StateGraph, START, END
    g = StateGraph(BuildPocState)

    # Recon block (all conditional on recon_first)
    _add_node(g, "port_sweep", node_port_sweep)
    _add_node(g, "waf_detect", node_waf_detect)
    _add_node(g, "waf_characterize", node_waf_characterize)
    _add_node(g, "basic_recon", node_basic_recon)
    _add_node(g, "product_identification", node_product_identification)
    _add_node(g, "product_cve_enumeration", node_product_cve_enumeration)
    _add_node(g, "response_mine", node_response_mine)
    _add_node(g, "auto_login", node_auto_login)
    _add_node(g, "framework_deep_enum", node_framework_deep_enum)
    _add_node(g, "zap_recon", node_zap_recon)
    _add_node(g, "openapi_recon", node_openapi_recon)
    _add_node(g, "discovered_knowledge_recon", node_discovered_knowledge_recon)
    _add_node(g, "playwright_recon", node_playwright_recon)
    _add_node(g, "arjun_recon", node_arjun_recon)

    # Auth / hints / research
    _add_node(g, "auth_establish", node_auth_establish)
    _add_node(g, "load_hints", node_load_hints)
    _add_node(g, "research", node_research)
    _add_node(g, "access_enumeration", node_access_enumeration)
    _add_node(g, "precondition_enumeration", node_precondition_enumeration)
    _add_node(g, "readiness_gate", node_readiness_gate)

    # Guidance assembly + strategy
    _add_node(g, "assemble_guidance", node_assemble_guidance)
    _add_node(g, "strategist", node_strategist)
    _add_node(g, "plan_verify", node_plan_verify)

    # Synth + execution + save
    _add_node(g, "gather_check", node_gather_check)
    _add_node(g, "deep_recon", node_deep_recon)
    _add_node(g, "synth", node_synth)
    _add_node(g, "run_refine", node_run_refine)
    _add_node(g, "failure_analysis", node_failure_analysis)
    _add_node(g, "save_store", node_save_store)
    _add_node(g, "tool_handoff", node_tool_handoff)

    # Edges — the spine
    g.add_conditional_edges(START, _route_after_start,
                             {"port_sweep": "port_sweep",
                              "auth_establish": "auth_establish"})

    # Recon: port_sweep -> waf_detect -> (characterize if family, else basic/mine block)
    g.add_edge("port_sweep", "waf_detect")
    g.add_conditional_edges("waf_detect", _route_after_waf,
                             {"waf_characterize": "waf_characterize",
                              "post_waf": "_post_waf_hub"})
    g.add_edge("waf_characterize", "_post_waf_hub")

    # Pass-through hub after WAF so both branches converge
    def _post_waf_passthrough(state):  # no-op node
        return {}
    _add_node(g, "_post_waf_hub", _post_waf_passthrough)
    g.add_conditional_edges("_post_waf_hub", _route_post_waf,
                             {"basic_recon": "basic_recon",
                              "post_mine": "_post_mine_hub"})

    # basic_recon -> response_mine -> (auto_login if creds, deep_enum if fw, else post_mine hub)
    g.add_edge("basic_recon", "product_identification")
    g.add_edge("product_identification", "product_cve_enumeration")
    g.add_edge("product_cve_enumeration", "response_mine")
    g.add_conditional_edges("response_mine", _route_after_response_mine,
                             {"auto_login": "auto_login",
                              "framework_deep_enum": "framework_deep_enum",
                              "post_mine": "_post_mine_hub"})
    g.add_conditional_edges("auto_login", _route_after_auto_login,
                             {"framework_deep_enum": "framework_deep_enum",
                              "post_mine": "_post_mine_hub"})
    g.add_edge("framework_deep_enum", "_post_mine_hub")

    # Pass-through hub after basic/mine/login/enum block converges
    _add_node(g, "_post_mine_hub", _post_waf_passthrough)
    g.add_conditional_edges("_post_mine_hub", _route_post_mine,
                             {"zap_recon": "zap_recon",
                              "arjun_recon": "openapi_recon",
                              "openapi_recon": "openapi_recon",
                              "auth_establish": "openapi_recon"})
    # After zap_recon, run openapi_recon unconditionally (cheap — ~12 well-
    # known paths probed once each; most hit on the first match or none at
    # all). Then run playwright_recon, which short-circuits unless the ZAP
    # paths look like an SPA haul. Both merge their discoveries into
    # arjun_discovered so the focused-active-scan escalation attacks them.
    g.add_conditional_edges("zap_recon", _route_post_zap,
                             {"arjun_recon": "openapi_recon",
                              "auth_establish": "openapi_recon"})
    g.add_edge("openapi_recon", "discovered_knowledge_recon")
    g.add_edge("discovered_knowledge_recon", "playwright_recon")
    # playwright_recon → arjun_recon (if _want arjun) else auth_establish.
    def _route_post_playwright(state):
        return "arjun_recon" if _want(state.get("recon_source", "basic"), "arjun") \
                             else "auth_establish"
    g.add_conditional_edges("playwright_recon", _route_post_playwright,
                             {"arjun_recon": "arjun_recon",
                              "auth_establish": "auth_establish"})
    g.add_edge("arjun_recon", "auth_establish")

    # Non-recon spine
    g.add_edge("auth_establish", "load_hints")
    g.add_edge("load_hints", "research")
    g.add_edge("research", "access_enumeration")
    g.add_edge("access_enumeration", "precondition_enumeration")
    g.add_edge("precondition_enumeration", "readiness_gate")
    g.add_edge("readiness_gate", "assemble_guidance")
    g.add_edge("assemble_guidance", "strategist")
    g.add_edge("strategist", "plan_verify")
    g.add_edge("plan_verify", "gather_check")
    # Gaps → one deeper-recon pass → gather again; early/0-iteration stop → same pass → go around once.
    def _route_after_gather(state):
        from api import _BUILD_POC_DEEP_RECON
        man = state.get("gather_manifest") or {}
        if (_BUILD_POC_DEEP_RECON == "on" and state.get("gather_blocked") and not state.get("deep_recon_done")
                and set(man.get("missing") or []) - {"artifact"}):
            return "deep_recon"
        return "synth"
    g.add_conditional_edges("gather_check", _route_after_gather,
                            {"deep_recon": "deep_recon", "synth": "synth"})
    g.add_edge("deep_recon", "gather_check")
    g.add_edge("synth", "run_refine")

    def _route_after_refine(state):
        from api import _BUILD_POC_DEEP_RECON, _BUILD_POC_EARLY_STOP_ITERS
        res = state.get("result") or {}
        gave_up = (res.get("stop_reason") in ("identical_resend", "dup_exit", "cross_round_dup")
                   or bool((res.get("metrics") or {}).get("identical_resend_stop"))
                   or bool((res.get("metrics") or {}).get("refine_dup_exit"))
                   or bool((res.get("metrics") or {}).get("cross_round_dup")))
        # "early" = the loop gave up (whatever the count — round 8 stopped at
        # iteration 3 and never widened) OR it ended within the first iterations
        early = (not res.get("success")) and (gave_up or int(res.get("iterations") or 0) <= _BUILD_POC_EARLY_STOP_ITERS)
        if (_BUILD_POC_DEEP_RECON == "on" and early and not state.get("deep_recon_done")
                and not res.get("artifact_required")):
            return "deep_recon"
        return "save_store"
    # Every end of the loop (blocked, exhausted, or the deep-recon go-around's
    # second pass) funnels through failure_analysis before save_store.
    g.add_conditional_edges("run_refine", _route_after_refine,
                            {"deep_recon": "deep_recon", "save_store": "failure_analysis"})
    g.add_edge("failure_analysis", "save_store")
    g.add_edge("save_store", "tool_handoff")
    g.add_edge("tool_handoff", END)

    return g.compile()


def invoke_build_poc(state: BuildPocState) -> Dict[str, Any]:
    """Run the graph and return the same dict shape _build_poc_core returned to
    its endpoint caller: {command, assertion, canary, success, verified,
    off_target, reflection, iterations, exploit_store_id, ...}."""
    graph = build_graph()
    try:
        final = graph.invoke(state)
    except Exception as e:  # noqa: BLE001
        # A crash between nodes used to leave no `result` and no index row
        # (CVE-2024-22120, 2026-10-08). Record it, then propagate.
        try:
            from api import _poc_trace, _poc_index, _poc_run_file
            _poc_trace(state.get("run_id"), "result",
                       response=f"crash: {type(e).__name__}: {str(e)[:400]}",
                       extra={"verified": False, "crash": True, "error_type": type(e).__name__})
            _poc_index(state.get("cve"), state.get("ip"), state.get("run_id"),
                       _poc_run_file(state.get("run_id")), False, 0, None, state.get("eid"))
        except Exception:  # noqa: BLE001
            pass
        raise
    result = final.get("result") or {}
    session_info = final.get("session_info")
    built = final.get("built") or {}
    return {
        "ok": True, "cve": final.get("cve"),
        "synth_kind": built.get("synth_kind"),
        "exploit_store_id": final.get("exploit_store_id"),
        "authenticated": bool(session_info and session_info.get("ok")),
        "auth_user": (session_info or {}).get("username"),
        "auth_method": (session_info or {}).get("method"),
        **result,
    }
