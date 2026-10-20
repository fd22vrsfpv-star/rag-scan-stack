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

import functools
import logging
import operator
import re
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
    reuse_recon: Optional[str]        # per-run auto|always|never recon reuse; None = default
    fact_challenge_mode: Optional[str]  # per-run auto|review|off; None = container default
    fact_challenge: Dict[str, Any]    # the challenger's verdict on the fact SET (findings/applied/ran) — an UNDECLARED key here is silently dropped
    cred_hints: List[str]
    admin_paths_mined: List[str]
    detected_frameworks: List[str]
    waf_family: Optional[str]
    waf_characterization: Dict[str, Any]
    secondary_products: List[Dict[str, Any]]

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
    #: The structured request plan behind `command` (etl/http_request.py),
    #: when synth produced one. Carried so the pre-dispatch probe can read the
    #: target rather than re-parsing the rendered command for it.
    plan: Optional[list]
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

    # Result of the known-good control run: the CVE's own nuclei template plus
    # a bounded set of same-product CVE templates, executed BEFORE synthesis.
    # {"ran": [...], "hit": [...], "evidence": str, "skipped": reason|None}.
    # A hit is third-party evidence the target is vulnerable AND a working
    # request shape; no hit on a verified template points at the target or the
    # plumbing rather than at synthesis.
    known_good: Dict[str, Any]

    # Post-run review agent output. node_post_run_review returned this WITHOUT
    # it being declared here, and LangGraph drops an undeclared key silently —
    # no error, no warning, the key simply is not in the final state (verified
    # 2026-10-15 against the installed langgraph). Nothing read it, so nothing
    # broke; the review is persisted to build_poc_reviews and traced
    # independently. Declaring it makes the field actually flow, so the next
    # reader gets the review instead of None for a reason nobody could see.
    review: Dict[str, Any]

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
                  focused_urls: Optional[List[str]] = None,
                  fact_challenge: Optional[str] = None,
                  reuse_recon: Optional[str] = None,
                  run_id: Optional[str] = None) -> BuildPocState:
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
        # The checkpoint key. Generated with a timestamp by default, so two
        # builds of the same CVE never collide — but a CALLER may pin it,
        # which is what makes recovery reachable from outside: re-POSTing the
        # same run_id resumes that thread from its last completed node
        # instead of starting a fresh build. Without this the checkpointer
        # works and nothing can ever ask it to.
        "run_id": run_id or f"{cve}_{ip}_{int(time.time())}",
        "t0": time.time(),
        "segments": [], "recon_metrics": {}, "intel_list": [],
        "zap_paths": [], "arjun_discovered": [], "focused_urls": list(focused_urls or []),
        "cred_hints": _supplied, "admin_paths_mined": [],
        # None => the container default. Threaded per-run so an operator can
        # demand a sign-off, or skip the challenge entirely, for ONE build
        # without an env edit and a restart.
        "fact_challenge_mode": fact_challenge,
        # None => the container default (`auto`). Per-run so a target known
        # not to have changed can skip recon entirely, and a target that just
        # changed can be forced to re-scan.
        "reuse_recon": reuse_recon,
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

def _recon_cached(tool, variant=None):
    """Serve a recon node from `recon_cache` when a FRESH result exists.

    A decorator rather than a rewrite of each node: the node keeps its name
    (so the routing guards still find `def node_zap_recon`), its body is
    untouched, and the caching policy lives in exactly one place.

    `tool` may be a callable taking the state, for a node whose answer has
    two different shelf lives — a ZAP ACTIVE scan goes stale faster than a
    passive spider, and a single TTL for both would either re-run the cheap
    one needlessly or over-trust the expensive one.

    `variant` is a callable taking the state and returning the inputs that
    change this tool's answer — the ZAP path list arjun fans across, whether a
    session is held. Leave a real input out and an UNAUTHENTICATED crawl would
    be served in answer to a request for an authenticated one, which is a
    wrong answer rather than a slow one.

    Only the metrics THIS node added are stored, computed as the delta against
    the state's metrics on entry — storing the merged dict would cache every
    earlier tool's numbers and replay them on a later run.

    A result with no segments and no side outputs is NOT stored: the nodes
    swallow their own tool errors, so "nothing at all" is more likely a
    failure than a finding, and caching it would pin that failure for hours.
    """
    def deco(fn):
        @functools.wraps(fn)
        def wrapper(state: BuildPocState) -> Dict[str, Any]:
            from api import (_recon_cache_lookup, _recon_cache_store, _poc_trace)
            try:
                from etl.recon_cache import cache_key, note, REUSE
            except Exception:  # noqa: BLE001
                return fn(state)        # no cache module: behave as before
            try:
                tname = tool(state) if callable(tool) else tool
            except Exception:  # noqa: BLE001
                tname = "recon"
            var = None
            try:
                var = variant(state) if callable(variant) else variant
            except Exception as e:  # noqa: BLE001
                logging.debug("recon cache variant for %s failed: %s", tname, e)
            key = cache_key(tname, state.get("ip"), state.get("port"), var)
            mode = state.get("reuse_recon")
            action, reason, payload, age = _recon_cache_lookup(key, tname, mode)
            before = set((state.get("recon_metrics") or {}).keys())

            if action == REUSE and isinstance(payload, dict):
                out = {k: v for k, v in payload.items() if k != "recon_metrics"}
                cached_metrics = {k: {**(v if isinstance(v, dict) else {}),
                                      "reused": True, "age_seconds": age,
                                      "signal": note(action, tname, reason)}
                                  for k, v in (payload.get("recon_metrics") or {}).items()}
                out["recon_metrics"] = {**(state.get("recon_metrics") or {}), **cached_metrics}
                _poc_trace(state.get("run_id"), f"recon:{tname}:cache",
                           response=note(action, tname, reason),
                           extra={"tool": tname, "age_seconds": age, "action": action,
                                  "reason": reason})
                return out

            # MISS, REFRESH or UNAVAILABLE all run the tool. They are traced
            # separately because only UNAVAILABLE means the cache is broken.
            if action != REUSE:
                _poc_trace(state.get("run_id"), f"recon:{tname}:cache",
                           response=note(action, tname, reason),
                           extra={"tool": tname, "action": action, "reason": reason,
                                  "age_seconds": age})
            out = fn(state)
            try:
                if _worth_caching(out):
                    delta = {k: v for k, v in (out.get("recon_metrics") or {}).items()
                             if k not in before}
                    _recon_cache_store(key, tname, state.get("ip"), state.get("port"),
                                       {**{k: v for k, v in out.items() if k != "recon_metrics"},
                                        "recon_metrics": delta},
                                       engagement_id=state.get("eid"), variant=var,
                                       run_id=state.get("run_id"))
            except Exception as e:  # noqa: BLE001
                logging.debug("recon cache store for %s failed: %s", tname, e)
            return out
        return wrapper
    return deco


def _worth_caching(out: Dict[str, Any]) -> bool:
    """Did the node actually produce something?

    The recon nodes catch their own tool failures and return empty, so an
    all-empty result is as likely to be a broken tool as a clean target.
    Caching it would pin that failure for the whole TTL.
    """
    if not isinstance(out, dict):
        return False
    if out.get("segments"):
        return True
    return any(out.get(k) for k in ("zap_paths", "arjun_discovered", "openapi",
                                    "detected_frameworks", "admin_paths_mined",
                                    "focused_urls", "cred_hints"))


def _auth_fingerprint(state: BuildPocState):
    """Whether this run holds a session, for the cache variant.

    An authenticated crawl and an anonymous one return different answers from
    the same tool against the same URL. Sharing a cache entry between them is
    the one failure mode worse than re-running: a wrong answer, served fast.
    The USER is part of it, not just the fact of a session — two accounts see
    different things. The credential itself never enters the key.
    """
    si = state.get("session_info") or {}
    auth = state.get("auth") or {}
    user = si.get("user") or si.get("username") or auth.get("username")
    return {"authenticated": bool(si.get("cookie_header") or si.get("cookie")),
            "user": str(user) if user else None}


@_recon_cached('port_sweep', variant=None)
def node_port_sweep(state: BuildPocState) -> Dict[str, Any]:
    from api import _scout_open_ports, _poc_trace
    import re as _re_ps
    _t0 = time.time()
    ps = _scout_open_ports(state["ip"], state["port"])
    metrics = {"port_sweep": {"seconds": round(time.time() - _t0, 2),
                              "chars_added": len(ps or ""),
                              "signal": "open-port list + banners"}}
    seg = []
    upd: Dict[str, Any] = {}
    if ps:
        seg.append(ps)
        _poc_trace(state["run_id"], "recon:port_sweep", response=ps[:1200])
        # PORT MISMATCH FIX: detect CVE-Bench Next.js wrapper ports and promote
        # the real application port. The wrapper serves /_next/* static chunks
        # and identifies as Next.js. The real app runs on an alt port (typically
        # 8000). Without this, all recon (auth, crawl, response_mine) hits the
        # wrapper and misses the actual target.
        _wrapper_ports = set()
        _app_ports = set()
        primary = int(state.get("port") or 0)
        for m in _re_ps.finditer(
            r"^\s*(\d+)(?:\s*\(requested\))?:\s*(.+)$", ps, _re_ps.MULTILINE
        ):
            _p = int(m.group(1))
            _banner = m.group(2)
            _bl = _banner.lower()
            _is_wrapper = (
                "next.js" in _bl
                or "/_next/" in _bl
                or "x-powered-by=next" in _bl
                or ('title="cve-bench"' in _bl and _p != 9091)
                or 'title="create next app"' in _bl
            )
            _is_evaluator = (_p == 9091)
            if _is_wrapper and not _is_evaluator:
                _wrapper_ports.add(_p)
            elif not _is_evaluator and _p != primary:
                _app_ports.add(_p)
        if primary in _wrapper_ports and _app_ports:
            _new_port = min(_app_ports)
            _poc_trace(state["run_id"], "port_mismatch_fix",
                       response=(f"Primary port {primary} is a CVE-Bench Next.js "
                                 f"wrapper; promoting port {_new_port} as the real "
                                 f"application target"),
                       extra={"old_port": primary, "new_port": _new_port,
                              "wrapper_ports": sorted(_wrapper_ports),
                              "app_ports": sorted(_app_ports)})
            upd["port"] = _new_port
            seg.append(f"\nPORT CORRECTION: port {primary} is a CVE-Bench wrapper "
                       f"(Next.js). The real application is on port {_new_port}. "
                       f"All subsequent probes/auth/crawl will target port {_new_port}.")
    return {"segments": seg, "recon_metrics": {**state.get("recon_metrics", {}), **metrics},
            **upd}


@_recon_cached('waf_detect', variant=None)
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
    from api import _identify_product_from_target, _poc_trace, _is_synthetic_cve
    _t0 = time.time()
    had_product = bool(state.get("product"))
    # Only run the (slower) deep dive when we DON'T already have research in
    # hand and the build carries a real CVE to research. _is_synthetic_cve
    # covers both synthesized prefixes (POC- now, NOCVE- on older rows) — a
    # single literal here would send old builds researching a nonexistent CVE.
    want_deep = (bool(state.get("research", True))
                 and bool(state.get("cve"))
                 and not _is_synthetic_cve(state.get("cve")))
    info = _identify_product_from_target(
        state["ip"], state["port"],
        run_deep_dive=want_deep,
        cve=state.get("cve"), eid=state.get("eid"), model=state.get("model"))
    upd: Dict[str, Any] = {}
    seg = []
    # Extract Server headers from alt ports discovered by port_sweep.
    # Port sweep stores banners like "9090: HTTP 302 Server=Werkzeug/3.0.6"
    # in segments. Product identification only checks the primary port, so
    # alt-port products (Werkzeug on :9090, etc.) were invisible to the
    # product enumeration pipeline. This shared extractor feeds both the
    # build-PoC pipeline and the exploit workbench.
    import re as _re_ps
    _existing_sp = {s["product"].lower() for s in (info.get("secondary_products") or [])}
    _primary_prod = (info.get("product") or "").lower()
    for _seg_text in (state.get("segments") or []):
        for _m in _re_ps.finditer(
            r"^\s*(\d+)(?:\s*\(requested\))?:\s*HTTP\s+\d+\s+Server=([^\s]+)",
            _seg_text, _re_ps.MULTILINE,
        ):
            _alt_port = int(_m.group(1))
            if _alt_port == int(state.get("port") or 0):
                continue  # primary port already handled
            _srv_raw = _m.group(2)
            _vm = _re_ps.match(r"([A-Za-z][A-Za-z0-9._-]*?)[/ ]([0-9]+\.[0-9][0-9.]*)", _srv_raw)
            if _vm:
                _sp_name, _sp_ver = _vm.group(1), _vm.group(2)
                if _sp_name.lower() not in _existing_sp and _sp_name.lower() != _primary_prod:
                    if info.get("secondary_products") is None:
                        info["secondary_products"] = []
                    info["secondary_products"].append({
                        "product": _sp_name, "version": _sp_ver,
                        "source": f"port_sweep:{_alt_port}",
                    })
                    _existing_sp.add(_sp_name.lower())
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
    upd["secondary_products"] = info.get("secondary_products") or []
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
    # Pull the full identification (secondary + plugins) — cheap, cached HTML.
    # Prefer state-propagated secondary_products (which include alt-port
    # discoveries from port_sweep) over a fresh re-fetch that only sees the
    # primary port.
    info = {}
    try:
        info = _identify_product_from_target(state["ip"], state["port"],
                                              run_deep_dive=False)
    except Exception as e:  # noqa: BLE001
        logging.debug("product enumeration identify failed: %s", e)
    state_sp = state.get("secondary_products") or []
    info_sp = info.get("secondary_products") or []
    # Merge: state takes priority (has alt-port products), then info
    _seen_sp = set()
    merged_sp = []
    for s in state_sp + info_sp:
        key = s["product"].lower()
        if key not in _seen_sp:
            merged_sp.append(s)
            _seen_sp.add(key)
    # Build the ordered work list: primary first, then secondary, then plugins.
    targets = []
    if primary:
        targets.append({"product": primary, "version": primary_ver, "tier": "primary"})
    elif info.get("product"):
        targets.append({"product": info["product"], "version": info.get("version"),
                        "tier": "primary"})
    for s in merged_sp:
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


@_recon_cached('framework_deep_enum', variant=lambda st: {'auth': _auth_fingerprint(st)})
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


@_recon_cached(lambda st: 'zap_active' if _want(st.get('recon_source', 'basic'), 'active') else 'zap',
               variant=lambda st: {'active': _want(st.get('recon_source', 'basic'), 'active'),
                                   'auth': _auth_fingerprint(st)})
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


@_recon_cached('openapi', variant=lambda st: {'auth': _auth_fingerprint(st)})
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


@_recon_cached('playwright', variant=lambda st: {'auth': _auth_fingerprint(st), 'urls': sorted(st.get('focused_urls') or [])[:20]})
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


@_recon_cached('arjun', variant=lambda st: {'zap_paths': sorted(st.get('zap_paths') or [])[:40], 'auth': _auth_fingerprint(st)})
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


CLASS_UNRESOLVED = "class_unresolved"


def _class_gate(state: BuildPocState) -> Dict[str, Any]:
    """{} when the class is known or resolved; a readiness block otherwise.

    Applies to a real CVE id only -- a product-only (NOCVE) build has no
    description to classify from and is steered by the operator's hint.
    """
    if (os.environ.get("BUILD_POC_CLASS_GATE", "on") or "on").lower() == "off":
        return {}
    cve = str(state.get("cve") or "").upper()
    if not cve.startswith("CVE-"):
        return {}
    from api import (_fetch_cve_details, _vuln_class_from_cve,
                     _resolve_unknown_class, _poc_trace)
    try:
        details = _fetch_cve_details(cve) or {}
    except Exception:  # noqa: BLE001
        details = {}
    if _vuln_class_from_cve(cve, details) != "unknown":
        return {}
    research = ""
    ro = state.get("research_out") or {}
    if isinstance(ro, dict):
        an = ro.get("analysis") or {}
        research = (an.get("summary") if isinstance(an, dict) else "") or ""
        research = (research + "\n" + str(ro.get("advisory_text") or ""))[:3000]
    r = _resolve_unknown_class(cve, details, extra_text=research,
                               model=state.get("model"), run_id=state.get("run_id"))
    if r.get("class") and r["class"] != "unknown":
        return {}
    why = (f"{CLASS_UNRESOLVED}: the vulnerability class of {cve} could not be "
           f"resolved ({r.get('evidence') or 'no evidence'}); set it with "
           f"PUT /software/cve-class/{cve} and rebuild")
    _poc_trace(state.get("run_id"), "class_gate_blocked", response=why)
    return {"readiness_blocked": True, "readiness_blockers": [why]}


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
    # CLASS GATE -- before anything else, and independent of the precondition
    # gate's mode. An `unknown` class means no class guidance, no reading
    # hints, no graded-goal preference and no proof template: the exploit
    # would be a guess. Resolve it (closed vocabulary, stored so every later
    # re-derivation sees it) or BLOCK the attempt. Operator ask, 2026-10-18:
    # "in a class unknown, that should be resolved first before trying an
    # exploit". BUILD_POC_CLASS_GATE=off restores the old behaviour.
    _cg = _class_gate(state)
    if _cg:
        return _cg
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
    # Does projectdiscovery already ship a check for this CVE? Worth knowing
    # before synthesising anything: a VERIFIED upstream template is a faster and
    # far more reliable answer than a from-scratch PoC, and when one exists and
    # the build still fails, "a working check existed and we did not use it" is
    # the single most useful line in the review.
    #
    # Advisory only — never gates the build, and every failure is swallowed.
    try:
        import requests as _rq
        from api import _poc_trace
        _nu = os.environ.get("NUCLEI_URL", "https://nuclei-runner:8011")
        _tr = _rq.get(f"{_nu}/templates/for-cve/{state['cve']}",
                      timeout=10, verify=False).json()
        if _tr.get("found"):
            _poc_trace(
                state["run_id"], "nuclei_template_available",
                response=(f"{_tr.get('template_id')} severity={_tr.get('severity')} "
                          f"verified={_tr.get('verified')} intrusive={_tr.get('intrusive')} "
                          f"path={_tr.get('template_path')}"),
                extra={"nuclei_template": _tr})
        else:
            _poc_trace(state["run_id"], "nuclei_template_available",
                       response=f"none for {state['cve']} ({_tr.get('reason')})",
                       extra={"nuclei_template": _tr})
    except Exception as e:  # noqa: BLE001
        logging.debug("nuclei template check skipped for %s: %s", state.get("cve"), e)

    # ── RUN THE KNOWN-GOOD CHECK, don't just note that one exists ───────────
    #
    # The block above has asked "does projectdiscovery ship a check for this
    # CVE" since it was written, logged the answer, and then synthesised from
    # scratch regardless — its own comment said so: "Advisory only — never
    # gates the build". On 2026-10-15 CVE-2024-3408 carried a template marked
    # verified=True and the build ran nine commands, ended max_iters, and never
    # executed it.
    #
    # Running it first is a CONTROL. Without one, a failed build cannot
    # separate "the exploit is hard" from "the target is not vulnerable" from
    # "our plumbing is broken". It also tries a bounded set of CVE templates
    # for the SAME PRODUCT, because a product's faults cluster by component and
    # coding habit — a 2022 Zabbix template firing on a 2024 Zabbix bug hands
    # synthesis a working request shape for the right application instead of a
    # guess.
    #
    # Advisory in the other direction: it never blocks the build, and every
    # failure is swallowed. It is scope-gated like any other target traffic.
    _known_good = None
    if (os.environ.get("BUILD_POC_KNOWN_GOOD", "on") or "on").lower() != "off":
        try:
            from api import _known_good_probe
            kg = _known_good_probe(
                state["cve"], state["ip"], state["port"],
                product=state.get("product") or "", eid=state.get("eid"),
                run_id=state["run_id"])
            # Carried on the RETURN, not by mutating `state`: a LangGraph node's
            # changes propagate only through the dict it returns, so assigning
            # to state here would have been silently discarded and synthesis
            # would never have seen the result.
            _known_good = kg
        except Exception as e:  # noqa: BLE001
            logging.debug("known-good probe skipped for %s: %s", state.get("cve"), e)

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
    _out = {"research_out": research_out}
    if _known_good:
        _out["known_good"] = _known_good
    return _out


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

    # KNOWN-GOOD EVIDENCE, first and in its own voice.
    #
    # A nuclei template that FIRED against this host is third-party proof the
    # vulnerability is present and a working request shape for it. Leaving that
    # in the trace while synthesis guesses is the same mistake the pipeline
    # already made with `input_field = listingfields`: the fact was gathered,
    # rendered somewhere nobody read, and ignored by all 26 dispatched
    # commands. So it goes at the FRONT of the guidance, labelled as evidence
    # rather than suggestion.
    kg = state.get("known_good") or {}
    kg_guidance = ""
    if kg.get("hit"):
        _own = [h for h in kg["hit"]
                if str(h.get("template", "")).upper() == str(state.get("cve", "")).upper()]
        _sib = [h for h in kg["hit"] if h not in _own]
        kg_guidance = (
            "KNOWN-GOOD EVIDENCE — a third-party check already FIRED on this "
            "host.\n"
            + ("  The CVE's OWN nuclei template matched: %s. The target IS "
               "vulnerable; you are reproducing a known-working request, not "
               "searching for one.\n" % ", ".join(h["template"] for h in _own)
               if _own else "")
            + ("  Template(s) for OTHER CVEs in the same product matched: %s. "
               "The same product has this class of fault and these request "
               "shapes reach it — adapt them rather than starting from the "
               "advisory text.\n" % ", ".join(h["template"] for h in _sib)
               if _sib else "")
            + "  Matcher output:\n" + (kg.get("evidence") or "")[:1500] + "\n")
    if recon_guidance:
        guidance = kg_guidance + hint_guidance + (recon_guidance + " " + auth_guidance).strip()
    else:
        guidance = kg_guidance + hint_guidance + auth_guidance
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
    # PROVE the gathered facts before synthesis uses them. Until this ran, a
    # fact's confidence reflected only where it came from; now it reflects
    # whether a test case confirmed it. A confirmed fact becomes enforceable
    # at dispatch (the fact gate), a refuted one stops being retried, and one
    # the probe could not decide stays exactly as unproven as it was.
    try:
        from api import _preflight_prove_facts
        _probe_results = _preflight_prove_facts(
            man, state["cve"], state["ip"], state["port"],
            eid=state.get("eid"), run_id=state["run_id"],
            product=state.get("product"))
    except Exception as _pfe:  # noqa: BLE001
        # Never fail the build on the prover. A probe that did not run is not
        # evidence of anything; synthesis continues with the facts as gathered.
        _probe_results = {}
        _poc_trace(state["run_id"], "preflight_facts",
                   response=f"(skipped: {type(_pfe).__name__}: {_pfe})")
    # CHALLENGE the fact SET. The probes above test one claim each; this is
    # the only step that reads them together and can notice that the endpoint
    # is a template, the route belongs to another product, or the parameter
    # came from a different vulnerability class. Each contradiction carries its
    # own declared action (clear / downgrade / relax_auth / warn) — one of them
    # UNBLOCKS a build, so "high severity" cannot be a single behaviour.
    try:
        from api import _challenge_derived_facts
        _auth_item = next((i for i in (man.get("items") or [])
                           if i.get("item") == "auth"), None)
        _reach = next((i for i in (man.get("items") or [])
                       if i.get("item") == "target_reachable"), None)
        _obs = []
        _m = re.search(r"HTTP (\d{3})", str((_reach or {}).get("value") or ""))
        if _m and not (state.get("session_info") or {}).get("cookie_header"):
            # The root answered this status with NO session attached, so it is
            # evidence about whether authentication is actually required.
            _obs.append({"item": "target_reachable", "status": int(_m.group(1)),
                         "value": (_reach or {}).get("value")})
        _challenge = _challenge_derived_facts(
            man, state["cve"], state["ip"], state["port"],
            eid=state.get("eid"), run_id=state["run_id"],
            product=state.get("product"), probe_results=_probe_results,
            auth_required=bool(_auth_item and _auth_item.get("status") == "missing"),
            auth_observations=_obs, mode=state.get("fact_challenge_mode"))
    except Exception as _ce:  # noqa: BLE001
        _challenge = {"ran": False, "error": f"{type(_ce).__name__}: {_ce}"}
        man["challenge"] = _challenge
        _poc_trace(state["run_id"], "fact_challenge",
                   response=f"(skipped: {type(_ce).__name__}: {_ce})")
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
    upd["fact_challenge"] = _challenge
    if mode == "strict" and not man.get("ready"):
        upd["gather_blocked"] = True
    elif (_challenge.get("findings")
          and str(_challenge.get("mode")) == "review"):
        # review mode: the operator signs off on a contested fact set before
        # traffic is spent on it. `auto` (the default) applied the actions and
        # carried on, which is what makes this opt-in rather than a new stall.
        upd["gather_blocked"] = True
        man["missing"] = (man.get("missing") or []) + ["intel_review"]
        man["follow_ups"] = (man.get("follow_ups") or []) + [
            "Review the challenged facts on the run's Intel tab, then re-run. "
            "Set BUILD_POC_FACT_CHALLENGE=auto to apply the actions and continue "
            "without a sign-off."]
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
    from api import _build_poc_second_pass_iters
    _second_pass_cap = _build_poc_second_pass_iters()
    upd: Dict[str, Any] = {"deep_recon_done": True, "deep_recon": {k: v for k, v in res.items() if k != "segments"},
                           # The go-around is a SECOND chance, not a second budget — but the
                           # cap is now the operator's (Settings → Scan Timeouts →
                           # "Build-PoC second-pass iterations", default 50). At the old
                           # hard 10 this clamp was the binding limit on every CVE that
                           # needed deep recon: a request for 50 became 10, and
                           # CVE-2024-22120 stopped at exactly 10 on max_iters with all 10
                           # iterations genuinely reaching the target.
                           "max_iters": min(int(state.get("max_iters") or 0) or _second_pass_cap, _second_pass_cap),
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
    # ── STRUCTURED REQUEST PLAN (etl/http_request.py) ──────────────────────
    #
    # When synth returns a `plan` — a list of steps, each a request as DATA —
    # the command is RENDERED from it rather than written by the model as a
    # shell string. That removes the largest class of pre-dispatch failure in
    # the archive at its source: 444 shell_syntax refusals are a quoting
    # decision, and a rendered command makes no quoting decisions.
    #
    # The plan is kept in state so the probe can READ the target instead of
    # re-parsing the command for it — the mistake that had it probing the
    # exploit's own callback sink (296 prerun_probe_fail rows).
    #
    # Additive: no plan, nothing changes. A plan that will not render is
    # dropped with its reason traced, and the model's own command stands —
    # a renderer fault must not cost the build an iteration.
    _plan = built.get("plan") if isinstance(built, dict) else None
    if _plan:
        try:
            from etl.http_request import (validate_plan as _vp, to_script as _ts,
                                          target_of as _tgt)
            _steps = _vp(_plan)
            _rendered = _ts(_steps, canary=built.get("canary"))
            _m, _u = _tgt(_steps)
            _poc_trace(state["run_id"], "synth_plan_rendered",
                       response=_rendered[:1200],
                       extra={"steps": len(_steps), "target_method": _m,
                              "target_url": _u,
                              "replaced_model_command": bool(built.get("command"))})
            built = {**built, "command": _rendered, "plan": _steps}
        except Exception as _pe:  # noqa: BLE001
            _poc_trace(state["run_id"], "synth_plan_rejected",
                       response=str(_pe)[:400],
                       extra={"kept": "the model's own command"})
            built = {**built, "plan": None}
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
        # The structured plan behind the command, when synth produced one.
        # Read by the pre-dispatch probe so it does not have to re-parse the
        # rendered command to find out what is being attacked.
        "plan": built.get("plan"),
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
        _cls = any(str(b).startswith(CLASS_UNRESOLVED) for b in blockers)
        return {"result": {"ok": True, "success": False, "verified": False,
                           "blocked": True, "blockers": blockers,
                           "stop_reason": CLASS_UNRESOLVED if _cls else "readiness_blocked",
                           "reason": ("class gate: " if _cls else
                                      "readiness gate: preconditions not met — ")
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
        # The structured plan behind the first command, so the pre-dispatch
        # probe reads the declared target instead of inferring it.
        plan=built.get("plan"),
        recon_source_used=state.get("recon_source"),
        # Hand arjun's live findings + any operator-supplied focused URLs
        # (BuildPocBody.focused_urls) to the escalation path, which runs a
        # per-URL ZAP active scan on them in addition to the generic
        # host-level scan. Catches URLs ZAP's own spider would never reach.
        arjun_discovered=state.get("arjun_discovered"),
        focused_urls_from_body=state.get("focused_urls"),
        gather_facts=(_gather_manifest_text(state["gather_manifest"]) if state.get("gather_manifest") else None),
        # Carry the escalation counters forward across a go-around. The second
        # pass starts from a fresh `built["metrics"]`, so without this the
        # stored result reports only the LAST pass — on CVE-2024-22120
        # (2026-10-13) that hid the single most interesting event of the run, a
        # payload-only command refused before dispatch and successfully
        # re-asked, which happened in pass 1 and appeared nowhere in the
        # metrics. Only the cumulative counters are carried; per-pass values
        # like target_runs keep their own meaning.
        metrics={**(built.get("metrics") or {}),
                 **{_k: int(((state.get("result") or {}).get("metrics") or {}).get(_k) or 0)
                    for _k in ("refine_axis_required", "refine_axis_rejected")
                    if ((state.get("result") or {}).get("metrics") or {}).get(_k)},
                 "refine_passes": int(((state.get("result") or {}).get("metrics") or {})
                                      .get("refine_passes") or 0) + 1,
                 "_session_cookie_header": ((state.get("session_info") or {}).get("cookie_header")
                                            or (state.get("auth") or {}).get("_auto_cookie") or "")},
        # Resolved object-ids from the login's post-access inventory /
        # precondition enumeration — enforced into every command so the model
        # can't substitute an invented id for one the login actually proved.
        resolved_ids=(state.get("precond_result") or {}).get("resolved"),
        prior_cmd_signatures=state.get("prior_cmd_signatures"))
    # CHAIN FALLBACK (operator ask, 2026-10-18: "2 as a backup"). On a real
    # exhaust (max_iters, axis_exhausted, drifted) with another class available
    # in the CVE's chain, re-synth with the backup class pinned and run refine
    # once more. Keep the better of the two (a verified attempt beats any
    # exhausted one; otherwise the higher-scoring best_attempt).
    # One retry only (we are not going to triple build time); env-gated.
    if (not result.get("verified")
            and result.get("backup_classes_available")
            and (os.environ.get("BUILD_POC_CLASS_FALLBACK", "on") or "on").lower() != "off"):
        from api import _synthesize_cve_poc
        backup = result["backup_classes_available"][0]
        _poc_trace(state["run_id"], "class_fallback_retry",
                   response=f"primary={result.get('primary_class')} exhausted "
                            f"({result.get('stop_reason')}); re-synthing as {backup}",
                   extra={"primary": result.get("primary_class"),
                          "backup": backup,
                          "stop_reason": result.get("stop_reason"),
                          "chain": result.get("backup_classes_available")})
        try:
            built2 = _synthesize_cve_poc(
                state["cve"], state["ip"], state["port"],
                state.get("product"), state.get("version"), state.get("eid"),
                run_id=state["run_id"], model=state.get("model"),
                vuln_class_override=backup)
        except Exception as e:  # noqa: BLE001
            built2 = None
            _poc_trace(state["run_id"], "class_fallback_synth_failed",
                       response=f"{type(e).__name__}: {e}"[:300])
        if built2 and built2.get("command"):
            result2 = _run_refine_poc(
                state["cve"], state["ip"], state["port"],
                built2["command"], built2["assertion"], state.get("eid"),
                state["run_id"], rationale=built2.get("rationale", ""),
                product=state.get("product"), version=state.get("version"),
                max_iters=state["max_iters"],
                canary=built2.get("canary"), origin_family=built2.get("origin_family"),
                llm_model=built2.get("llm_model"), model=state.get("model"),
                recon_source_used=state.get("recon_source"),
                arjun_discovered=state.get("arjun_discovered"),
                focused_urls_from_body=state.get("focused_urls"),
                gather_facts=(_gather_manifest_text(state["gather_manifest"])
                              if state.get("gather_manifest") else None),
                metrics={**(built2.get("metrics") or {}),
                         "refine_passes": int((result.get("metrics") or {})
                                              .get("refine_passes") or 0) + 1,
                         "class_fallback_pass": 1,
                         "_session_cookie_header": (
                             (state.get("session_info") or {}).get("cookie_header")
                             or (state.get("auth") or {}).get("_auto_cookie") or "")},
                resolved_ids=(state.get("precond_result") or {}).get("resolved"),
                prior_cmd_signatures=state.get("prior_cmd_signatures"),
                vuln_class_override=backup,
                tried_classes=list((result.get("tried_classes") or [])))
            _poc_trace(state["run_id"], "class_fallback_outcome",
                       extra={"backup": backup, "verified": bool(result2.get("verified")),
                              "stop_reason": result2.get("stop_reason")})
            # A verified fallback wins outright. Otherwise keep whichever
            # produced the higher-scoring best_attempt (verified>any exhaust;
            # higher best_score > lower; ties keep the ORIGINAL primary so the
            # recorded primary class is stable).
            def _better(a, b):
                if bool(a.get("verified")) != bool(b.get("verified")):
                    return a if a.get("verified") else b
                return a if float(a.get("best_score") or 0) >= float(b.get("best_score") or 0) else b
            picked = _better(result, result2)
            picked["chain_fallback"] = {
                "fired": True, "backup_class": backup,
                "primary_result": {k: result.get(k) for k in
                                   ("verified", "stop_reason", "best_score", "iterations")},
                "backup_result": {k: result2.get(k) for k in
                                  ("verified", "stop_reason", "best_score", "iterations")},
                "winner": "backup" if picked is result2 else "primary"}
            result = picked
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
                     _poc_trace, _poc_run_file, _extract_lessons, _store_lessons)
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
            try:
                auth = state.get("auth") or {}
                ls_bits = {"product": state.get("product"), "cve": state["cve"],
                           "eid": state.get("eid"), "gather_manifest": man,
                           "session_info": state.get("session_info"),
                           "auth": {"username": auth.get("username")} if auth.get("username") else {},
                           "vuln_class": (man.get("facts") or {}).get("vuln_class") or
                                         (state.get("built") or {}).get("vuln_class") or ""}
                lessons = _extract_lessons(run_id, result, ls_bits)
                if lessons:
                    n = _store_lessons(lessons, run_id)
                    _poc_trace(run_id, "lessons_extracted",
                               extra={"count": n, "types": list({l["lesson_type"] for l in lessons})})
            except Exception:  # noqa: BLE001
                pass
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
        try:
            ls_bits = {**state_bits, "product": state.get("product"), "cve": state["cve"],
                       "eid": state.get("eid"), "gather_manifest": man,
                       "vuln_class": (man.get("facts") or {}).get("vuln_class") or
                                     (state.get("built") or {}).get("vuln_class") or ""}
            lessons = _extract_lessons(run_id, result, ls_bits, failure_analysis=fa)
            if lessons:
                n = _store_lessons(lessons, run_id)
                _poc_trace(run_id, "lessons_extracted",
                           extra={"count": n, "types": list({l["lesson_type"] for l in lessons})})
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


def _preferred_command(result: Dict[str, Any]):
    """The command worth storing: the verified one, else the best-scoring.

    Returns the FINAL command whenever the run verified (what passed is the
    proof) or whenever the loop never scored a better attempt. Otherwise the
    best attempt, which for a drifted run is an earlier iteration.
    """
    final = result.get("final_command")
    if result.get("verified"):
        return final
    best = result.get("best_command")
    if not best or best == final:
        return final
    # Only prefer the best when it genuinely outranks where the loop ended.
    from api import _attempt_score
    final_score = _attempt_score(success=False, drifted=bool(result.get("drifted")),
                                 off_target=bool(result.get("off_target")),
                                 output=result.get("output") or "x", command=final)
    return best if (result.get("best_score") or -1) > final_score else final


def _preferred_assertion(result: Dict[str, Any]):
    """The assertion belonging to whichever command _preferred_command picked."""
    if _preferred_command(result) == result.get("best_command") \
            and result.get("best_command"):
        return result.get("best_assertion") or result.get("final_assertion")
    return result.get("final_assertion")


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
    # Do NOT overwrite a verified exploit_store row with an unverified one.
    # The deep-recon go-around can produce a second pass whose unverified
    # result shadows the first pass's verified entry (CVE-2024-36412).
    _skip_unverified = False
    if not result.get("verified"):
        try:
            from api import get_db
            with get_db() as _sc, _sc.cursor() as _scur:
                _scur.execute(
                    """SELECT id FROM exploit_store
                       WHERE verified = true
                         AND (metadata->>'attempt_run_id' = %s
                              OR (cve = %s AND target_host = %s))
                       LIMIT 1""",
                    (state.get("run_id") or '', state.get("cve") or '',
                     str(state.get("ip") or '')))
                _vrow = _scur.fetchone()
                if _vrow:
                    store_id = str(_vrow[0])
                    _skip_unverified = True
                    _poc_trace(state.get("run_id"), "save_store_skip",
                               response=f"verified entry {store_id} exists; "
                                        f"not overwriting with unverified")
        except Exception:  # noqa: BLE001
            pass
    try:
        if result.get("final_command") and not _skip_unverified:
            store_id = _save_exploit_store(
                name=f"PoC {state['cve']} on {state['ip']}"
                     + (" (verified)" if result.get("verified") else " (unverified)"),
                cve=state["cve"], kind="web",
                target_host=state["ip"], target_port=state["port"],
                product=state.get("product"), version=state.get("version"),
                # Store the BEST attempt, not the last. When the refine loop
                # drifts, its final command is the worst it produced:
                # CVE-2026-21589 synthesised the correct traversal first,
                # wandered onto an unrelated /bamboo/browse login flow, and
                # stored THAT — so pressing Run in the Store re-ran a command
                # aimed at a URL that was never the vulnerability.
                #
                # A verified run always stores its final command: the thing
                # that passed IS the proof. Only an unverified run falls back
                # to the best-scoring attempt, and only when it actually
                # scored better than the last one.
                command=_preferred_command(result),
                assertion=_preferred_assertion(result),
                rationale=built.get("rationale", ""),
                verified=bool(result.get("verified")), source="cve_poc_builder",
                security_test_id=result.get("security_test_id"),
                poc_log_path=result.get("log_path"),
                llm_model=result.get("llm_model"), built_at=result.get("built_at"),
                eid=state.get("eid"),
                metadata={"off_target": result.get("off_target"),
                          "drifted": result.get("drifted"),
                          # WHICH attempt this row holds, so an operator
                          # reading a failed PoC can tell whether it is the
                          # loop's last wander or its best shot.
                          "stored_attempt": ("final" if _preferred_command(result)
                                             == result.get("final_command") else "best"),
                          "best_score": result.get("best_score"),
                          "best_iteration": result.get("best_iteration"),
                          "reflection": result.get("reflection"),
                          "iterations": result.get("iterations"),
                          "metrics": metrics,
                          "research": (research_out or {}).get("analysis"),
                          "research_sources": (research_out or {}).get("sources"),
                          "failure_analysis": state.get("failure_analysis") or None,
                          "attempt_run_id": state.get("run_id")})
        elif state.get("failure_analysis") and not _skip_unverified:
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


def node_post_run_review(state: BuildPocState) -> Dict[str, Any]:
    """RAG-driven post-run review agent. Retrieves review criteria from RAG,
    evaluates each against the run trace, stores findings for operator approval,
    and feeds learnings back into RAG for future runs."""
    from api import (_post_run_review, _poc_trace, _read_trace_entries,
                     _summarize_build_trace, _trace_extra)
    result = state.get("result") or {}
    fa = state.get("failure_analysis") or {}
    session_info = state.get("session_info") or {}
    trace_summary = {}
    try:
        store_id = state.get("exploit_store_id")
        if store_id:
            entries = _read_trace_entries(store_id)
            trace_summary = _summarize_build_trace(entries)
    except Exception:  # noqa: BLE001
        pass
    try:
        review = _post_run_review(
            run_id=state.get("run_id"),
            cve=state.get("cve"),
            ip=state.get("ip"),
            port=state.get("port"),
            product=state.get("product"),
            result=result,
            fa=fa,
            session_info=session_info,
            trace_summary=trace_summary,
            eid=state.get("eid"))
        _poc_trace(state.get("run_id"), "post_run_review",
                   response=(f"review completed: {review.get('summary', '')[:300]}"),
                   extra={"review_id": review.get("review_id"),
                          "findings_count": len(review.get("findings", [])),
                          "fail_count": sum(1 for f in review.get("findings", [])
                                           if f.get("status") == "fail"),
                          "prior_learnings": review.get("prior_learnings_count", 0)})
        return {"review": review}
    except Exception as e:  # noqa: BLE001
        logging.warning("post_run_review failed run=%s: %s", state.get("run_id"), e)
        return {}


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


def build_graph(checkpointer=None):
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
    _add_node(g, "post_run_review", node_post_run_review)

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
        from api import _BUILD_POC_DEEP_RECON, _BUILD_POC_EARLY_STOP_ITERS, get_db
        res = state.get("result") or {}
        # GUARD: if this run already produced a verified exploit, do NOT
        # route to deep_recon for a go-around — the second pass would
        # write an unverified entry that shadows the verified one.
        # CVE-2024-36412: verified at iter 3, go-around overwrote with
        # verified=False at iter 19. This single bug cost the only
        # success in the focused-10 benchmark.
        if res.get("verified"):
            return "save_store"
        try:
            run_id = state.get("run_id")
            cve = state.get("cve")
            ip = state.get("ip")
            if run_id or (cve and ip):
                with get_db() as c, c.cursor() as cur:
                    cur.execute(
                        """SELECT 1 FROM exploit_store
                           WHERE verified = true
                             AND (metadata->>'attempt_run_id' = %s
                                  OR (cve = %s AND target_host = %s))
                           LIMIT 1""",
                        (run_id or '', cve or '', str(ip or '')))
                    if cur.fetchone():
                        return "save_store"
        except Exception:  # noqa: BLE001
            pass
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
    g.add_edge("tool_handoff", "post_run_review")
    g.add_edge("post_run_review", END)

    return g.compile(checkpointer=checkpointer)


def _saver_cm():
    """Postgres checkpointer, the same mechanism agent sessions already use.

    Mirrors `autogen_agents/langgraph_engine.py::_saver_cm` deliberately —
    one checkpointing story, one set of tables, `thread_id` telling the two
    apart. Returns None when the package or the DSN is absent, and the build
    then runs exactly as before: a missing checkpointer must degrade recovery,
    never block a build.
    """
    try:
        from langgraph.checkpoint.postgres import PostgresSaver
    except Exception as e:  # noqa: BLE001
        import logging as _lg
        _lg.getLogger(__name__).info(
            "build-poc: checkpointing unavailable (%s) — running unrecoverable",
            type(e).__name__)
        return None
    dsn = os.environ.get("DB_DSN")
    if not dsn:
        return None
    try:
        return PostgresSaver.from_conn_string(dsn)
    except Exception as e:  # noqa: BLE001
        import logging as _lg
        _lg.getLogger(__name__).warning(
            "build-poc: checkpointer init failed (%s) — running unrecoverable", e)
        return None


def _has_checkpoint(graph, cfg) -> bool:
    """Has this thread_id run before?

    Decides RESUME vs FRESH, and the distinction is load-bearing: with a
    checkpointer, passing the full initial state again RESTARTS the graph,
    while passing None resumes from the last completed node. Getting it
    backwards would silently re-run a 12-iteration build from scratch.
    """
    try:
        snap = graph.get_state(cfg)
        return bool(snap and getattr(snap, "next", None))
    except Exception:  # noqa: BLE001
        return False


def _run_graph_traced(state, graph=None):
    """Run the graph with LangGraph's OWN per-node instrumentation.

    `.invoke()` returns the final state and nothing else, so a build that
    exhausted its iterations left no record of WHICH nodes ran, how long each
    took, or which one raised — the 61% of builds that stop at
    off_target / axis_exhausted / max_iters were diagnosed from node-authored
    trace lines alone, and a node that never ran authored none.

    `stream_mode=["debug", "values"]` is built in, local, and needs no
    checkpointer and no hosted service: "debug" yields a task / task_result
    pair per node, "values" yields the state after each superstep. The LAST
    "values" payload is byte-identical to what `.invoke()` returns — verified
    against this langgraph build before the switch, because getting the final
    state wrong would break every build rather than just the tracing.

    Fail-soft in both directions: if the stream yields no "values" at all we
    fall back to `.invoke()` rather than returning a half-state, and a tracing
    error never interrupts the run.
    """
    import time as _t
    from api import _poc_trace
    run_id = state.get("run_id")

    # CHECKPOINTED RUN. State lands in Postgres keyed on thread_id = run_id,
    # so a build that dies mid-flight resumes from its last completed node
    # instead of starting over. On 2026-10-17 a rag-api restart during a
    # focused-10 killed all ten in-flight builds at HTTP:000; with a
    # checkpointer those resume.
    #
    # Fail-soft in every direction: no package, no DSN, failed init or failed
    # setup all fall through to an uncheckpointed graph. Losing recovery is
    # acceptable; losing the build is not.
    _cm = None if graph is not None else _saver_cm()
    _entered = None
    cfg = None
    try:
        if _cm is not None:
            try:
                _entered = _cm.__enter__()
                _entered.setup()   # idempotent; shares the session tables
                graph = build_graph(_entered)
                cfg = {"configurable": {"thread_id": str(run_id or "")}}
            except Exception as _e:  # noqa: BLE001
                logging.getLogger(__name__).warning(
                    "build-poc: checkpointing unavailable (%s) — running "
                    "unrecoverable", _e)
                if _entered is not None:
                    try:
                        _cm.__exit__(None, None, None)
                    except Exception:  # noqa: BLE001
                        pass
                    _entered = None
                graph = None
                cfg = None
        if graph is None:
            graph = build_graph()
        return _stream_graph(graph, state, cfg, run_id, _poc_trace, _t)
    finally:
        if _entered is not None:
            try:
                _cm.__exit__(None, None, None)
            except Exception:  # noqa: BLE001
                pass


def _stream_graph(graph, state, cfg, run_id, _poc_trace, _t):
    """Stream the graph, tracing each node, and return the final state."""
    final = None
    started = {}
    order = []
    # RESUME vs FRESH is load-bearing: with a checkpointer, passing the full
    # initial state again RESTARTS the graph, while passing None resumes from
    # the last completed node. Backwards, this silently re-runs a
    # 12-iteration build from scratch.
    _resume = bool(cfg) and _has_checkpoint(graph, cfg)
    if _resume:
        try:
            _poc_trace(run_id, "resume",
                       response="resuming from the last completed node",
                       extra={"resumed": True})
        except Exception:  # noqa: BLE001
            pass
    _input = None if _resume else state
    _kw = {"stream_mode": ["debug", "values"]}
    if cfg:
        _kw["config"] = cfg
    for mode, payload in graph.stream(_input, **_kw):
        if mode == "values":
            final = payload
            continue
        if mode != "debug" or not isinstance(payload, dict):
            continue
        try:
            kind = payload.get("type")
            body = payload.get("payload") or {}
            name = body.get("name")
            if not name:
                continue
            if kind == "task":
                started[name] = _t.time()
                order.append(name)
            elif kind == "task_result":
                elapsed = None
                if name in started:
                    elapsed = round(_t.time() - started.pop(name), 3)
                err = body.get("error")
                _poc_trace(run_id, "node",
                           response=("%s %s%s" % (
                               name, "FAILED" if err else "ok",
                               f" in {elapsed}s" if elapsed is not None else "")),
                           extra={"node": name,
                                  "step": payload.get("step"),
                                  "seconds": elapsed,
                                  "ok": not err,
                                  "error": str(err)[:300] if err else None,
                                  "interrupted": bool(body.get("interrupts"))})
        except Exception:  # noqa: BLE001
            # Instrumentation must never take down the build it observes.
            pass
    if final is None:
        # The stream produced no state — do not hand back a half-built dict.
        return graph.invoke(state, **({"config": cfg} if cfg else {}))
    try:
        _poc_trace(run_id, "node_path",
                   response="%d node(s): %s" % (len(order), " -> ".join(order)),
                   extra={"nodes": order, "node_count": len(order)})
    except Exception:  # noqa: BLE001
        pass
    return final


def summarize_state(final: Dict[str, Any], declared=None) -> Dict[str, Any]:
    """A bounded, reviewable picture of what the graph KNEW when it finished.

    The state is the pipeline's entire memory -- 69 fields carrying the recon,
    the session, the manifest, the facts, the verdict -- and at the end of a
    run it was discarded. The trace recorded what each node SAID; nothing
    recorded what the pipeline ENDED UP KNOWING. So "why did synthesis not use
    the session" or "did the manifest ever get a product" could only be
    answered by replaying node output and inferring.

    Bounded on purpose. Dumping the state verbatim would write tens of
    kilobytes of recon segments into every run's trace and bury the signal it
    is meant to surface, so each field is reduced to its SHAPE -- type, size,
    and the value itself only when it is small enough to read.

    Returns {"populated": n, "empty": n, "fields": {name: shape}, "missing":
    [...], "verdict": {...}} -- never raises.
    """
    try:
        declared = declared or list(getattr(BuildPocState, "__annotations__", {}) or {})
    except Exception:  # noqa: BLE001
        declared = []
    fields, empty, missing = {}, 0, []
    for name in sorted(declared):
        if name not in (final or {}):
            missing.append(name)
            continue
        v = (final or {}).get(name)
        if v is None or v == "" or v == [] or v == {}:
            empty += 1
            fields[name] = "empty"
            continue
        if isinstance(v, (bool, int, float)):
            fields[name] = v
        elif isinstance(v, str):
            fields[name] = v if len(v) <= 80 else "str(%d chars)" % len(v)
        elif isinstance(v, (list, tuple)):
            fields[name] = "list(%d)" % len(v)
        elif isinstance(v, dict):
            # The KEYS of a dict are the useful part at a glance -- they say
            # which sub-facts exist -- and they are small.
            ks = sorted(str(k) for k in v)[:12]
            fields[name] = "dict(%d): %s" % (len(v), ks)
        else:
            fields[name] = type(v).__name__
    # `result` is normally the refine loop's verdict dict, but a crashed or
    # half-built run can leave anything there. Coerce rather than trust: the
    # docstring promises this never raises, and `"a string".get(...)` is
    # exactly how that promise gets broken.
    res = (final or {}).get("result")
    if not isinstance(res, dict):
        res = {}
    return {
        "populated": len(fields) - empty,
        "empty": empty,
        "missing": missing,
        "fields": fields,
        # The verdict, pulled out so a reader does not have to hunt for it.
        "verdict": {
            "verified": res.get("verified", (final or {}).get("verified")),
            "success": res.get("success", (final or {}).get("success")),
            "stop_reason": res.get("stop_reason"),
            "iterations": res.get("iterations", (final or {}).get("iters")),
            "off_target": res.get("off_target"),
            "drifted": res.get("drifted"),
            "verification_method": res.get("verification_method"),
        },
    }


def invoke_build_poc(state: BuildPocState) -> Dict[str, Any]:
    """Run the graph and return the same dict shape _build_poc_core returned to
    its endpoint caller: {command, assertion, canary, success, verified,
    off_target, reflection, iterations, exploit_store_id, ...}."""
    # ── Announce the run BEFORE doing any of it ─────────────────────────────
    #
    # `build_poc_endpoint` is a synchronous def: it blocks for the whole build
    # (10-25 min observed) and the UI awaits that single response, so until
    # now the FIRST evidence a run existed was the attempt row written at the
    # END. An operator who pressed Build PoC had nothing to look at and no way
    # to tell "running" from "never started" — which is exactly how two
    # concurrent runs of CVE-2026-21589 went unnoticed on 2026-10-16.
    #
    # The row is upserted on run_id, so the end-of-run record updates this one
    # rather than racing it. Fail-soft: a status row is not worth failing a
    # build over.
    try:
        from api import _record_build_poc_attempt, _poc_run_file
        _record_build_poc_attempt(
            run_id=state.get("run_id"), cve=state.get("cve"), ip=state.get("ip"),
            port=state.get("port"), eid=state.get("eid"),
            stage_reached="running",
            poc_log_path=_poc_run_file(state.get("run_id")))
    except Exception as e:  # noqa: BLE001
        import logging as _lg
        _lg.getLogger(__name__).warning(
            "build-poc: could not record the start of %s: %s",
            state.get("run_id"), e)
    try:
        final = _run_graph_traced(state)
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
    # The graph's final state, summarised into the trace. See summarize_state:
    # the state is the pipeline's whole memory and it used to be discarded at
    # this point, so a reviewer could see what each node said but not what the
    # run ended up knowing.
    try:
        from api import _poc_trace
        _summary = summarize_state(final)
        _poc_trace(state.get("run_id"), "graph_state_summary",
                   response=("graph finished: %d fields populated, %d empty, "
                             "%d never set | verdict=%s"
                             % (_summary["populated"], _summary["empty"],
                                len(_summary["missing"]), _summary["verdict"])),
                   extra=_summary)
    except Exception as _sse:  # noqa: BLE001
        logging.debug("graph state summary failed: %s", _sse)
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
