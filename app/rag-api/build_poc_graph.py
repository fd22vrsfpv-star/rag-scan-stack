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
    guidance: str
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

    # Final verdict
    verified: bool
    reflection: bool
    off_target: bool
    exploit_store_id: Optional[str]
    result: Dict[str, Any]


def enabled() -> bool:
    """True when the LangGraph build path should be used. Env-flag default off."""
    return os.environ.get("BUILD_POC_LANGGRAPH", "0").lower() in ("1", "true", "yes", "on")


def initial_state(cve: str, ip: str, port: int, product=None, version=None, eid=None,
                  max_iters: int = 3, research: bool = True, model=None, auth=None,
                  recon_first: bool = False, recon_source: str = "basic",
                  hint: Optional[str] = None) -> BuildPocState:
    """Build the initial state dict handed to the graph. Mirrors the argument shape
    of _build_poc_core so the wrapper is trivial."""
    return {
        "cve": cve, "ip": ip, "port": port,
        "product": product, "version": version, "eid": eid,
        "max_iters": max_iters, "model": model, "research": research,
        "recon_first": recon_first, "recon_source": recon_source, "hint": hint,
        "run_id": f"{cve}_{ip}_{int(time.time())}",
        "t0": time.time(),
        "segments": [], "recon_metrics": {}, "intel_list": [],
        "zap_paths": [], "cred_hints": [], "admin_paths_mined": [],
        "detected_frameworks": [], "waf_family": None, "waf_characterization": {},
        "auth": auth or {}, "auth_guidance": "", "session_info": None,
        "hint_guidance": "", "hint_parts": [], "research_out": None,
        "recon_guidance": "", "strategy": "", "plan_verdicts": {}, "guidance": "",
        "built": None,
        "command": "", "assertion": {}, "canary": None, "origin_family": None,
        "llm_model": None, "output": "",
        "success": False, "drifted": False, "iters": 0, "escalated": False,
        "escalation_guidance": "", "metrics": {},
        "verified": False, "reflection": False, "off_target": False,
        "exploit_store_id": None, "result": {},
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
    cred_hints = list(dict.fromkeys(cred_hints))
    admin_paths = list(dict.fromkeys(admin_paths))
    detected_frameworks = list(dict.fromkeys(
        x.get("framework") for x in intel_list if x.get("framework")))
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
        note = (f"AUTO-LOGIN SUCCESS with mined creds {login['cred']} at "
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


def node_arjun_recon(state: BuildPocState) -> Dict[str, Any]:
    from api import _scout_arjun, _scout_arjun_paths, _poc_trace
    _t0 = time.time()
    zap_paths = state.get("zap_paths") or []
    if zap_paths:
        a, per_path = _scout_arjun_paths(state["ip"], state["port"], zap_paths)
        signal = f"honored params per endpoint (fanned across {len(per_path)} paths)"
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
            "recon_metrics": {**state.get("recon_metrics", {}), **metrics}}


# ── auth / hints / research ────────────────────────────────────────────────────
def node_auth_establish(state: BuildPocState) -> Dict[str, Any]:
    """Establish an authenticated session when the operator supplied creds OR when
    auto_login already captured a cookie. Matches the monolith exactly."""
    from api import _establish_session_for_build
    auth = state.get("auth") or {}
    auth_guidance = ""
    session_info = None
    if auth and (auth.get("username") or auth.get("bruteforce")):
        try:
            session_info = _establish_session_for_build(
                state["ip"], state["port"], auth, state.get("eid"))
            ch = (session_info or {}).get("cookie_header")
            if ch:
                auth_guidance = (f"AUTH: an authenticated session exists — send this cookie in "
                                 f"EVERY exploit request: Cookie: {ch}. (user "
                                 f"{session_info.get('username')}). ")
        except Exception as e:  # noqa: BLE001
            logging.debug("build auth step failed: %s", e)
    if auth and auth.get("_auto_cookie") and not auth_guidance:
        auth_guidance = (f"AUTH (auto-login from mined creds): send this cookie in EVERY "
                         f"exploit request: Cookie: {auth['_auto_cookie']}. "
                         f"Logged in at {auth.get('_auto_login_path', '?')} with credentials "
                         "extracted from a leaked README/docs — the app is now "
                         "AUTHENTICATED, target the admin backend for post-auth CVEs.")
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


def node_research(state: BuildPocState) -> Dict[str, Any]:
    """Fetch reference-PoC material from MSF/ExploitDB/NVD. Returns the analysis
    dict but does NOT compose the guidance string — that's assemble_guidance's job."""
    if not state.get("research"):
        return {"research_out": None}
    from api import _research_exploit
    try:
        research_out = _research_exploit(
            state["cve"], state["ip"], state["port"],
            state.get("product"), state.get("version"), state.get("eid"),
            model=state.get("model"))
    except Exception as e:  # noqa: BLE001
        logging.debug("build research step failed: %s", e)
        research_out = None
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
        guidance = (auth_guidance + " " + " ".join(parts)).strip()
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
    from api import _verify_strategist_plan, _poc_trace
    strategy = state.get("strategy") or ""
    if not strategy:
        return {}
    try:
        _auto_cookie = (state.get("auth") or {}).get("_auto_cookie")
        strategy_verified, verdicts = _verify_strategist_plan(
            state["ip"], state["port"], strategy, session_cookie=_auto_cookie)
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
    return {"strategy": strategy, "plan_verdicts": verdicts, "guidance": guidance}


# ── synth + run-refine loop ────────────────────────────────────────────────────
def node_synth(state: BuildPocState) -> Dict[str, Any]:
    from api import _synthesize_cve_poc
    built = _synthesize_cve_poc(
        state["cve"], state["ip"], state["port"],
        state.get("product"), state.get("version"), state.get("eid"),
        run_id=state["run_id"], guidance_extra=state.get("guidance") or "",
        model=state.get("model"))
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
    from api import _run_refine_poc
    built = state.get("built") or {}
    result = _run_refine_poc(
        state["cve"], state["ip"], state["port"],
        built["command"], built["assertion"], state.get("eid"),
        state["run_id"], rationale=built.get("rationale", ""),
        product=state.get("product"), version=state.get("version"),
        max_iters=state["max_iters"],
        canary=built.get("canary"), origin_family=built.get("origin_family"),
        llm_model=built.get("llm_model"), metrics=built.get("metrics"),
        model=state.get("model"),
        recon_source_used=state.get("recon_source"))
    return {"result": result,
            "verified": bool(result.get("verified")),
            "reflection": bool(result.get("reflection")),
            "off_target": bool(result.get("off_target")),
            "iters": int(result.get("iterations", 0)),
            "success": bool(result.get("success"))}


def node_save_store(state: BuildPocState) -> Dict[str, Any]:
    """Save the built PoC + emit webhook. Store verified/unverified — the
    unverified rows stay for operator inspection (same as monolith)."""
    from api import _save_exploit_store
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
                          "research_sources": (research_out or {}).get("sources")})
    except Exception:  # noqa: BLE001
        pass
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
    """After basic/mine/auto-login/deep-enum block, branch on want_zap then want_arjun."""
    if _want(state.get("recon_source", "basic"), "zap"):
        return "zap_recon"
    if _want(state.get("recon_source", "basic"), "arjun"):
        return "arjun_recon"
    return "auth_establish"


def _route_post_zap(state: BuildPocState) -> str:
    return "arjun_recon" if _want(state.get("recon_source", "basic"), "arjun") else "auth_establish"


# ── graph builder ──────────────────────────────────────────────────────────────
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
    g.add_node("port_sweep", node_port_sweep)
    g.add_node("waf_detect", node_waf_detect)
    g.add_node("waf_characterize", node_waf_characterize)
    g.add_node("basic_recon", node_basic_recon)
    g.add_node("response_mine", node_response_mine)
    g.add_node("auto_login", node_auto_login)
    g.add_node("framework_deep_enum", node_framework_deep_enum)
    g.add_node("zap_recon", node_zap_recon)
    g.add_node("arjun_recon", node_arjun_recon)

    # Auth / hints / research
    g.add_node("auth_establish", node_auth_establish)
    g.add_node("load_hints", node_load_hints)
    g.add_node("research", node_research)

    # Guidance assembly + strategy
    g.add_node("assemble_guidance", node_assemble_guidance)
    g.add_node("strategist", node_strategist)
    g.add_node("plan_verify", node_plan_verify)

    # Synth + execution + save
    g.add_node("synth", node_synth)
    g.add_node("run_refine", node_run_refine)
    g.add_node("save_store", node_save_store)

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
    g.add_node("_post_waf_hub", _post_waf_passthrough)
    g.add_conditional_edges("_post_waf_hub", _route_post_waf,
                             {"basic_recon": "basic_recon",
                              "post_mine": "_post_mine_hub"})

    # basic_recon -> response_mine -> (auto_login if creds, deep_enum if fw, else post_mine hub)
    g.add_edge("basic_recon", "response_mine")
    g.add_conditional_edges("response_mine", _route_after_response_mine,
                             {"auto_login": "auto_login",
                              "framework_deep_enum": "framework_deep_enum",
                              "post_mine": "_post_mine_hub"})
    g.add_conditional_edges("auto_login", _route_after_auto_login,
                             {"framework_deep_enum": "framework_deep_enum",
                              "post_mine": "_post_mine_hub"})
    g.add_edge("framework_deep_enum", "_post_mine_hub")

    # Pass-through hub after basic/mine/login/enum block converges
    g.add_node("_post_mine_hub", _post_waf_passthrough)
    g.add_conditional_edges("_post_mine_hub", _route_post_mine,
                             {"zap_recon": "zap_recon",
                              "arjun_recon": "arjun_recon",
                              "auth_establish": "auth_establish"})
    g.add_conditional_edges("zap_recon", _route_post_zap,
                             {"arjun_recon": "arjun_recon",
                              "auth_establish": "auth_establish"})
    g.add_edge("arjun_recon", "auth_establish")

    # Non-recon spine
    g.add_edge("auth_establish", "load_hints")
    g.add_edge("load_hints", "research")
    g.add_edge("research", "assemble_guidance")
    g.add_edge("assemble_guidance", "strategist")
    g.add_edge("strategist", "plan_verify")
    g.add_edge("plan_verify", "synth")
    g.add_edge("synth", "run_refine")
    g.add_edge("run_refine", "save_store")
    g.add_edge("save_store", END)

    return g.compile()


def invoke_build_poc(state: BuildPocState) -> Dict[str, Any]:
    """Run the graph and return the same dict shape _build_poc_core returned to
    its endpoint caller: {command, assertion, canary, success, verified,
    off_target, reflection, iterations, exploit_store_id, ...}."""
    graph = build_graph()
    final = graph.invoke(state)
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
