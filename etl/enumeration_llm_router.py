"""LLM router for enumeration: per-task model routing + triage + fact review.

Two LLM ROLES exist in the enumeration pipeline, and they want different
handling:

  * EXTRACTION — read output that the deterministic extractors
    (knowledge/enumeration_extractors.yaml) missed and propose structured facts.
  * REVIEW     — validate candidate facts (from BOTH the deterministic extractors
    AND the LLM fallback) before they become proposals/observations, so a
    low-confidence generic match or an LLM guess does not fill the queue with
    false positives.

The ROUTER does two things:

  1. Selects the model / params per role from operator config
     (app_settings, category 'config', keys ``enum_router.*``; code defaults when
     unset — same mechanism as the session watchdog). The model defaults to None
     so llm_query TASK-ROUTES it (a hardcoded model masquerades as a caller
     choice and 404s on task-routing backends — see memory
     llm-query-model-default-defeats-routing); an operator may pin one per role.
  2. TRIAGES each output chunk so the LLM runs only when it adds value:
     deterministic extractors first, LLM extraction only when they miss and the
     output is substantive; review only over the facts that are actually
     uncertain (configurable to all).

Fail direction:
  * extraction fails CLOSED — an error yields no extra facts, never acts blind.
  * review fails OPEN — an error keeps the facts as-is, so a reviewer outage does
    not silently drop real findings.

No hard dependency on post_enumeration: it imports this, not the other way round.
"""
from __future__ import annotations

import logging
import os
import re
import time
from typing import Any, Callable, Dict, List, Optional

log = logging.getLogger("enumeration_llm_router")

# llm_query listens on HTTP, not HTTPS — an https:// URL fails with an SSL
# "record layer failure" and every router LLM call then fails closed silently.
LLM_URL = os.environ.get("LLM_URL", "http://llm_query:8002/ollama/chat")

# Fact kinds the LLM roles may emit / keep — the vocabulary the extractors and
# rules already speak. An invented kind nothing consumes is dropped.
ALLOWED_FACTS = {"secret", "host", "file", "credential", "share", "host_fact"}

# Global kill switch (kept for backward-compat with ENUMERATION_LLM_FALLBACK).
_GLOBAL_ENABLED = os.environ.get("ENUMERATION_LLM_FALLBACK", "1") not in (
    "0", "false", "False", "")

# Code defaults; app_settings overrides per key. Namespaced + globally unique so
# they set the same way as every other tunable (/settings/config/{key}).
_DEFAULTS: Dict[str, Any] = {
    "enum_router.extraction.enabled": True,
    "enum_router.extraction.model": None,      # None => llm_query task-routes it
    "enum_router.extraction.temperature": 0.0,
    "enum_router.extraction.max_tokens": 600,
    "enum_router.extraction.min_chars": 40,
    "enum_router.extraction.max_chars": 6000,
    # HARD budget: at most this many LLM extraction calls per rolling window,
    # process-wide. The post-enumeration sweep re-analyses up to 100 historical
    # executions in a loop; without a budget an LLM-per-row turns a fast sweep
    # into a 30-minute one (observed). This caps the blast radius even if a
    # caller forgets to disable the LLM for batch work.
    "enum_router.extraction.max_per_window": 8,
    "enum_router.extraction.window_sec": 300,
    "enum_router.review.enabled": True,
    "enum_router.review.model": None,
    "enum_router.review.temperature": 0.0,
    "enum_router.review.max_tokens": 500,
    # which facts to review: "uncertain" (llm-sourced / generic / low-confidence)
    # or "all".
    "enum_router.review.scope": "uncertain",
    # DEEPEN: investigate an informational finding the deterministic rules did
    # not name — propose ONE read-only probe to turn a "note" into evidence.
    "enum_router.deepen.enabled": True,
    "enum_router.deepen.model": None,
    "enum_router.deepen.temperature": 0.0,
    "enum_router.deepen.max_tokens": 400,
    "enum_router.deepen.max_per_window": 6,
    "enum_router.deepen.window_sec": 300,
    # PROMOTION: turn a shape the LLM keeps discovering into a permanent extractor.
    "enum_router.promotion.enabled": True,
    # Auto-approve a proposed extractor once its kind has this many PRIOR confirmed
    # sightings. 0 = never auto-approve (operator approves every one manually) —
    # the safe default: a one-off LLM guess never becomes a permanent rule on its
    # own. Set to e.g. 3 to let a shape seen 3+ times activate automatically.
    "enum_router.promotion.auto_approve_after": 0,
}

_SETTINGS_TTL = int(os.environ.get("ENUM_ROUTER_SETTINGS_TTL", "60"))


def _as_bool(v: Any, default: bool) -> bool:
    if v is None:
        return default
    if isinstance(v, bool):
        return v
    return str(v).strip().lower() in ("true", "1", "yes", "on")


class EnumerationLLMRouter:
    """Routes enumeration LLM calls by role, triages when to call, and reviews
    facts. One instance is fine to share (settings are cached with a TTL)."""

    def __init__(self, connect: Optional[Callable[[], Any]] = None):
        self._connect = connect
        self._cache: Dict[str, Any] = {}
        self._cache_at: float = 0.0
        self._extract_calls: List[float] = []   # timestamps, for the budget
        self._deepen_calls: List[float] = []     # separate budget for deepen()

    # ── config ───────────────────────────────────────────────────────────────
    def _settings(self) -> Dict[str, Any]:
        now = time.time()
        if self._cache and (now - self._cache_at) < _SETTINGS_TTL:
            return self._cache
        merged = dict(_DEFAULTS)
        rows: Dict[str, str] = {}
        try:
            conn = self._connect() if self._connect else self._default_connect()
            try:
                with conn.cursor() as cur:
                    cur.execute("SELECT key, value FROM public.app_settings "
                                "WHERE category = 'config' AND key = ANY(%s)",
                                (list(_DEFAULTS.keys()),))
                    rows = {k: v for k, v in cur.fetchall()}
            finally:
                conn.close()
        except Exception:  # noqa: BLE001
            log.debug("enum router: app_settings unavailable; using defaults",
                      exc_info=True)
        for key, raw in rows.items():
            default = _DEFAULTS.get(key)
            if isinstance(default, bool):
                merged[key] = _as_bool(raw, default)
            elif isinstance(default, int) and not isinstance(default, bool):
                try:
                    merged[key] = int(raw)
                except (TypeError, ValueError):
                    pass
            elif isinstance(default, float):
                try:
                    merged[key] = float(raw)
                except (TypeError, ValueError):
                    pass
            else:  # str / None
                merged[key] = (raw if raw not in (None, "", "null", "None")
                               else default)
        self._cache = merged
        self._cache_at = now
        return merged

    @staticmethod
    def _default_connect():
        import psycopg2
        dsn = os.environ.get("DB_DSN",
                             "postgresql://app:app@rag-postgres:5432/scans")
        c = psycopg2.connect(dsn, connect_timeout=5)
        c.autocommit = True
        return c

    def route(self, task: str) -> Dict[str, Any]:
        """Params for a role: {'enabled','model','temperature','max_tokens', ...}."""
        s = self._settings()
        p = f"enum_router.{task}."
        return {k[len(p):]: v for k, v in s.items() if k.startswith(p)}

    # ── LLM call ───────────────────────────────────────────────────────────────
    def _call_llm(self, system: str, user: str, params: Dict[str, Any]) -> str:
        import requests
        body: Dict[str, Any] = {
            "messages": [{"role": "system", "content": system},
                         {"role": "user", "content": user}],
            "max_tokens": int(params.get("max_tokens") or 500),
            "temperature": float(params.get("temperature") or 0.0),
        }
        model = params.get("model")
        if model:                       # omit => llm_query task-routes it
            body["model"] = model
        resp = requests.post(LLM_URL, json=body, timeout=60, verify=False)
        if resp.status_code >= 400:
            log.debug("enum router LLM HTTP %s: %s", resp.status_code,
                      resp.text[:160])
            return ""
        data = resp.json()
        if not isinstance(data, dict):
            return ""
        msg = data.get("message")
        if isinstance(msg, dict) and msg.get("content"):
            return msg["content"]
        ch = data.get("choices")
        if isinstance(ch, list) and ch:
            content = ((ch[0] or {}).get("message") or {}).get("content")
            if content:
                return content
        return data.get("response") or data.get("content") or ""

    @staticmethod
    def _first_json(text: str):
        import json as _json
        import re as _re
        m = _re.search(r"\{.*\}", text or "", _re.S)
        if not m:
            return None
        try:
            return _json.loads(m.group(0))
        except Exception:  # noqa: BLE001
            return None

    # ── triage / budget ─────────────────────────────────────────────────────
    def _within_budget(self, p: Dict[str, Any], *, consume: bool = False,
                       bucket: Optional[List[float]] = None) -> bool:
        """Token-bucket over a rolling window, process-wide. Read-only unless
        `consume`. `bucket` selects which call log (extraction vs deepen)."""
        if bucket is None:
            bucket = self._extract_calls
        window = float(p.get("window_sec") or 300)
        cap = int(p.get("max_per_window") or 8)
        now = time.time()
        bucket[:] = [t for t in bucket if now - t < window]
        if len(bucket) >= cap:
            return False
        if consume:
            bucket.append(now)
        return True

    def should_extract(self, output: str, deterministic_facts: List[Dict]) -> bool:
        """LLM extraction runs only when the deterministic extractors found
        NOTHING, the output is substantive (within size bounds), AND the rolling
        budget is not exhausted."""
        if not _GLOBAL_ENABLED or deterministic_facts:
            return False
        p = self.route("extraction")
        if not p.get("enabled"):
            return False
        n = len((output or "").strip())
        if n < int(p.get("min_chars") or 40):
            return False
        return self._within_budget(p)

    # ── extraction ───────────────────────────────────────────────────────────
    def extract(self, output: str, *, tool: str = "", target: str = "",
                service: str = "") -> List[Dict[str, Any]]:
        """Classify output that matched no extractor into structured facts.
        Fails CLOSED (returns [] on any problem)."""
        p = self.route("extraction")
        text = (output or "").strip()
        if not _GLOBAL_ENABLED or not p.get("enabled"):
            return []
        if len(text) < int(p.get("min_chars") or 40):
            return []
        # Consume the rolling budget; refuse once exhausted so a batch caller
        # cannot fire an unbounded number of LLM calls.
        if not self._within_budget(p, consume=True):
            log.debug("enum router extraction budget exhausted; skipping")
            return []
        text = text[:int(p.get("max_chars") or 6000)]
        try:
            system = (
                "You are a penetration-test post-exploitation analyst reading the "
                "raw output of a command for AUTHORIZED security testing. The "
                "platform's pattern matchers found NOTHING actionable in it. "
                "Identify anything a tester would act on and return ONLY JSON, no "
                'prose: {"facts":[{"fact":"secret|host|file|credential|host_fact",'
                '"kind":"<short kind, e.g. api_token, config_path>",'
                '"value":"<the literal string found>",'
                '"why":"<one short reason it matters>"}]}. Only include something '
                'actually present in the output. If nothing is actionable, return '
                '{"facts":[]}. Never invent values.')
            user = (f"Tool: {tool}\nTarget: {target}\nService: {service}\n"
                    f"Output:\n{text}")
            parsed = self._first_json(self._call_llm(system, user, p))
            raw = parsed.get("facts") if isinstance(parsed, dict) else None
            if not isinstance(raw, list):
                return []
            facts: List[Dict[str, Any]] = []
            for rf in raw[:25]:
                if not isinstance(rf, dict):
                    continue
                kind_fact = str(rf.get("fact") or "").strip().lower()
                if kind_fact not in ALLOWED_FACTS:
                    continue
                val = rf.get("value")
                if not val:
                    continue
                fact: Dict[str, Any] = {
                    "fact": kind_fact,
                    "kind": str(rf.get("kind") or "llm").strip()[:40],
                    "value": str(val)[:300],
                    "service": service,
                    "source": "llm_fallback",
                    "confidence": "low",
                    "why": str(rf.get("why") or "")[:200],
                    "line": str(val)[:200],
                }
                fact["target"] = (str(val) if kind_fact == "host" else target)
                if kind_fact == "host":
                    fact["seen_on"] = target
                facts.append(fact)
            return facts
        except Exception as e:  # noqa: BLE001
            log.debug("enum router extraction failed: %s", e)
            return []

    # ── review ─────────────────────────────────────────────────────────────────
    def _needs_review(self, fact: Dict[str, Any], scope: str) -> bool:
        if scope == "all":
            return True
        # "uncertain": LLM-sourced, the low-confidence generic catch, or anything
        # already flagged low confidence.
        return (fact.get("source") == "llm_fallback"
                or fact.get("kind") == "generic"
                or fact.get("confidence") == "low")

    def review(self, facts: List[Dict[str, Any]], *, output: str = "",
               target: str = "", service: str = "") -> Dict[str, Any]:
        """Validate candidate facts before they are queued. Returns
        {"facts": kept_facts, "reviewed": n, "dropped": n}. Fails OPEN — an error
        keeps every fact, so a reviewer outage never silently drops findings."""
        result = {"facts": facts, "reviewed": 0, "dropped": 0}
        if not facts:
            return result
        p = self.route("review")
        if not _GLOBAL_ENABLED or not p.get("enabled"):
            return result
        scope = str(p.get("scope") or "uncertain")
        idx = [i for i, f in enumerate(facts) if self._needs_review(f, scope)]
        if not idx:
            return result
        try:
            import json as _json
            lines = []
            for i in idx:
                f = facts[i]
                lines.append(f"{i}. fact={f.get('fact')} kind={f.get('kind')} "
                             f"value={str(f.get('value') or f.get('path') or f.get('target'))[:160]} "
                             f"why={str(f.get('why') or '')[:120]}")
            system = (
                "You are validating candidate findings extracted from penetration-"
                "test enumeration output, for AUTHORIZED security testing. For each "
                "numbered item decide if it is a REAL, actionable finding actually "
                "supported by the output, or a FALSE POSITIVE (a placeholder, an "
                "example value, a variable name with no secret, a self/reserved "
                "host, unrelated text). Return ONLY JSON: "
                '{"verdicts":[{"i":<index>,"keep":true|false,'
                '"confidence":"high|medium|low","reason":"<short>"}]}. '
                "Judge only from the output; when unsure, keep it and mark "
                "confidence low.")
            user = (f"Target: {target}\nService: {service}\n"
                    f"Output (context):\n{(output or '')[:4000]}\n\n"
                    f"Candidate findings:\n" + "\n".join(lines))
            parsed = self._first_json(self._call_llm(system, user, p))
            verdicts = parsed.get("verdicts") if isinstance(parsed, dict) else None
            if not isinstance(verdicts, list):
                return result                       # fail open
            vmap = {}
            for v in verdicts:
                if isinstance(v, dict) and isinstance(v.get("i"), int):
                    vmap[v["i"]] = v
            kept: List[Dict[str, Any]] = []
            dropped = 0
            for i, f in enumerate(facts):
                v = vmap.get(i)
                if v is None:
                    kept.append(f)                  # not judged -> keep
                    continue
                result["reviewed"] += 1
                if v.get("keep") is False:
                    dropped += 1
                    continue
                f = dict(f)
                f["review"] = {"kept": True,
                               "confidence": str(v.get("confidence") or "low"),
                               "reason": str(v.get("reason") or "")[:200]}
                kept.append(f)
            result["facts"] = kept
            result["dropped"] = dropped
            return result
        except Exception as e:  # noqa: BLE001
            log.debug("enum router review failed (keeping all): %s", e)
            return {"facts": facts, "reviewed": 0, "dropped": 0}

    # ── deepen ─────────────────────────────────────────────────────────────────
    _DEEPEN_TOOLS = {"curl", "wget", "http", "httpx", "nuclei", "whatweb"}
    # Tools allowed for an IMPACTFUL confirmation of a STATE-CHANGING finding (a
    # POST-body SQLi cannot be reproduced by a read-only GET). These route to the
    # human approval lane, never the safe lane — so a mutating tool is admissible.
    _DEEPEN_IMPACTFUL_TOOLS = {"curl", "wget", "http", "httpx", "sqlmap"}

    @staticmethod
    def _probe_is_impactful(cmd: str) -> bool:
        """A confirmation probe is IMPACTFUL (state-changing → approval lane) if it
        runs sqlmap or sends a request body / non-GET method. `curl -G/--get`
        appends --data as a GET QUERY STRING, so with -G a --data probe is
        read-only again (only sqlmap stays impactful)."""
        head = (cmd.split() or [""])[0].split("/")[-1].lower()
        if head == "sqlmap":
            return True
        get_mode = bool(re.search(r"(?:^|\s)(?:-G|--get)(?:\s|$)", cmd))
        if get_mode:
            return False
        return bool(re.search(
            r"(?:^|\s)(?:-X\s*(?:POST|PUT|PATCH|DELETE)\b|--data\b|--data-raw\b"
            r"|--data-binary\b|--data-urlencode\b|-d\b|-F\b|--form\b)", cmd))

    def deepen_finding(self, finding: Dict[str, Any],
                       force: bool = False) -> Optional[Dict[str, Any]]:
        """Investigate a finding: ask the LLM for ONE confirmation probe that turns
        it into evidence. Returns {command, why, assertion, tier} or None.
        Budget-capped (separate bucket) and fail-CLOSED.

        METHOD-AWARE. A finding on a POST/PUT/PATCH/DELETE request (or a body
        parameter) CANNOT be reproduced by a read-only GET — the classic case is a
        POST-body SQL injection at a login form, where a `curl -G` probe just hits
        the app and returns the same redirect for any input. For a state-changing
        finding this asks for an IMPACTFUL confirmation (curl -X POST/--data, or
        sqlmap --data) and returns tier='impactful', which the caller routes to the
        human APPROVAL lane (never the safe lane); a read-only GET returned for a
        state-changing finding is the dead-probe bug this fixes, so it is REJECTED
        (fail-closed). A GET finding keeps the read-only probe, tier='safe'.

        force=True is the OPERATOR-INITIATED path ("Deepen this finding" button):
        propose the best probe regardless of the auto-triage `worth` verdict, and
        bypass the enabled-flag (the operator asked for it explicitly)."""
        p = self.route("deepen")
        if not _GLOBAL_ENABLED or (not force and not p.get("enabled")):
            return None
        url = finding.get("url") or finding.get("target") or ""
        name = finding.get("name") or finding.get("issue_type") or ""
        if not url or not name:
            return None
        method = str(finding.get("method") or finding.get("http_method") or "GET").upper()
        param = (finding.get("param") or finding.get("parameter")
                 or finding.get("param_name") or "")
        state_changing = method in ("POST", "PUT", "PATCH", "DELETE")
        if not self._within_budget(p, consume=True, bucket=self._deepen_calls):
            return None
        try:
            worth_clause = (
                "The operator has explicitly asked to investigate this finding, so "
                "ALWAYS propose the best probe (set worth=true)."
                if force else
                "Decide whether it is worth a deeper look.")
            if state_changing:
                shape = (
                    f"This finding is on an HTTP {method} request, so a read-only GET "
                    f"CANNOT reproduce it. Give ONE IMPACTFUL confirmation probe that "
                    f"uses {method}: either `curl -s -i -X {method} --data '<body>' "
                    f"'<url>'` or `sqlmap -u '<url>' --data '<body>' -p <param> "
                    f"--batch --smart --level 1 --risk 1`. It WILL be routed to the "
                    f"human approval lane before it runs. MUST start with one of: "
                    f"curl, wget, http, httpx, sqlmap.")
            else:
                shape = (
                    "Give ONE READ-ONLY probe (GET, no side effects) that turns the "
                    "finding into evidence. MUST start with one of: curl, wget, http, "
                    "httpx, nuclei, whatweb.")
            system = (
                "You are triaging a web finding for AUTHORIZED security testing. "
                f"{worth_clause} {shape} Return ONLY JSON: "
                '{"worth": true|false, "command": "<one command using the URL>", '
                '"assertion": {"contains": "<expected string>"}, '
                '"why": "<one short sentence>"}. If not worth deepening, '
                '{"worth": false}.')
            user = (f"Finding: {name}\nURL: {url}\nHTTP method: {method}\n"
                    f"Parameter: {param}\nType: {finding.get('issue_type') or ''}\n"
                    f"Known payload: {str(finding.get('payload') or '')[:200]}")
            parsed = self._first_json(self._call_llm(system, user, p))
            if not isinstance(parsed, dict) or (not force and not parsed.get("worth")):
                return None
            cmd = str(parsed.get("command") or "").strip()
            head = (cmd.split() or [""])[0].split("/")[-1].lower()
            if not cmd:
                return None
            impactful = self._probe_is_impactful(cmd)
            if state_changing and not impactful:
                # A read-only GET cannot confirm a state-changing finding: never
                # queue the dead probe.
                log.debug("deepen: refusing read-only probe for %s finding on %s",
                          method, url)
                return None
            tier = "impactful" if impactful else "safe"
            allow = self._DEEPEN_IMPACTFUL_TOOLS if impactful else self._DEEPEN_TOOLS
            if head not in allow:
                return None
            assertion = parsed.get("assertion") if isinstance(parsed.get("assertion"), dict) else {}
            return {"command": cmd, "why": str(parsed.get("why") or "")[:200],
                    "assertion": assertion, "tier": tier}
        except Exception as e:  # noqa: BLE001
            log.debug("enum router deepen failed: %s", e)
            return None


    def synth_login_macro(self, html: str, page_url: str) -> Optional[Dict[str, Any]]:
        """LLM fallback for auto-populate: read a login page the deterministic
        parser could not and return the Auth Profile macro fields. Budget-gated
        (deepen bucket), fail-CLOSED. Returns
        {login_url, login_data, csrf_field, auth_type} or None."""
        p = self.route("deepen")
        if not _GLOBAL_ENABLED or not (html or "").strip():
            return None
        if not self._within_budget(p, consume=True, bucket=self._deepen_calls):
            return None
        try:
            system = (
                "You are reading an HTML login page for AUTHORIZED security "
                "testing. Return ONLY JSON describing how to submit the login "
                "form: {\"login_url\":\"<absolute form action>\","
                "\"login_data\":\"field1={%username%}&field2={%password%}"
                "[&csrf={%csrf%}]\",\"csrf_field\":\"<hidden token field name or "
                "null>\"}. Use the placeholders {%username%}/{%password%}/{%csrf%} "
                "for those fields; carry other hidden fields with their literal "
                "values. If there is no login form, return {}.")
            user = f"Page URL: {page_url}\nHTML (truncated):\n{html[:6000]}"
            parsed = self._first_json(self._call_llm(system, user, p))
            if not isinstance(parsed, dict):
                return None
            ld = str(parsed.get("login_data") or "")
            if "{%username%}" not in ld or "{%password%}" not in ld:
                return None
            return {"login_url": str(parsed.get("login_url") or page_url),
                    "login_data": ld,
                    "csrf_field": parsed.get("csrf_field") or None,
                    "auth_type": "csrf" if parsed.get("csrf_field") else "form"}
        except Exception as e:  # noqa: BLE001
            log.debug("synth_login_macro failed: %s", e)
            return None


_ROUTER: Optional[EnumerationLLMRouter] = None


def get_router(connect: Optional[Callable[[], Any]] = None) -> EnumerationLLMRouter:
    """Shared router instance."""
    global _ROUTER
    if _ROUTER is None:
        _ROUTER = EnumerationLLMRouter(connect=connect)
    return _ROUTER
