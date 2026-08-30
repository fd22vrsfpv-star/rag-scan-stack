"""LLM synthesis of a CUSTOM security test for one finding.

The long-term direction (memory: custom-tests-direction) is to move past picking
a fixed tool toward the agent AUTHORING a bespoke command/payload + assertion for
a specific finding. This is the prototype of that step.

It does NOT execute anything and it does NOT relax any gate. The LLM only writes
a candidate {command, assertion, tier}; the SAME machinery then applies:
  * tier is decided by the engine's `_classify` (fail-safe) on the SYNTHESIZED
    command — the LLM's own opinion cannot upgrade a test to the safe lane;
  * a safe candidate still runs through the scope-gated /tools/execute;
  * an impactful candidate still needs human approval.

Runs in the autogen container so it uses the resolved LLM backend (dashboard-DB
first — Azure DeepSeek here), NOT rag-api's ollama path which is not the active
backend. Reuses langgraph_engine's classifier + category vocab (no duplication).
"""
from __future__ import annotations

import json
import re
from typing import Any, Dict, Optional

# Reuse the ONE classifier + vocab (no duplicated safe/impactful logic).
from langgraph_engine import (
    _classify, _tool_head, _SAFE_CATEGORIES, _IMPACTFUL_CATEGORIES,
    _SAFE_TOOL_HINTS, _chat_model,
)
from db_utils import CLAUSE_KEYS  # shared clause vocabulary (autogen container)

# Tokens that make a command impactful no matter what category the LLM claims —
# they change data, write files, or open a shell. Belt-and-braces on top of
# _classify (which is category+tool based).
_DANGER = (
    "--dump", "--os-shell", "--sql-shell", "--file-write", "--file-dest",
    "-os-pwn", "meterpreter", "msfconsole", "bash -i", "/dev/tcp", " nc ",
    "ncat ", "; rm ", "&& rm", "rm -rf", "> /", ">> /", "-X put", "-X delete",
    "curl -t ", "--upload-file", "mkfifo", "chmod +x",
)


def _extract_json(text: str) -> Optional[dict]:
    if not text:
        return None
    fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.S)
    if fence:
        try:
            return json.loads(fence.group(1))
        except Exception:
            pass
    a, b = text.find("{"), text.rfind("}")
    if a >= 0 and b > a:
        try:
            return json.loads(text[a:b + 1])
        except Exception:
            return None
    return None


def classify_synth(category: str, command: str, llm_tier: str) -> str:
    """Fail-safe tier for a synthesized test. Safe requires ALL of: the engine's
    _classify says safe, the LLM did not itself flag impactful, and no dangerous
    token appears in the command. Anything else is impactful."""
    cmd = (command or "").lower()
    if any(tok in cmd for tok in _DANGER):
        return "impactful"
    if str(llm_tier).lower() == "impactful":
        return "impactful"
    return _classify(category if category in _SAFE_CATEGORIES else "rce",
                     command or "", has_exploit_ref=False)


_PROMPT = """You are a senior penetration tester. Write ONE concrete, MINIMAL \
security test that PROVES the web finding below, following the OWASP WSTG \
methodology provided.

Finding:
  type: {issue_type}
  name: {name}
  cwe: {cwe}
  target: {target}
  url: {url}

WSTG methodology (how to test):
{guidance}

Rules:
- The command must be a single shell command using ONLY: curl, nuclei, sslscan, \
sqlmap (detection only), httpx, wget, gobuster, ffuf, whatweb, nikto, dig.
- Prefer a SAFE, read-only detection probe. Mark tier "impactful" ONLY if the \
command changes data, writes files, dumps a database, or executes code.
- The assertion must be machine-checkable using ONLY these keys: \
{clause_keys}. Choose the observable that distinguishes vulnerable from not.
- Use {{url}} / {{target}} placeholders if you don't have a concrete value.

Reply with ONLY this JSON (no prose):
{{"tool":"<tool>","command":"<one shell command>","category":"<short_slug>",\
"tier":"safe|impactful","assertion":{{...}},"rationale":"<=160 chars why this proves it"}}"""


def synthesize(finding: Dict[str, Any], guidance: str = "",
               *, max_tokens: int = 700) -> Dict[str, Any]:
    """Author a candidate custom test for `finding`. Returns
    {ok, spec:{name,tool,command,category,tier,assertion,rationale}, raw, error}.
    The returned tier is the FAIL-SAFE tier, not necessarily the LLM's."""
    issue = finding.get("issue_type") or finding.get("finding_type") or finding.get("name") or ""
    prompt = _PROMPT.format(
        issue_type=issue, name=finding.get("name") or "",
        cwe=finding.get("cwe") or "", target=finding.get("target") or "",
        url=finding.get("url") or finding.get("target") or "",
        guidance=(guidance or "(no WSTG guidance matched)")[:3500],
        clause_keys=", ".join(sorted(CLAUSE_KEYS)),
    )
    try:
        model = _chat_model()
        resp = model.invoke(prompt)
        raw = getattr(resp, "content", None) or str(resp)
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": f"llm call failed: {e}", "spec": None, "raw": ""}

    obj = _extract_json(raw)
    if not obj or not obj.get("command"):
        return {"ok": False, "error": "no valid JSON test in model reply",
                "spec": None, "raw": raw[:800]}

    command = str(obj["command"]).strip()
    category = str(obj.get("category") or "http_probe").strip()[:60]
    assertion = obj.get("assertion") if isinstance(obj.get("assertion"), dict) else {}
    assertion = {k: v for k, v in assertion.items() if k in CLAUSE_KEYS}
    tier = classify_synth(category, command, obj.get("tier", "safe"))
    # Keep the category coherent with the fail-safe tier so the DB lane check and
    # the engine agree: a safe tier must carry a safe category.
    if tier == "safe" and category not in _SAFE_CATEGORIES:
        category = "http_probe"
    if tier == "impactful" and category not in _IMPACTFUL_CATEGORIES:
        category = "rce"
    spec = {
        "name": (f"AI:{issue[:48]}" if issue else "AI custom test"),
        "tool": _tool_head(command) or (obj.get("tool") or "curl"),
        "command": command, "category": category, "tier": tier,
        "assertion": assertion or {"min_output_bytes": 1},
        "rationale": str(obj.get("rationale") or "")[:200],
    }
    return {"ok": True, "spec": spec, "raw": raw[:400], "error": None}
