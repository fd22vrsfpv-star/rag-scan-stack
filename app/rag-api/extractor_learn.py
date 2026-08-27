"""Self-adapting extractor distiller.

The extractor design is "deterministic first; the prompt covers only what regexes
cannot" (see extractor_specs.py). This module closes the loop: when the model
fills a schema field that the deterministic regexes MISSED, it authors a stable
regex ONCE, validates that the regex re-extracts the same value, and stores it in
`extractor_learned` (status='active'). Every later run of that tool then extracts
the field deterministically — no model. It also PROPOSES a `notable` finding rule
for the newly-learned field (status='proposed') for operator review.

This is the same "LLM normalises once → reusable deterministic tool" pattern as
scope_classifier.distill_rule_from_decision, applied to tool-output extraction.
"""
import json
import logging
import re
from typing import Any, Dict, List, Optional

import extractor_specs as es

log = logging.getLogger("extractor_learn")

_AUTHOR_PROMPT = """You are writing ONE Python regular expression that extracts a
specific value from a security tool's raw output, so it never needs an LLM again.

Field name: {field}
Value to extract: {value!r}

Rules:
- Return ONLY a JSON object: {{"pattern": "<regex>"}}
- The regex MUST contain exactly ONE capturing group that captures the value.
- Prefer a stable anchor (a label/prefix that precedes the value), not the literal
  value itself. It will run with re.MULTILINE | re.IGNORECASE over the whole output.
- Keep it minimal and robust to surrounding whitespace.

--- RAW OUTPUT (truncated) ---
{output}
--- END ---
"""


def _author_regex(raw: str, field: str, value: str, model: str) -> Optional[str]:
    """Ask the model for a regex that extracts `value`; return the pattern or None."""
    from artifact_consumer import _call_llm, _extract_json, MAX_CONTENT_CHARS
    prompt = _AUTHOR_PROMPT.format(field=field, value=value,
                                   output=raw[:MAX_CONTENT_CHARS])
    try:
        resp, _meta = _call_llm(prompt, model)
    except Exception as e:
        log.warning("regex authoring call failed for %s: %s", field, e)
        return None
    obj = _extract_json(resp) or {}
    pattern = obj.get("pattern") if isinstance(obj, dict) else None
    return pattern if isinstance(pattern, str) and pattern.strip() else None


def _validate_regex(pattern: str, raw: str, value: str) -> bool:
    """The regex must compile, have exactly one group, and re-extract `value`."""
    try:
        rx = re.compile(pattern, re.MULTILINE | re.IGNORECASE)
    except re.error:
        return False
    if rx.groups != 1:
        return False
    want = str(value).strip()
    for m in rx.finditer(raw):
        if (m.group(1) or "").strip() == want:
            return True
    return False


def _kind_of(value: Any) -> str:
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, list):
        return "list"
    return "string"


def spec_llm_fill(spec: dict, tool: str, target: str, port, command: str,
                  raw: str, model: str) -> Dict[str, Any]:
    """Run the spec's OWN LLM prompt for the schema fields the deterministic pass
    left unresolved. Returns only the fields the model filled (validated against
    the spec schema)."""
    from artifact_consumer import _call_llm, _extract_json
    det = es.run_deterministic(spec, raw)
    schema = spec.get("schema") or {}
    unresolved = [f for f in schema if not det.get(f)]
    if not unresolved:
        return {}
    prompt = es.build_prompt(spec, tool, target, port, command, raw)
    try:
        resp, _meta = _call_llm(prompt, model)
    except Exception as e:
        log.warning("spec LLM fill call failed for %s: %s", tool, e)
        return {}
    parsed = _extract_json(resp)
    if not isinstance(parsed, dict):
        return {}
    try:
        es.validate_result(spec, parsed)
    except Exception:
        # keep only well-typed values we can still learn from
        pass
    return {f: parsed[f] for f in unresolved
            if parsed.get(f) not in (None, "", [], {})}


def distill_artifact(cur, tool: str, raw: str, target: str = "", port=None,
                     command: str = "", model: Optional[str] = None,
                     artifact_id: Optional[str] = None) -> dict:
    """Learn deterministic extractors for values the model filled but regex missed.

    Returns {tool, learned:[fields], proposed_notable:[ids], skipped:[...]}.
    Idempotent: re-running never re-authors a field already learned (unique index
    on (tool, kind, rule shape) + ON CONFLICT DO NOTHING)."""
    from artifact_consumer import DEFAULT_MODEL
    model = model or DEFAULT_MODEL
    spec = es.spec_for(tool)
    result = {"tool": tool, "learned": [], "proposed_notable": [], "skipped": []}
    if not spec:
        result["skipped"].append("no spec for tool")
        return result

    det = es.run_deterministic(spec, raw)
    filled = spec_llm_fill(spec, tool, target, port, command, raw, model)
    for field, value in filled.items():
        if det.get(field):
            continue  # regex already gets it
        # author a regex against a representative scalar for the value
        sample = value[0] if isinstance(value, list) and value else value
        if not isinstance(sample, (str, int, float)) or not str(sample).strip():
            result["skipped"].append(f"{field}: no scalar sample")
            continue
        pattern = _author_regex(raw, field, str(sample), model)
        if not pattern or not _validate_regex(pattern, raw, str(sample)):
            result["skipped"].append(f"{field}: regex not validated")
            continue
        capture = "all" if isinstance(value, list) else "first"
        det_rule = {field: {"pattern": pattern, "capture": capture, "type": _kind_of(value)}}
        cur.execute("""
            INSERT INTO extractor_learned (tool, kind, rule, status, source, sample_artifact_id, confidence)
            VALUES (%s, 'deterministic', %s::jsonb, 'active', 'distilled', %s, 0.9)
            ON CONFLICT (tool, kind, md5(rule::text)) DO NOTHING
        """, (tool, json.dumps(det_rule), artifact_id))
        if cur.rowcount:
            result["learned"].append(field)
        # Propose a finding rule for the new field (review-gated).
        notable = {
            "id": f"learned_{tool}_{field}",
            "when": f"len({field}) > 0" if isinstance(value, list) else field,
            "severity": "info",
            "title": f"{tool}: {field} present on {{target}}",
            "detail": f"Learned extractor surfaced '{field}' from {tool} output.",
        }
        cur.execute("""
            INSERT INTO extractor_learned (tool, kind, rule, status, source, sample_artifact_id, confidence)
            VALUES (%s, 'notable', %s::jsonb, 'proposed', 'distilled', %s, 0.6)
            ON CONFLICT (tool, kind, md5(rule::text)) DO NOTHING
        """, (tool, json.dumps(notable), artifact_id))
        if cur.rowcount:
            result["proposed_notable"].append(notable["id"])
    return result
