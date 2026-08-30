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

# Operator-directed extraction: the reviewer saw something in the raw output they
# want captured and typed what it is. The model names a field, copies the value
# verbatim (so a regex can re-find it), and says whether there are several.
_FOCUS_PROMPT = """The operator is reviewing raw output from the security tool
`{tool}` and wants to extract a specific thing so it becomes a reusable rule.

Operator wants to extract: {focus}

Return ONLY a JSON object:
  {{"present": <true|false>,
    "field": "<short snake_case name for this value>",
    "value": <the exact value from the text, or an array of values>,
    "is_list": <true if the output contains multiple occurrences>}}

- Set present=false if the output does not actually contain it. Never invent a
  value that is not present in the text.
- `value` MUST be copied verbatim from the output so a regex can re-find it.

--- OUTPUT (truncated) ---
{output}
--- END ---
"""

_SNAKE_RE = re.compile(r"[^a-z0-9]+")


def _snake(text: str) -> str:
    """A safe snake_case field key from free text (schema/DB rule key)."""
    s = _SNAKE_RE.sub("_", (text or "").strip().lower()).strip("_")
    return s[:48] or "focus_field"


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


def _learn_field(cur, tool: str, field: str, value: Any, raw: str, model: str,
                 artifact_id: Optional[str], result: dict) -> bool:
    """Author + validate a regex for one (field, value) and store it as an ACTIVE
    deterministic rule plus a PROPOSED notable. Returns True when a new
    deterministic rule was inserted. Idempotent via the unique index."""
    sample = value[0] if isinstance(value, list) and value else value
    if not isinstance(sample, (str, int, float)) or not str(sample).strip():
        result["skipped"].append(f"{field}: no scalar sample")
        return False
    pattern = _author_regex(raw, field, str(sample), model)
    if not pattern or not _validate_regex(pattern, raw, str(sample)):
        result["skipped"].append(f"{field}: regex not validated")
        return False
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
    return True


def _distill_focus(cur, tool: str, raw: str, focus: str, det: dict, model: str,
                   artifact_id: Optional[str], result: dict) -> dict:
    """Operator-directed learning: extract exactly what the reviewer asked for and
    author a deterministic rule for it. Works even with NO disk spec — the learned
    rules synthesise one on the next load (extractor_specs._synth_spec)."""
    from artifact_consumer import _call_llm, _extract_json, MAX_CONTENT_CHARS
    prompt = _FOCUS_PROMPT.format(tool=tool, focus=focus, output=raw[:MAX_CONTENT_CHARS])
    try:
        resp, _meta = _call_llm(prompt, model)
    except Exception as e:
        log.warning("focus extract call failed for %s: %s", tool, e)
        return {"requested": focus, "found": False, "error": str(e)[:200]}
    obj = _extract_json(resp) or {}
    if not isinstance(obj, dict) or not obj.get("present"):
        return {"requested": focus, "found": False}
    field = _snake(obj.get("field") or focus)
    value = obj.get("value")
    if obj.get("is_list") and not isinstance(value, list):
        value = [value] if value not in (None, "", []) else []
    if value in (None, "", []):
        return {"requested": focus, "found": False}
    if det.get(field):
        return {"requested": focus, "found": True, "field": field,
                "value": value, "already_covered": True, "learned": False}
    learned = _learn_field(cur, tool, field, value, raw, model, artifact_id, result)
    return {"requested": focus, "found": True, "field": field,
            "value": value, "learned": learned}


def distill_artifact(cur, tool: str, raw: str, target: str = "", port=None,
                     command: str = "", model: Optional[str] = None,
                     artifact_id: Optional[str] = None,
                     focus: Optional[str] = None) -> dict:
    """Learn deterministic extractors for values the model filled but regex missed.

    Two learning paths:
      * schema-gap — fields the spec's own prompt fills that the regexes missed
        (automatic; requires a disk spec).
      * focus — the operator names a specific thing to extract; works with or
        without a disk spec (the first learned rule bootstraps a synthesised one).

    Returns {tool, learned:[fields], proposed_notable:[ids], skipped:[...], focus}.
    Idempotent: re-running never re-authors a field already learned (unique index
    on (tool, kind, rule shape) + ON CONFLICT DO NOTHING)."""
    from artifact_consumer import DEFAULT_MODEL
    model = model or DEFAULT_MODEL
    spec = es.spec_for(tool)
    result = {"tool": tool, "learned": [], "proposed_notable": [], "skipped": [],
              "focus": None}

    det: Dict[str, Any] = {}
    if spec:
        det = es.run_deterministic(spec, raw)
        filled = spec_llm_fill(spec, tool, target, port, command, raw, model)
        for field, value in filled.items():
            if det.get(field):
                continue  # regex already gets it
            _learn_field(cur, tool, field, value, raw, model, artifact_id, result)
    else:
        result["skipped"].append("no disk profile — focus-directed learning only")

    # Operator-directed focus: extract and learn exactly what was asked for.
    if focus and focus.strip():
        result["focus"] = _distill_focus(cur, tool, raw, focus, det, model,
                                         artifact_id, result)

    if not spec:
        return result  # no patterns to measure coverage against

    # Coverage check: after learning, is there STILL substantial output that no
    # pattern consumed? That is content outside the schema — the author never
    # anticipated it. Raise a coverage_gap flag (deduped) so it's visible/actionable.
    try:
        cov = es.coverage(spec, raw)
        result["coverage"] = cov
        if cov["residual_lines"] >= 4 and cov["coverage_pct"] < 85:
            cur.execute("""SELECT 1 FROM agent_flags WHERE flag_type='coverage_gap'
                           AND flagging_agent='extractor-coverage'
                           AND data->>'tool'=%s AND status='pending' LIMIT 1""", (tool,))
            if not cur.fetchone():
                import agent_flags as _af
                _af.flag_for_agent(
                    cur, "extractor-coverage", "coverage_gap",
                    {"tool": tool, "target": target, "coverage_pct": cov["coverage_pct"],
                     "uncovered_lines": cov["residual_lines"],
                     "residual_sample": cov["residual_sample"][:10],
                     "reason": f"{cov['residual_lines']} line(s) of {tool} output "
                               f"({100 - cov['coverage_pct']:.0f}%) match no extractor pattern"})
                result["coverage_gap_flagged"] = True
    except Exception as e:
        log.warning("coverage check failed for %s: %s", tool, e)
    return result
