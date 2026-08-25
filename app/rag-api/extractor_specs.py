"""Per-tool extraction specs: what to pull out of a tool's output, and how.

WHY THIS EXISTS
---------------
`artifact_consumer` sends every tool through ONE generic prompt asking for a
prose summary plus loose string arrays. That is the wrong shape for the actual
problem, which is measured:

  * 94.2% of `recon_findings` (98 of 104 rows, 17 tools) are generic dumps —
    `finding_type='tool_output'` or `'tool_table_row'` with `key_values` EMPTY.
    The text is captured; nothing says what it MEANS, so nothing can filter,
    sort or triage it.
  * 2.23 MB of output across 19 tools has no extractor at all. One enum4linux-ng
    run discloses **35 usernames** through a null session, SMB1-only dialects,
    signing not required, the FQDN and the Samba version — 47 such runs, none
    interpreted.

Hand-writing 19 Python extractors does not happen, and the generic dumper is
what filled that vacuum badly. So a spec declares, per tool, a TYPED schema and
an extraction prompt with real few-shot examples, and the existing artifact LLM
queue does the work.

DESIGN
------
* **Deterministic first.** A spec may declare `deterministic` regexes. Anything
  they resolve is not sent to a model: it is cheaper, stable across runs, and a
  stable extraction is what keeps a finding's fingerprint from forking. The
  prompt covers only what regexes cannot.
* **Typed, validated results.** A model returning `users: "35"` where the schema
  says `list` is a failure, not a result. Validation rejects it so the artifact
  retries rather than storing a wrong shape.
* **No `eval` on knowledge files.** `knowledge/` is an operator-editable bind
  mount; `eval()` on a `when:` expression there would be arbitrary code
  execution from a data file. Predicates are parsed by a restricted evaluator
  that understands exactly six forms and nothing else.
* **Content-hash signature.** Same approach as `artifact_actions._signature`:
  edits take effect without a rebuild, and a stored result records the signature
  it was produced under so staleness is detectable rather than invisible.
"""
import hashlib
import os
import re
from typing import Any, Dict, List, Optional

SPEC_DIR = os.environ.get("EXTRACTOR_SPEC_DIR", "/knowledge/extractors")

_REQUIRED = ("tool", "schema", "prompt")
_TYPES = ("string", "number", "boolean", "list", "object")

_cache: Dict[str, Any] = {"signature": None, "specs": {}}


# ── loading ─────────────────────────────────────────────────────────────────

def _spec_files(spec_dir: str) -> List[str]:
    try:
        names = sorted(os.listdir(spec_dir))
    except OSError:
        return []
    return [os.path.join(spec_dir, n) for n in names
            if n.endswith((".yaml", ".yml")) and not n.startswith("_")]


def signature(spec_dir: str = None) -> Optional[str]:
    """Content hash of every spec file.

    Deliberately content, not mtime: a bind mount can carry a rewritten file
    with an unchanged timestamp, and a copy can change mtime without changing
    a byte. Either way mtime answers the wrong question.
    """
    files = _spec_files(spec_dir or SPEC_DIR)
    if not files:
        return None
    h = hashlib.sha256()
    for path in files:
        h.update(os.path.basename(path).encode())
        try:
            with open(path, "rb") as fh:
                h.update(fh.read())
        except OSError:
            h.update(b"<unreadable>")
    return h.hexdigest()[:16]


def _validate_spec(spec: dict, path: str) -> List[str]:
    problems = []
    for key in _REQUIRED:
        if not spec.get(key):
            problems.append(f"{os.path.basename(path)}: missing '{key}'")
    schema = spec.get("schema") or {}
    if not isinstance(schema, dict):
        problems.append(f"{os.path.basename(path)}: 'schema' must be a mapping")
        schema = {}
    for field, decl in schema.items():
        t = (decl or {}).get("type") if isinstance(decl, dict) else None
        if t not in _TYPES:
            problems.append(
                f"{os.path.basename(path)}: field '{field}' has type {t!r}; "
                f"must be one of {', '.join(_TYPES)}")
    for rule in spec.get("notable") or []:
        for key in ("id", "when", "severity", "title"):
            if not rule.get(key):
                problems.append(
                    f"{os.path.basename(path)}: notable rule missing '{key}'")
        pred = rule.get("when")
        if pred and _parse_predicate(pred) is None:
            problems.append(
                f"{os.path.basename(path)}: rule {rule.get('id')!r} has an "
                f"unparsable 'when': {pred!r}")
    return problems


def load_specs(spec_dir: str = None, force: bool = False):
    """{tool: spec} keyed by tool and every alias, lowercased.

    Returns ({} , [problems]) rather than raising: one malformed spec must not
    take the whole extraction pass down, and the problems are reported so a
    broken file is visible instead of silently absent.
    """
    spec_dir = spec_dir or SPEC_DIR
    sig = signature(spec_dir)
    if not force and sig is not None and _cache["signature"] == sig:
        return _cache["specs"], _cache.get("problems", [])

    try:
        import yaml
    except ImportError:
        return {}, ["pyyaml is not installed; extraction specs cannot be read"]

    specs, problems = {}, []
    for path in _spec_files(spec_dir):
        try:
            with open(path, encoding="utf-8") as fh:
                doc = yaml.safe_load(fh) or {}
        except Exception as exc:            # noqa: BLE001
            problems.append(f"{os.path.basename(path)}: {type(exc).__name__}: {exc}")
            continue
        if doc.get("enabled") is False:
            continue
        bad = _validate_spec(doc, path)
        if bad:
            problems.extend(bad)
            continue
        doc["_source_file"] = os.path.basename(path)
        doc["_signature"] = sig
        for name in [doc["tool"]] + list(doc.get("aliases") or []):
            specs[str(name).strip().lower()] = doc
    _cache.update({"signature": sig, "specs": specs, "problems": problems})
    return specs, problems


def spec_for(tool: str, spec_dir: str = None):
    specs, _ = load_specs(spec_dir)
    return specs.get((tool or "").strip().lower())


# ── restricted predicates (NO eval) ─────────────────────────────────────────
# Six forms only. Anything else fails to parse and is reported as a spec error
# rather than being run.
_PRED_RES = (
    ("len_gt", re.compile(r"^len\(\s*(?P<f>[\w.]+)\s*\)\s*>\s*(?P<n>\d+)$")),
    ("len_ge", re.compile(r"^len\(\s*(?P<f>[\w.]+)\s*\)\s*>=\s*(?P<n>\d+)$")),
    # Plain numeric comparison. Omitting this made `remaining_hours > 24`
    # unparsable, so hydra's "this run could never finish" rule silently never
    # fired — a spec error that only the loader's problem list revealed.
    ("num_cmp", re.compile(r"^(?P<f>[\w.]+)\s*(?P<op>>=|<=|>|<)\s*(?P<n>-?[\d.]+)$")),
    ("eq",     re.compile(r"^(?P<f>[\w.]+)\s*==\s*(?P<v>true|false|null|-?\d+|'[^']*'|\"[^\"]*\")$", re.I)),
    ("ne",     re.compile(r"^(?P<f>[\w.]+)\s*!=\s*(?P<v>true|false|null|-?\d+|'[^']*'|\"[^\"]*\")$", re.I)),
    ("truthy", re.compile(r"^(?P<f>[\w.]+)$")),
    ("falsy",  re.compile(r"^not\s+(?P<f>[\w.]+)$")),
)


def _parse_predicate(expr: str):
    expr = (expr or "").strip()
    for kind, rx in _PRED_RES:
        m = rx.match(expr)
        if m:
            return (kind, m.groupdict())
    return None


def _literal(text: str):
    t = text.strip()
    low = t.lower()
    if low == "true":
        return True
    if low == "false":
        return False
    if low == "null":
        return None
    if (t.startswith("'") and t.endswith("'")) or \
       (t.startswith('"') and t.endswith('"')):
        return t[1:-1]
    try:
        return int(t)
    except ValueError:
        return t


def _resolve(data: dict, dotted: str):
    cur = data
    for part in dotted.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def evaluate_predicate(expr: str, data: dict) -> bool:
    parsed = _parse_predicate(expr)
    if not parsed:
        return False
    kind, g = parsed
    value = _resolve(data, g["f"])
    if kind == "truthy":
        return bool(value)
    if kind == "falsy":
        return not bool(value)
    if kind in ("len_gt", "len_ge"):
        try:
            n = len(value)
        except TypeError:
            return False
        return n > int(g["n"]) if kind == "len_gt" else n >= int(g["n"])
    if kind == "num_cmp":
        try:
            left, right = float(value), float(g["n"])
        except (TypeError, ValueError):
            return False    # a missing or non-numeric field is not a match
        op = g["op"]
        return {">": left > right, ">=": left >= right,
                "<": left < right, "<=": left <= right}[op]
    want = _literal(g["v"])
    return (value == want) if kind == "eq" else (value != want)


# ── deterministic pre-pass ──────────────────────────────────────────────────

def run_deterministic(spec: dict, output: str) -> Dict[str, Any]:
    """Fields a regex can resolve, so the model is never asked for them.

    `capture: all` collects every match; otherwise the first wins. A pattern
    that matches nothing simply leaves the field to the prompt.
    """
    got: Dict[str, Any] = {}
    for field, decl in (spec.get("deterministic") or {}).items():
        pattern = decl.get("pattern") if isinstance(decl, dict) else decl
        if not pattern:
            continue
        try:
            rx = re.compile(pattern, re.M | re.I)
        except re.error:
            continue
        matches = rx.findall(output or "")
        if not matches:
            continue
        want_declared = (decl.get("type") if isinstance(decl, dict) else None) \
            or ((spec.get("schema") or {}).get(field) or {}).get("type")
        if want_declared == "boolean" and rx.groups == 0:
            # Presence IS the value. Without this, a pattern like
            # "Server allows authentication via username '' and password ''"
            # matched and then evaluated its own matched sentence against a
            # truthy-word list, yielding False — so the null-session finding,
            # the highest-severity fact in the run, never fired.
            got[field] = True
            continue
        flat = [m if isinstance(m, str) else next((x for x in m if x), "")
                for m in matches]
        flat = [f.strip() for f in flat if f and f.strip()]
        if not flat:
            continue
        want = (decl.get("type") if isinstance(decl, dict) else None) \
            or ((spec.get("schema") or {}).get(field) or {}).get("type")
        if want == "list" or (isinstance(decl, dict) and decl.get("capture") == "all"):
            seen, uniq = set(), []
            for f in flat:
                if f not in seen:
                    seen.add(f)
                    uniq.append(f)
            got[field] = uniq
        elif want == "boolean":
            got[field] = str(flat[0]).strip().lower() in ("true", "yes", "1",
                                                          "required", "enabled")
        elif want == "number":
            digits = re.sub(r"[^\d.\-]", "", flat[0])
            try:
                got[field] = float(digits) if "." in digits else int(digits)
            except ValueError:
                got[field] = flat[0]
        else:
            got[field] = flat[0]
    return got


# ── prompt + result validation ──────────────────────────────────────────────

def build_prompt(spec: dict, tool: str, target: str, port, command: str,
                 content: str, already: Dict[str, Any] = None) -> str:
    """Render the spec's prompt, telling the model what is already known.

    Fields the deterministic pass resolved are listed as settled, so the model
    is not invited to contradict a regex that read the text exactly.
    """
    schema_lines = []
    for field, decl in (spec.get("schema") or {}).items():
        d = decl or {}
        desc = d.get("description") or ""
        schema_lines.append(f'  "{field}": {d.get("type")}  — {desc}'.rstrip(" —"))

    example_block = ""
    for ex in (spec.get("examples") or [])[:2]:
        example_block += ("\n--- EXAMPLE OUTPUT ---\n"
                          f"{(ex.get('output') or '').strip()}\n"
                          "--- EXAMPLE EXTRACTION ---\n"
                          f"{(ex.get('extract') or '').strip()}\n")

    known = ""
    if already:
        known = ("\nAlready determined from the text by exact pattern match — "
                 "treat these as settled and do not contradict them:\n"
                 + "\n".join(f"  {k} = {v!r}" for k, v in already.items()) + "\n")

    return (
        f"{spec['prompt'].strip()}\n\n"
        f"Tool: {tool}\nTarget: {target or 'unknown'}"
        f"{f':{port}' if port else ''}\nCommand: {(command or '')[:400]}\n\n"
        "Return ONLY a JSON object with exactly these keys:\n"
        + "\n".join(schema_lines)
        + "\n\nOmit a key entirely if the output does not contain it. Never "
          "invent a value that is not present in the text.\n"
        + known + example_block
        + f"\n--- OUTPUT ---\n{content}\n--- END ---\n")


_PY_TYPES = {"string": str, "number": (int, float), "boolean": bool,
             "list": list, "object": dict}


def validate_result(spec: dict, result: dict):
    """(cleaned, problems). A wrong-typed field is dropped, not coerced.

    Coercing `users: "35"` into `["35"]` would store a confident lie. Dropping
    it and reporting the problem lets the artifact retry.
    """
    if not isinstance(result, dict):
        return {}, ["result is not a JSON object"]
    schema = spec.get("schema") or {}
    cleaned, problems = {}, []
    for field, value in result.items():
        if field.startswith("_"):
            cleaned[field] = value
            continue
        decl = schema.get(field)
        if not decl:
            problems.append(f"unexpected field {field!r} (not in schema)")
            continue
        want = _PY_TYPES.get(decl.get("type"))
        if want and not isinstance(value, want):
            problems.append(
                f"field {field!r} should be {decl.get('type')}, "
                f"got {type(value).__name__}")
            continue
        cleaned[field] = value
    missing_required = [f for f, d in schema.items()
                        if (d or {}).get("required") and f not in cleaned]
    problems += [f"missing required field {f!r}" for f in missing_required]
    return cleaned, problems


def notable_from(spec: dict, extracted: dict) -> List[dict]:
    """Findings the spec declares, for the facts that were extracted.

    A rule may declare `params: [field, ...]`. Those field VALUES are carried on
    the finding and stored with it, machine-readable rather than embedded in a
    sentence. That matters for informational findings: an SMB password policy is
    not a defect to fix, it is a set of parameters that CONSTRAIN testing —
    minimum length, history depth, lockout duration — and a later decision
    ("is a spray safe here?", "how long is the lockout window?") needs the value,
    not prose about it.
    """
    out = []
    for rule in spec.get("notable") or []:
        try:
            if not evaluate_predicate(rule["when"], extracted):
                continue
        except Exception:                   # noqa: BLE001
            continue
        title = rule["title"]
        for field in re.findall(r"\{(\w+)\}", title):
            val = extracted.get(field)
            if isinstance(val, list):
                val = len(val)
            title = title.replace("{" + field + "}",
                                  "unknown" if val is None else str(val))
        fact = {"id": rule["id"], "severity": rule["severity"],
                "title": title, "detail": rule.get("detail", ""),
                "source": "extractor_spec",
                "spec": spec.get("_source_file")}
        params = {f: extracted[f] for f in (rule.get("params") or [])
                  if f in extracted}
        if params:
            fact["params"] = params
        out.append(fact)
    return out
