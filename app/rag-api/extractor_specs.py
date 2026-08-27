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
import time
from typing import Any, Dict, List, Optional

SPEC_DIR = os.environ.get("EXTRACTOR_SPEC_DIR", "/knowledge/extractors")

_REQUIRED = ("tool", "schema", "prompt")
_TYPES = ("string", "number", "boolean", "list", "object")

# Where a follow-on's RESULT goes when it produces data rather than running a
# command. Each name must already have a consumer — a sink nothing reads is a
# declaration that looks like plumbing and moves nothing.
#
#   identities      target_wordlists.import_enumerated_identities()
#   wordlists       /wordlists/build-target (harvests from identities)
#   ports           the ports table, for services a port scan missed
#   scan_parameters knowledge/scan_parameters.yaml sources
#   findings        recon_findings, via post_review_agent.ingest_extracted_facts
FEED_SINKS = {"identities", "wordlists", "ports", "scan_parameters", "findings"}

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


# ── self-adapting overlay (extractor_learned) ───────────────────────────────
# ACTIVE learned rules merge onto each tool's disk spec so a shape the LLM found
# once is extracted deterministically forever. Checked at most every _OVERLAY_TTL
# seconds (mirrors llm_settings) so spec_for() stays cheap; folded into the cache
# signature so a new/approved learned rule invalidates cached extractions.
_OVERLAY_TTL = 30.0
_overlay_cache: Dict[str, Any] = {"sig": None, "rows": {}, "checked_at": 0.0}


def _load_overlay():
    """(sig, {tool: {deterministic:{}, notable:[], follow_on:[]}}) from ACTIVE
    extractor_learned rows. Best-effort: returns ('', {}) if the DB is unreachable
    so extraction always falls back to the on-disk profiles."""
    now = time.time()
    if now - _overlay_cache["checked_at"] < _OVERLAY_TTL:
        return _overlay_cache["sig"], _overlay_cache["rows"]
    dsn = os.environ.get("DB_DSN")
    if not dsn:
        _overlay_cache.update(sig="", rows={}, checked_at=now)
        return "", {}
    try:
        import psycopg2
        from psycopg2.extras import RealDictCursor
        conn = psycopg2.connect(dsn)
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("SELECT count(*) n, COALESCE(max(updated_at)::text,'') m "
                            "FROM extractor_learned WHERE status='active'")
                r = cur.fetchone()
                sig = f"{r['n']}:{r['m']}"
                cur.execute("SELECT tool, kind, rule FROM extractor_learned WHERE status='active'")
                rows: Dict[str, Any] = {}
                for row in cur.fetchall():
                    t = (row["tool"] or "").strip().lower()
                    if not t:
                        continue
                    d = rows.setdefault(t, {"deterministic": {}, "notable": [], "follow_on": []})
                    rule = row["rule"] if isinstance(row["rule"], dict) else {}
                    if row["kind"] == "deterministic":
                        d["deterministic"].update(rule)
                    elif row["kind"] in ("notable", "follow_on"):
                        d[row["kind"]].append(rule)
        finally:
            conn.close()
        _overlay_cache.update(sig=sig, rows=rows, checked_at=now)
        return sig, rows
    except Exception:
        _overlay_cache.update(sig="", rows={}, checked_at=now)
        return "", {}


def _merge_overlay(spec: dict, ov: dict) -> dict:
    """Merge a tool's ACTIVE learned rules onto its spec (learned augments; the
    disk spec's own id wins on a collision)."""
    merged = dict(spec)
    if ov.get("deterministic"):
        base = dict(merged.get("deterministic") or {})
        for k, v in ov["deterministic"].items():
            base.setdefault(k, v)     # disk field definition wins
        merged["deterministic"] = base
    for section in ("notable", "follow_on"):
        add = ov.get(section) or []
        if add:
            own = list(merged.get(section) or [])
            own_ids = {r.get("id") for r in own}
            merged[section] = own + [r for r in add if r.get("id") not in own_ids]
    merged["_has_learned"] = True
    return merged


def _synth_spec(tool: str, ov: dict) -> dict:
    """Minimal spec for a tool that has ONLY learned rules (no disk profile)."""
    return {"tool": tool, "schema": {}, "prompt": "",
            "deterministic": dict(ov.get("deterministic") or {}),
            "notable": list(ov.get("notable") or []),
            "follow_on": list(ov.get("follow_on") or []),
            "_synth_from_learned": True}


def _apply_class(spec: dict, classes: dict) -> dict:
    """Merge a class template under a tool's own spec.

    The TOOL wins on every key it declares. Merging is one level deep for the
    mapping sections (`schema`, `deterministic`) and additive for the rule lists
    (`notable`, `follow_on`), with a tool's rule replacing the class rule of the
    same id — so a class can ship a sensible default that one tool overrides
    without copying the rest.
    """
    name = spec.get("class")
    if not name or name not in classes:
        return spec
    tmpl = classes[name] or {}
    merged = dict(spec)
    for section in ("schema", "deterministic"):
        base = dict(tmpl.get(section) or {})
        base.update(spec.get(section) or {})
        if base:
            merged[section] = base
    for section in ("notable", "follow_on"):
        own = list(spec.get(section) or [])
        own_ids = {r.get("id") for r in own}
        inherited = [r for r in (tmpl.get(section) or [])
                     if r.get("id") not in own_ids]
        if own or inherited:
            merged[section] = inherited + own
    for key in ("prompt", "description", "max_chars"):
        if not merged.get(key) and tmpl.get(key):
            merged[key] = tmpl[key]
    merged["_class"] = name
    return merged


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

    schema_fields = set(schema)
    for rule in spec.get("follow_on") or []:
        name = os.path.basename(path)
        if not rule.get("id"):
            problems.append(f"{name}: follow_on rule missing 'id'")
        pred = rule.get("when")
        if not pred or _parse_predicate(pred) is None:
            problems.append(
                f"{name}: follow_on {rule.get('id')!r} has an unparsable "
                f"'when': {pred!r}")
        # A rule must either run something or feed something. One that does
        # neither is a declaration with no effect, which reads as coverage.
        if not rule.get("script") and not rule.get("feeds"):
            problems.append(
                f"{name}: follow_on {rule.get('id')!r} has neither 'script' "
                f"nor 'feeds' — it would do nothing")
        if rule.get("script") and not rule.get("scanner"):
            problems.append(
                f"{name}: follow_on {rule.get('id')!r} has a script but no "
                f"'scanner'; the dispatcher routes on scanner")
        if rule.get("feeds") and rule["feeds"] not in FEED_SINKS:
            problems.append(
                f"{name}: follow_on {rule.get('id')!r} feeds "
                f"{rule['feeds']!r}, which nothing consumes. Known sinks: "
                f"{', '.join(sorted(FEED_SINKS))}")
        each = rule.get("for_each")
        if each:
            if each not in schema_fields:
                problems.append(
                    f"{name}: follow_on {rule.get('id')!r} iterates "
                    f"{each!r}, which is not in the schema")
            elif (schema.get(each) or {}).get("type") != "list":
                problems.append(
                    f"{name}: follow_on {rule.get('id')!r} iterates {each!r}, "
                    f"which is not a list")
    return problems


def load_specs(spec_dir: str = None, force: bool = False):
    """{tool: spec} keyed by tool and every alias, lowercased.

    Returns ({} , [problems]) rather than raising: one malformed spec must not
    take the whole extraction pass down, and the problems are reported so a
    broken file is visible instead of silently absent.
    """
    spec_dir = spec_dir or SPEC_DIR
    disk_sig = signature(spec_dir)
    overlay_sig, overlay = _load_overlay()
    # Combined key: disk profiles + the ACTIVE learned overlay. Either changing
    # invalidates cached extractions.
    sig = f"{disk_sig}|{overlay_sig}"
    if not force and disk_sig is not None and _cache["signature"] == sig:
        return _cache["specs"], _cache.get("problems", [])

    try:
        import yaml
    except ImportError:
        return {}, ["pyyaml is not installed; extraction specs cannot be read"]

    # Class templates first: they carry the shape shared by a family of tools
    # (a credential attack always reports recovered pairs and a rate), so a
    # per-tool spec supplies only the patterns that differ.
    classes = {}
    class_file = os.path.join(spec_dir, "_classes.yaml")
    if os.path.exists(class_file):
        try:
            with open(class_file, encoding="utf-8") as fh:
                classes = (yaml.safe_load(fh) or {}).get("classes") or {}
        except Exception as exc:            # noqa: BLE001
            problems_early = [f"_classes.yaml: {type(exc).__name__}: {exc}"]
        else:
            problems_early = []
    else:
        problems_early = []

    specs, problems = {}, list(problems_early)
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
        doc = _apply_class(doc, classes)
        doc["_source_file"] = os.path.basename(path)
        doc["_signature"] = sig
        for name in [doc["tool"]] + list(doc.get("aliases") or []):
            specs[str(name).strip().lower()] = doc

    # Merge the ACTIVE learned overlay: augment matching disk specs, and
    # synthesize a minimal spec for tools that have ONLY learned rules.
    for tool_key, ov in (overlay or {}).items():
        base = specs.get(tool_key)
        if base is not None:
            merged = _merge_overlay(base, ov)
            merged["_signature"] = sig
            for k, v in list(specs.items()):
                if v is base:
                    specs[k] = merged
        else:
            syn = _synth_spec(tool_key, ov)
            syn["_signature"] = sig
            specs[tool_key] = syn

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


# ── coverage: what the patterns did NOT consume ─────────────────────────────
# Lines that are noise, not uncovered data: separators, progress bars, tool
# banners, timestamps. Residual after removing these is genuinely unexplained.
_COVERAGE_NOISE = re.compile(
    r"^(?:[-=_*#~.\s]+|\[[*+\-!i]\].*|\d{1,2}:\d{2}(?::\d{2})?.*|"
    r"(?:starting|running|scanning|progress|elapsed|done|finished|completed)\b.*|"
    r"v?\d+\.\d+(?:\.\d+)?\s*$)", re.IGNORECASE)


def coverage(spec: dict, output: str) -> Dict[str, Any]:
    """How much of the output the deterministic patterns actually consumed, and
    the residual — the non-trivial lines NO pattern matched. Substantial residual
    is the signal that the tool emitted something the profile does not cover yet
    (a new field/finding the author never anticipated), which is exactly what a
    schema-field diff cannot see. Line-granular and approximate on purpose: it is
    a screening signal, not a parser."""
    text = output or ""
    lines = text.splitlines()
    matched: set = set()
    for decl in (spec.get("deterministic") or {}).values():
        pattern = decl.get("pattern") if isinstance(decl, dict) else decl
        if not pattern:
            continue
        try:
            rx = re.compile(pattern, re.M | re.I)
        except re.error:
            continue
        for m in rx.finditer(text):
            first = text.count("\n", 0, m.start())
            last = text.count("\n", 0, m.end())
            for i in range(first, last + 1):
                matched.add(i)
    residual, substantive = [], 0
    for i, ln in enumerate(lines):
        s = ln.strip()
        if not s or i in matched:
            continue
        if _COVERAGE_NOISE.match(s):
            continue
        substantive += 1
        if len(residual) < 25:
            residual.append(s[:200])
    total = sum(1 for ln in lines if ln.strip())
    cov_pct = round(100.0 * (1 - substantive / total), 1) if total else 100.0
    return {
        "total_lines": total,
        "matched_lines": len(matched),
        "residual_lines": substantive,
        "coverage_pct": cov_pct,
        "residual_sample": residual,
    }


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


# ── follow-on actions ───────────────────────────────────────────────────────

def _fill_action_script(script: str, values: dict) -> str:
    """Substitute {field} and {item} from extracted values.

    A placeholder that cannot be filled is LEFT IN PLACE, exactly as
    `artifact_actions.suggest_actions` does: the caller then marks the action
    `needs_input`, and a command that cannot run as written must never queue.
    Guessing a value is worse than an incomplete command, because a wrong port
    looks runnable.
    """
    out = script or ""
    for field in re.findall(r"\{(\w+)\}", out):
        if field not in values:
            continue
        val = values[field]
        if isinstance(val, (list, tuple, set)):
            continue                        # a list is for for_each, not a scalar
        if val is None or isinstance(val, bool):
            continue
        out = out.replace("{" + field + "}", str(val))
    return out


def follow_on_from(spec: dict, extracted: dict, context: dict = None) -> List[dict]:
    """Actions a tool's OWN OUTPUT implies, fired on extracted fields.

    This is the half that was missing. `knowledge/artifact_rules/builtin.yaml`
    re-parsed raw text with a second pattern set to propose commands, so an
    action could never use an extracted VALUE — the extractor knew the share was
    called `tmp` and the rule could only say "shares were found". With
    `for_each: shares` the same fact becomes `smbclient //target/tmp`.

    Emits the shape `artifact_actions.suggest_actions()` already returns, so
    `_insert_recommendation`, the auto-queue contract and the UI are unchanged.

    `feeds` actions carry no script: their result is DATA going to a sink
    (identities, wordlists, ports), not a command for a human to run.
    """
    context = dict(context or {})
    values = {**extracted, **context}
    out = []
    for rule in spec.get("follow_on") or []:
        try:
            if not evaluate_predicate(rule.get("when", ""), extracted):
                continue
        except Exception:                   # noqa: BLE001
            continue

        each_field = rule.get("for_each")
        items = [None]
        if each_field:
            raw = extracted.get(each_field)
            if not isinstance(raw, (list, tuple)):
                continue
            items = list(raw)
            if not items:
                continue

        for item in items:
            local = dict(values)
            if item is not None:
                local["item"] = item
            script = _fill_action_script(rule.get("script", ""), local)
            title = _fill_action_script(rule.get("title", rule["id"]), local)
            # Same rule as artifact_actions: an unresolved placeholder means the
            # action cannot run as written, so it is offered but never queued.
            needs_input = bool(rule.get("needs_input")) or "{" in script
            # Written out rather than a conditional expression: `A or B if C
            # else D` binds as `(A or B) if C else D`, which is not what it
            # looks like and is a trap for the next reader.
            if rule.get("evidence"):
                evidence = rule["evidence"]
            elif item is not None:
                evidence = f"{each_field}={item}"
            else:
                evidence = f"matched: {rule.get('when')}"
            action = {
                "id": rule["id"] + (f":{item}" if item is not None else ""),
                "category": rule.get("category") or spec.get("class") or "general",
                "title": title,
                "scanner": rule.get("scanner"),
                "script": script or None,
                "rationale": rule.get("rationale", ""),
                "priority": int(rule.get("priority", 50)),
                "evidence": evidence,
                "needs_input": needs_input if script else False,
                "auto_queue": bool(rule.get("auto_queue")) and not needs_input
                              and bool(script),
                "source": "analysis_profile",
                "spec": spec.get("_source_file"),
            }
            if rule.get("feeds"):
                action["feeds"] = rule["feeds"]
                action["feed_field"] = rule.get("feed_field") or each_field
                action["feed_values"] = (
                    extracted.get(action["feed_field"])
                    if action["feed_field"] else None)
                # A data feed is not a command a human runs.
                action["auto_queue"] = False
                action["needs_input"] = False
            out.append(action)
    out.sort(key=lambda a: (-a["priority"], a["id"]))
    return out
