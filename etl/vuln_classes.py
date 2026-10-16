"""One vulnerability-class vocabulary, and one place that normalises into it.

The same concept was spelled differently in eleven places. `_FILE_READ_CLASSES`
listed `lfi`, `path-traversal` AND `path_traversal` — three names for one idea,
in one set. Each gate had inlined its own partial alias list (6 non-canonical
entries in one, 6 in another, 5, 2, 0, 0), so in a single run `path-traversal`
passed one gate and failed another. That was never eleven vocabularies; it was
one vocabulary with eleven private, divergent spell-checkers.

Two producers emit a class name:

  * `_vuln_class_from_cve` — deterministic, 10 canonical names.
  * the LLM fallback — free text, which is where `path-traversal` came from.

`canonical()` is called ONCE at each producer's exit. Downstream code then never
sees a non-canonical name and never needs an alias list of its own. Every old
set becomes a projection: `classes_where(file_read=True)`,
`path_is_the_field(cls)`.

DETERMINISTIC, never fuzzy. A gate asking "is this a file-read class?" must get
an exact answer; CLAUDE.md's rule is "retrieve, then gate — never retrieve to
authorize". An unrecognised name resolves to `unknown`, which is a real class
with defined (conservative) behaviour, not a crash and not a guess.

Pure: no database, no network. `knowledge/vuln_classes.yaml` is bind-mounted, so
adding a class or an alias takes effect on reload with no code change and no
image rebuild — which is the whole point, since every one of the eleven sets
needed a rebuild to extend.

    pytest tests/test_vuln_classes.py
"""
from __future__ import annotations

import os
import re
import threading
from typing import Any, Dict, List, Optional, Set

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

UNKNOWN = "unknown"

_HERE = os.path.dirname(os.path.abspath(__file__))
_DEFAULT_PATHS = (
    os.path.join(os.environ.get("KNOWLEDGE_DIR", "/knowledge"), "vuln_classes.yaml"),
    os.path.join(_HERE, "..", "knowledge", "vuln_classes.yaml"),
)

_lock = threading.Lock()
_cache: Dict[str, Any] = {}


def _squash(s: str) -> str:
    """`Path Traversal` / `path_traversal` / `PATH-TRAVERSAL` -> `pathtraversal`.

    Only case, separators and surrounding punctuation are normalised away. No
    stemming, no edit distance: two names that differ by a letter are two
    different names, because a gate that guesses is not a gate.
    """
    return re.sub(r"[^a-z0-9]+", "", str(s or "").lower())


def load(path: Optional[str] = None, force: bool = False) -> Dict[str, Any]:
    """The parsed table, cached. Returns an EMPTY table when unreadable.

    A caller must be able to tell "no such class" from "the table did not
    load", so `loaded()` reports which happened rather than letting an empty
    table read as a vocabulary with nothing in it.
    """
    global _cache
    with _lock:
        if _cache and not force and not path:
            return _cache
        data, src = {}, None
        if yaml is not None:
            for p in ([path] if path else list(_DEFAULT_PATHS)):
                if not p or not os.path.isfile(p):
                    continue
                try:
                    with open(p, encoding="utf-8") as fh:
                        data = yaml.safe_load(fh) or {}
                    src = p
                    break
                except Exception:  # noqa: BLE001
                    continue
        by_name, by_alias, by_cwe = {}, {}, {}
        raw_alias: List[tuple] = []     # (original spelling, class) for prose matching
        for c in (data.get("classes") or []):
            if not isinstance(c, dict) or not c.get("name"):
                continue
            name = str(c["name"]).strip().lower()
            by_name[name] = c
            by_alias[_squash(name)] = name
            raw_alias.append((name, name))
            for a in (c.get("aliases") or []):
                by_alias.setdefault(_squash(a), name)
                raw_alias.append((str(a), name))
            for cw in (c.get("cwes") or []):
                cid = str((cw or {}).get("id") or "").strip().upper()
                if cid:
                    # ONE CWE -> MANY classes, by design. CWE-78 is both `cmdi`
                    # and `rce`; CWE-98 is both `lfi` and `rfi`. Picking one
                    # would make the lookup lie about the other.
                    by_cwe.setdefault(cid, [])
                    if name not in by_cwe[cid]:
                        by_cwe[cid].append(name)
        for cid in by_cwe:
            by_cwe[cid].sort()      # deterministic, never file order
        # Boundary-aware patterns for matching a class name in PROSE. Squashing
        # separators is right for `canonical("Path Traversal")` and wrong for
        # scanning text: `rce` is a substring of "resou(rce)key", so a
        # substring scan classified a path traversal as remote code execution.
        # Each alias becomes `\btoken[-_ ]?token\b`, longest first so
        # `remote file inclusion` is not swallowed by a shorter alias inside it.
        alias_res = []
        for spelling, cls in raw_alias:
            toks = [t for t in re.split(r"[^a-z0-9]+", str(spelling).lower()) if t]
            if not toks:
                continue
            # Separators are flexible so one entry covers `arbitrary-file-read`,
            # `arbitrary file read` and `arbitrary_file_read` — but the ends are
            # anchored on word boundaries, because `rce` is a substring of
            # "resou(rce)key" and a plain substring scan classified a path
            # traversal as remote code execution.
            alias_res.append((len(spelling),
                              re.compile(r"\b" + r"[-_ ]?".join(map(re.escape, toks)) + r"\b",
                                         re.I),
                              cls))
        alias_res.sort(key=lambda x: -x[0])
        built = {"raw": data, "source": src, "by_name": by_name,
                 "by_alias": by_alias, "by_cwe": by_cwe,
                 "alias_res": alias_res, "loaded": bool(by_name)}
        if not path:
            _cache = built
        return built


def loaded() -> bool:
    """Did the table actually load? `False` means every lookup below is
    answering from an empty vocabulary, which is not the same as 'no match'."""
    return bool(load().get("loaded"))


def canonical(name) -> str:
    """The canonical class name for any spelling. Unrecognised -> `unknown`.

    This is the ONE normalisation point. Call it where a class name enters the
    system — the classifier's exit and the LLM fallback's exit — not at each
    consumer, which is how eleven divergent alias lists happened.
    """
    t = load()
    key = _squash(name)
    if not key:
        return UNKNOWN
    return t["by_alias"].get(key, UNKNOWN)


def is_known(name) -> bool:
    return canonical(name) != UNKNOWN or _squash(name) == UNKNOWN


def get(name) -> Optional[dict]:
    return load()["by_name"].get(canonical(name))


def names() -> List[str]:
    return sorted(load()["by_name"])


def aliases_of(name) -> List[str]:
    return list((get(name) or {}).get("aliases") or [])


# ── projections (what the eleven sets used to be) ───────────────────────────


def classes_where(**props) -> Set[str]:
    """Every class whose properties match. A list-valued property matches when
    the asked-for value is IN it."""
    out = set()
    for name, c in load()["by_name"].items():
        for k, want in props.items():
            have = c.get(k)
            if isinstance(have, list):
                if want not in have:
                    break
            elif bool(have) != bool(want) if isinstance(want, bool) else have != want:
                break
        else:
            out.add(name)
    return out


def injection_points(name) -> List[str]:
    return list((get(name) or {}).get("injects_via") or [])


def path_is_the_field(name) -> bool:
    """Is the URL PATH the only injection point?

    Deliberately `== ["path"]`, not `"path" in …`. An LFI injects through a
    parameter and a traversal through the path; `auth-bypass` and `idor` can do
    either. Treating "can inject via path" as "has no parameter" is the bug
    this table exists to end — it made the gather gate stop demanding a
    parameter for every file read.
    """
    return injection_points(name) == ["path"]


def needs_input_field(name) -> bool:
    """Is there a parameter / key / field to find at all?"""
    pts = injection_points(name)
    return bool(pts) and pts != ["path"]


def needs_oob_sink(name) -> bool:
    return bool((get(name) or {}).get("needs_oob_sink"))


def is_file_read(name) -> bool:
    """Can this class read a file? Orthogonal to WHERE it injects — XXE reads
    files through a request body, which is exactly what a single flat set could
    not express."""
    return bool((get(name) or {}).get("file_read"))


def is_blind_capable(name) -> bool:
    return bool((get(name) or {}).get("blind_capable"))


def proof_kinds(name) -> List[str]:
    return list((get(name) or {}).get("proof") or [])


# ── reference vocabularies ──────────────────────────────────────────────────


def classes_for_cwe(cwe) -> List[str]:
    """EVERY class a CWE points at, sorted. A CWE is a narrowing signal, not an
    answer: CWE-78 is `cmdi` and `rce`, CWE-98 is `lfi` and `rfi`."""
    return list(load()["by_cwe"].get(str(cwe or "").strip().upper(), []))


def class_for_cwe(cwe) -> str:
    """The class a CWE identifies ON ITS OWN — which is only meaningful when
    it points at exactly one.

    Returns `unknown` when the CWE is unmapped AND when it is ambiguous,
    because "I cannot tell from this alone" is the truthful answer and
    returning the alphabetically-first class would be a fabricated certainty.
    Callers with more to go on should use `resolve()`.
    """
    hits = classes_for_cwe(cwe)
    return hits[0] if len(hits) == 1 else UNKNOWN


def resolve(text=None, cwes=None) -> dict:
    """Decide a class from the COMBINATION of a name and a CWE set.

    The class NAME is primary: an advisory that says "path traversal" has told
    us the class, and no CWE should overrule it. The CWEs narrow when the text
    does not name a class, and where they disagree the ambiguity is reported
    rather than resolved by file order.

    Returns {class, candidates, basis, ambiguous}:
        basis = "name"      a class name or alias appeared in the text
                "cwe"       the CWEs pointed at exactly one class
                "cwe+name"  several CWE candidates, the text picked one
                "none"      nothing to go on -> class is `unknown`
    `ambiguous` is True when several candidates survived; `class` is then
    `unknown` and `candidates` carries them, so a caller can ask for more
    evidence instead of acting on a guess.
    """
    t = str(text or "")
    tbl = load()

    # 1. An explicit name or alias in the text wins outright. Matched on word
    #    boundaries, longest alias first.
    named = [(n, cls) for n, rx, cls in tbl.get("alias_res", []) if rx.search(t)]
    if named:
        top = named[0][0]
        tied = {c for n, c in named if n == top}
        if len(tied) == 1:
            return {"class": named[0][1],
                    "candidates": sorted({c for _, c in named}),
                    "basis": "name", "ambiguous": False}

    # 2. The CWEs give a candidate set.
    cands: List[str] = []
    for cw in (cwes or []):
        for c in classes_for_cwe(cw):
            if c not in cands:
                cands.append(c)
    cands.sort()
    if len(cands) == 1:
        return {"class": cands[0], "candidates": cands, "basis": "cwe",
                "ambiguous": False}

    # 3. Several CWE candidates — let the text break the tie, but only if it
    #    actually mentions one of them.
    if len(cands) > 1:
        mentioned = [cls for _, rx, cls in tbl.get("alias_res", [])
                     if cls in cands and rx.search(t)]
        if len(set(mentioned)) == 1:
            return {"class": mentioned[0], "candidates": cands,
                    "basis": "cwe+name", "ambiguous": False}
        return {"class": UNKNOWN, "candidates": cands, "basis": "cwe",
                "ambiguous": True}

    return {"class": UNKNOWN, "candidates": [], "basis": "none",
            "ambiguous": False}


def cwes_for(name) -> List[dict]:
    return list((get(name) or {}).get("cwes") or [])


def cwe_ids_for(name) -> List[str]:
    return [str(c.get("id")) for c in cwes_for(name) if c.get("id")]


def owasp_for(name) -> Optional[str]:
    return (get(name) or {}).get("owasp")


def wstg_for(name) -> List[str]:
    return list((get(name) or {}).get("wstg") or [])


def mitre_for(name) -> List[str]:
    return list((get(name) or {}).get("mitre") or [])


def references(name) -> dict:
    """Everything a report needs to name this finding in the reader's own
    vocabulary — CWE, OWASP Top 10, WSTG and ATT&CK in one call."""
    c = get(name) or {}
    return {"class": canonical(name), "title": c.get("title"),
            "cwes": cwes_for(name), "owasp": c.get("owasp"),
            "wstg": wstg_for(name), "mitre": mitre_for(name)}
