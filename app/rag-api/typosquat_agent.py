"""Typosquat / lookalike domain detector.

Priority #C in the OSINT scope-expansion plan. Given an engagement's
in-scope apex domains (e.g. `blackbaud.com`), this agent generates
plausible lookalike domains an attacker would register — the ones the
operator must NEVER accidentally scan — and flags them.

Six transform families:
  * edit-1 / edit-2 (insert, delete, substitute)
  * adjacent-key QWERTY typos
  * homoglyph confusables (ASCII, with a bounded Cyrillic set)
  * bitsquats (single-bit flip on each ASCII character)
  * IDN forms (xn-- punycode of a lookalike string)
  * TLD swaps (same base, different TLD)

The scorer blends edit distance, confusable count, IDN presence, and
resolution tier into a score in [0.0, 1.0]. High-confidence candidates
(score >= TYPOSQUAT_AUTO_BLOCK_AT, default 0.85) are auto-added to the
GLOBAL `not_in_scope` deny-list via `exclude_from_scope` — the scope
gate refuses dispatch for every engagement. Lower-score candidates land
in `scope_suggestions` for operator review.

Operator-confirmed design (from the plan):
  * TLD-swap-only (no character change) is LOWER confidence — never
    auto-blocks. Legitimate sister TLDs (`blackbaud.com` + `blackbaud.co.uk`)
    stay reviewable.
  * Any IDN presence (`xn--` form) scores high regardless of edit distance.
"""
from __future__ import annotations

import ipaddress
import logging
import os
import socket
import string
from typing import Iterable

logger = logging.getLogger(__name__)

# QWERTY row adjacency (US layout). Each key maps to the keys reachable
# by a single sideways/vertical slip. Kept lowercase; the generator
# lowercases the seed before expansion.
_QWERTY_ADJACENT: dict[str, str] = {
    "q": "wa", "w": "qeas", "e": "wrsd", "r": "etdf", "t": "ryfg",
    "y": "tugh", "u": "yihj", "i": "uojk", "o": "ipkl", "p": "ol",
    "a": "qwsz", "s": "awedxz", "d": "serfxc", "f": "drtgcv",
    "g": "ftyhvb", "h": "gyujbn", "j": "huiknm", "k": "jiolm",
    "l": "kop", "z": "asx", "x": "zsdc", "c": "xdfv",
    "v": "cfgb", "b": "vghn", "n": "bhjm", "m": "njk",
    "0": "9", "1": "2q", "2": "13qw", "3": "24we", "4": "35er",
    "5": "46rt", "6": "57ty", "7": "68yu", "8": "79ui", "9": "80io",
}

# ASCII->lookalike character substitutions. Includes Cyrillic a/e/o/p/c (and
# their uppercase counterparts) that render identically to Latin letters in
# most fonts. Also classic ASCII swaps (rn->m, l->1, O->0). Each entry maps a
# source char to a sequence of plausible lookalike characters.
_HOMOGLYPHS: dict[str, str] = {
    "a": "а",   # cyrillic a (U+0430)
    "e": "е",   # cyrillic e (U+0435)
    "o": "о0",  # cyrillic o (U+043E), plus zero
    "p": "р",   # cyrillic er (U+0440)
    "c": "с",   # cyrillic es (U+0441)
    "x": "х",   # cyrillic ha (U+0445)
    "y": "у",   # cyrillic u (looks like y)
    "l": "1ӏI", # digit 1, Cyrillic palochka (U+04CF), uppercase i
    "i": "1l",       # digit 1, lowercase L
    "s": "5",        # digit 5
    "g": "9",        # digit 9
    "b": "68",       # digits 6 and 8
    "n": "mh",       # m, h
    "m": "n",        # single n (also rn->m handled below as 2-char rule)
    "u": "v",        # v
    "v": "u",        # u
    "d": "cl",       # c+l
}

# Two-character rules — e.g. `rn` -> `m` is the classic typosquat trick.
# Applied LEFT-to-RIGHT: find source bigram, replace with the lookalike.
_HOMOGLYPH_BIGRAMS: list[tuple[str, str]] = [
    ("rn", "m"),
    ("vv", "w"),
    ("cl", "d"),
    ("nn", "m"),
    ("rr", "n"),
    ("ij", "u"),
]

# Common TLD swaps. Operator-confirmed: these are LOW-confidence by
# default because legitimate sister TLDs are common.
_TLD_SWAPS: tuple[str, ...] = (
    "com", "net", "org", "co", "io", "us", "info", "biz", "me",
    "co.uk", "com.au", "co.in", "io.net",
)

# Max candidates per seed. Caps the fan-out so a long seed doesn't DOS
# the generator — operator-confirmed in the plan ("bounded set ~200/domain").
MAX_CANDIDATES_PER_SEED = int(os.environ.get("TYPOSQUAT_MAX_PER_SEED", "200"))

# Score at which a candidate is auto-added to the GLOBAL not_in_scope
# deny-list. Below this threshold, the candidate lands in
# scope_suggestions for operator review only.
TYPOSQUAT_AUTO_BLOCK_AT = float(os.environ.get("TYPOSQUAT_AUTO_BLOCK_AT", "0.85"))


# ─── Candidate generation ──────────────────────────────────────────────

def _split_domain(domain: str) -> tuple[str, str]:
    """Return (label, tld) where label is everything before the LAST dot
    and tld is the remainder. `foo.co.uk` -> ("foo", "co.uk"). For
    unusual tld forms we treat the first dot as the split so a
    user-supplied `foo.sub.example.com` gets label="foo.sub.example"
    and the TLD-swap transform doesn't touch internal structure."""
    d = (domain or "").strip().strip(".").lower()
    if "." not in d:
        return d, ""
    # Match the operator-friendly "last-two-labels-ish" rule for well-known
    # multi-part TLDs so bb.co.uk splits as ("bb", "co.uk") instead of
    # ("bb.co", "uk").
    for multi in ("co.uk", "co.in", "com.au", "co.jp", "co.kr", "co.za",
                  "ac.uk", "org.uk", "gov.uk"):
        if d.endswith("." + multi):
            label = d[:-(len(multi) + 1)]
            return label, multi
    base, _, tld = d.rpartition(".")
    return base, tld


def _edit_variants(label: str, max_edits: int = 2) -> set[str]:
    """Edit-distance-1 and -2 variants of `label`.

    Includes insertion (1 char from a-z0-9), deletion (one char), and
    substitution (one char with another from a-z0-9). Bounded by
    MAX_CANDIDATES_PER_SEED at the caller — we don't cap here so the
    caller can mix with other transforms before trimming.
    """
    alphabet = string.ascii_lowercase + string.digits
    seen: set[str] = set()

    def _edit1(s: str) -> Iterable[str]:
        # Deletions
        for i in range(len(s)):
            yield s[:i] + s[i+1:]
        # Substitutions
        for i in range(len(s)):
            for ch in alphabet:
                if ch != s[i]:
                    yield s[:i] + ch + s[i+1:]
        # Insertions
        for i in range(len(s) + 1):
            for ch in alphabet:
                yield s[:i] + ch + s[i:]

    for v in _edit1(label):
        if v and 2 < len(v) < 64 and v != label:
            seen.add(v)
    if max_edits >= 2:
        # Edit-2: one more edit from each edit-1 result. Cap to keep the
        # fan-out finite — pick a sample of edit-1 results.
        edit1_sample = sorted(seen)[:40]
        for v1 in edit1_sample:
            for v2 in _edit1(v1):
                if v2 and 2 < len(v2) < 64 and v2 != label:
                    seen.add(v2)
    return seen


def _qwerty_adjacent_variants(label: str) -> set[str]:
    """Single-key QWERTY-adjacent slip at each position."""
    out: set[str] = set()
    for i, ch in enumerate(label):
        for neighbor in _QWERTY_ADJACENT.get(ch, ""):
            v = label[:i] + neighbor + label[i+1:]
            if v != label:
                out.add(v)
    return out


def _homoglyph_variants(label: str) -> set[str]:
    """Single-char substitutions using the ASCII/Cyrillic lookalike map,
    plus the bigram rules (rn->m, vv->w, cl->d, nn->m, rr->n, ij->u).
    IDN forms (xn--) are produced by _idn_variants, not here."""
    out: set[str] = set()
    for i, ch in enumerate(label):
        for sub in _HOMOGLYPHS.get(ch, ""):
            v = label[:i] + sub + label[i+1:]
            if v != label:
                out.add(v)
    for src, dst in _HOMOGLYPH_BIGRAMS:
        if src in label:
            out.add(label.replace(src, dst, 1))
        if dst in label:
            # Reverse direction: m->rn in the LAST position of the label
            # (common in registered typosquats like `rnicrosoft`).
            idx = label.rfind(dst)
            if idx >= 0:
                out.add(label[:idx] + src + label[idx+len(dst):])
    return out


def _bitsquat_variants(label: str) -> set[str]:
    """Single-bit flip of each ASCII character. Keeps only variants that
    land back in the printable ASCII (letters + digits + hyphen) set — a
    bitsquat where the flipped byte isn't a valid DNS char is unregisterable."""
    valid = set(string.ascii_lowercase + string.digits + "-")
    out: set[str] = set()
    for i, ch in enumerate(label):
        if not ch.isascii():
            continue
        base = ord(ch)
        for bit in range(8):
            flipped = chr(base ^ (1 << bit)).lower()
            if flipped in valid and flipped != ch:
                v = label[:i] + flipped + label[i+1:]
                if v != label:
                    out.add(v)
    return out


def _idn_variants(label: str) -> set[str]:
    """IDN / punycode forms. Produces one `xn--` encoding of a
    Cyrillic-substituted variant per each homoglyph position. These
    always score high regardless of distance (operator-confirmed)."""
    out: set[str] = set()
    for i, ch in enumerate(label):
        for sub in _HOMOGLYPHS.get(ch, ""):
            if sub.isascii():
                continue  # ASCII swaps aren't IDN
            v = label[:i] + sub + label[i+1:]
            try:
                puny = v.encode("idna").decode("ascii")
                if puny.startswith("xn--"):
                    out.add(puny)
            except (UnicodeError, UnicodeDecodeError):
                continue
    return out


def _tld_swaps(label: str, tld: str) -> set[str]:
    """Full-domain variants with the base label unchanged, TLD swapped
    to each entry in _TLD_SWAPS. Returns full `label.newtld` strings so
    they can be de-duped alongside character-level variants.

    Operator-confirmed: these score LOW (sister TLDs are common and
    often legitimate) and never auto-block."""
    out: set[str] = set()
    for new_tld in _TLD_SWAPS:
        if new_tld != tld.lower():
            out.add(f"{label}.{new_tld}")
    return out


def generate_typosquat_candidates(seed_domain: str,
                                  max_candidates: int = MAX_CANDIDATES_PER_SEED
                                  ) -> list[dict]:
    """Build a bounded set of plausible typosquat candidates for one seed.

    Each returned entry: {domain, transform, source_label}. `transform`
    identifies which family produced it ("edit", "qwerty", "homoglyph",
    "bitsquat", "idn", "tld_swap") so the scorer can weight accordingly.

    The result is deterministic for a given seed — repeated calls return
    the same set in the same order."""
    label, tld = _split_domain(seed_domain)
    if not label or not tld:
        return []
    candidates: list[dict] = []
    seen_domains: set[str] = set()

    def _add(variant_label: str, transform: str, as_full_domain: bool = False):
        full = variant_label if as_full_domain else f"{variant_label}.{tld}"
        key = full.lower()
        if key == seed_domain.lower() or key in seen_domains:
            return
        seen_domains.add(key)
        candidates.append({
            "domain": full,
            "transform": transform,
            "source_label": seed_domain,
        })

    # Priority order: higher-signal transforms first so trimming the tail
    # drops the noisiest first.
    for v in _idn_variants(label):
        _add(v, "idn")
    for v in _homoglyph_variants(label):
        _add(v, "homoglyph")
    for v in _bitsquat_variants(label):
        _add(v, "bitsquat")
    for v in _qwerty_adjacent_variants(label):
        _add(v, "qwerty")
    for v in _edit_variants(label, max_edits=1):
        _add(v, "edit1")
    for v in _tld_swaps(label, tld):
        _add(v, "tld_swap", as_full_domain=True)
    for v in _edit_variants(label, max_edits=2):
        _add(v, "edit2")

    return candidates[:max_candidates]


# ─── Scoring ──────────────────────────────────────────────────────────

def _levenshtein(a: str, b: str) -> int:
    """Pure-Python Levenshtein edit distance. Fine for domain-length
    strings (< 64 chars)."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            curr[j] = min(
                prev[j] + 1,            # deletion
                curr[j - 1] + 1,        # insertion
                prev[j - 1] + (ca != cb)  # substitution
            )
        prev = curr
    return prev[-1]


def _confusable_char_count(a: str, b: str) -> int:
    """Count positions where `a` and `b` differ by a known confusable
    (homoglyph) pair. Only compared at matching index positions, so this
    is a weak signal for insertions/deletions."""
    count = 0
    for ca, cb in zip(a, b):
        if ca == cb:
            continue
        if cb in _HOMOGLYPHS.get(ca, "") or ca in _HOMOGLYPHS.get(cb, ""):
            count += 1
    return count


def _resolves(domain: str, timeout_sec: float = 2.0) -> str:
    """Return 'resolves', 'parked', or 'unregistered' for a domain.

    v1 implementation uses socket DNS resolution — a resolving domain is
    'resolves' (someone owns + hosts it), a domain that returns a known
    parking IP (we don't maintain that list yet) OR fails resolution with
    NXDOMAIN is treated as 'unregistered'. For a quick signal this is
    sufficient; higher-fidelity registration checks (RDAP / WHOIS) are a
    v2 improvement."""
    socket.setdefaulttimeout(timeout_sec)
    try:
        info = socket.getaddrinfo(domain, None)
        if info:
            return "resolves"
    except socket.gaierror:
        return "unregistered"
    except Exception:  # noqa: BLE001
        return "unregistered"
    finally:
        socket.setdefaulttimeout(None)
    return "unregistered"


def score_typosquat(cand: dict, seed_domain: str,
                    resolution: str | None = None) -> dict:
    """Return {score, reason} for a candidate.

    Score components (summed, capped at 1.0):
      * IDN presence         +0.6  — any xn-- form is always suspicious
      * Confusable char      +0.15 per lookalike char at matched position
      * Low edit distance    up to +0.4 (closer == higher)
      * Resolution signal    +0.2 if resolves, +0.1 if parked, 0 if unreg
      * TLD-swap-only penalty -0.3 so legitimate sister TLDs don't auto-block
    """
    cand_label, _ = _split_domain(cand["domain"])
    seed_label, _ = _split_domain(seed_domain)
    transform = cand.get("transform", "")

    score = 0.0
    reasons: list[str] = []

    if transform == "idn" or "xn--" in cand["domain"]:
        score += 0.6
        reasons.append("IDN (punycode) form — attackers' favorite")
    # Confusable chars at matching positions
    conf_count = _confusable_char_count(cand_label, seed_label)
    if conf_count > 0:
        score += min(0.45, 0.15 * conf_count)
        reasons.append(f"{conf_count} confusable char(s)")
    # Edit distance signal (closer = higher score; capped at distance 3)
    dist = _levenshtein(cand_label, seed_label)
    if dist > 0:
        edit_component = max(0.0, 0.4 - 0.1 * (dist - 1))
        if edit_component > 0:
            score += edit_component
            reasons.append(f"edit distance {dist}")
    # Resolution signal
    if resolution == "resolves":
        score += 0.2
        reasons.append("domain resolves")
    elif resolution == "parked":
        score += 0.1
        reasons.append("domain parked")
    # TLD-swap-only penalty (no character change)
    if transform == "tld_swap":
        score -= 0.3
        reasons.append("TLD swap only (sister-TLD risk, pending review)")

    score = max(0.0, min(1.0, score))
    return {
        "score": round(score, 3),
        "reason": "; ".join(reasons) if reasons else "(no signal)",
        "transform": transform,
        "edit_distance": dist,
        "confusable_count": conf_count,
    }


# ─── Database write path ──────────────────────────────────────────────

def _resolve_apex_seeds(cur, engagement_id: str) -> list[str]:
    """Pull apex domains from the engagement's scope_targets. Only
    target_type='domain' (and 'url' normalized to its host) qualify as
    seeds — IPs and CIDRs don't generate typosquats."""
    try:
        cur.execute(
            "SELECT target, target_type FROM public.scope_targets "
            "WHERE engagement_id = %s::uuid "
            "AND target IS NOT NULL AND target <> '' "
            "AND target_type IN ('domain', 'url')",
            (engagement_id,),
        )
        rows = cur.fetchall()
    except Exception as e:
        logger.warning("resolve_apex_seeds failed: %s", e)
        return []
    seeds: set[str] = set()
    for r in rows:
        if isinstance(r, dict):
            tgt, ttype = r.get("target"), r.get("target_type")
        else:
            tgt, ttype = r[0], r[1]
        if not tgt:
            continue
        # Normalize url targets to the host
        if ttype == "url":
            from urllib.parse import urlparse
            try:
                h = urlparse(tgt if "://" in tgt else "//" + tgt).netloc
                if "@" in h:
                    h = h.split("@")[-1]
                if ":" in h:
                    h = h.split(":")[0]
                tgt = h or tgt
            except Exception:  # noqa: BLE001
                pass
        tgt = (tgt or "").strip().lower().rstrip(".")
        # Skip IPs (shouldn't be here but defensive)
        try:
            ipaddress.ip_address(tgt)
            continue
        except ValueError:
            pass
        if tgt and "." in tgt:
            seeds.add(tgt)
    return sorted(seeds)


def _write_suggestion(cur, candidate: str, reasoning: str,
                      confidence: float) -> bool:
    """Insert into scope_suggestions. Idempotent via the UNIQUE(target)
    constraint — a repeat candidate is skipped with ON CONFLICT. Returns
    True on insert, False on conflict / error."""
    try:
        cur.execute(
            "INSERT INTO public.scope_suggestions "
            "(target, suggested_scope, confidence, reasoning, method) "
            "VALUES (%s, 'typosquats', %s, %s, 'typosquat') "
            "ON CONFLICT (target) DO NOTHING",
            (candidate, confidence, reasoning),
        )
        return cur.rowcount > 0
    except Exception as e:  # noqa: BLE001
        logger.debug("scope_suggestions write failed for %s: %s", candidate, e)
        return False


def _add_to_typosquats_scope(cur, candidate: str, engagement_id: str) -> bool:
    """Insert the candidate into the engagement's `typosquats` scope.

    This replaces the earlier flat insert into the global `not_in_scope`
    deny-list: operator asked for typosquats to be grouped under their
    own named scope so they are visible as a cohort instead of mixed
    into the general exclude list. The scope gate's deny-list loader
    (etl/scope_gate.load_not_in_scope_denylist) now ALSO reads every
    engagement's `typosquats` scope, so block semantics are preserved —
    the gate still refuses dispatch to anything landed here, including
    cross-engagement.

    engagement_id is REQUIRED. Per CLAUDE.md's "Scope entries are
    per-engagement collected config" invariant, writing a scope row
    without attribution is an orphan a purge cannot claim. If no
    engagement is available the write is REFUSED (not silently
    downgraded to the global not_in_scope list, which was the old
    behaviour) — operator-asked tightening so a typosquat is never
    recorded under the wrong engagement.
    """
    if not engagement_id:
        logger.warning(
            "typosquats scope write refused for %s: no engagement_id "
            "in context (CLAUDE.md requires engagement attribution)",
            candidate,
        )
        return False
    try:
        cur.execute(
            "INSERT INTO public.scope_targets "
            "(name, target, target_type, source, engagement_id) "
            "VALUES ('typosquats', %s, 'domain', 'typosquat_auto', %s::uuid) "
            "ON CONFLICT DO NOTHING",
            (candidate, engagement_id),
        )
        return cur.rowcount > 0
    except Exception as e:  # noqa: BLE001
        logger.debug("typosquats scope write failed for %s: %s",
                     candidate, e)
        return False


# Keep the old name as an alias so any late-pattern caller / test that
# imports `_add_to_denylist` still finds it. Both routes write to the
# same destination now.
_add_to_denylist = _add_to_typosquats_scope


def flag_typosquats_for_engagement(get_db_fn, engagement_id: str,
                                   check_resolution: bool = True,
                                   auto_block_at: float = TYPOSQUAT_AUTO_BLOCK_AT
                                   ) -> dict:
    """Entry point. For each in-scope apex domain of the engagement:
    generate candidates, score, write to scope_suggestions, and
    auto-add high-confidence hits to not_in_scope.

    `get_db_fn` is a callable returning a context-managed DB connection
    (passed in by the caller to keep this module decoupled from
    app.rag_api.api — eases unit testing).

    Returns a summary dict: {seeds, total_candidates, suggestions_written,
    denylist_added}. The caller surfaces this in a /jobs/scope-pivot
    response.
    """
    out = {
        "seeds": 0,
        "total_candidates": 0,
        "suggestions_written": 0,
        "denylist_added": 0,
        "errors": [],
    }
    try:
        with get_db_fn() as c, c.cursor() as cur:
            seeds = _resolve_apex_seeds(cur, engagement_id)
            out["seeds"] = len(seeds)
            for seed in seeds:
                cands = generate_typosquat_candidates(seed)
                out["total_candidates"] += len(cands)
                for cand in cands:
                    resolution = (_resolves(cand["domain"])
                                  if check_resolution else None)
                    score_info = score_typosquat(cand, seed,
                                                  resolution=resolution)
                    reasoning = (f"{score_info['reason']} "
                                 f"(resolution={resolution or 'skipped'})")
                    if _write_suggestion(cur, cand["domain"],
                                          reasoning, score_info["score"]):
                        out["suggestions_written"] += 1
                    # Auto-block high-confidence hits — but never
                    # auto-block tld_swap-only (operator-confirmed guard).
                    if (score_info["score"] >= auto_block_at
                            and cand.get("transform") != "tld_swap"):
                        if _add_to_typosquats_scope(cur, cand["domain"],
                                                     engagement_id):
                            out["denylist_added"] += 1
            c.commit()
    except Exception as e:
        logger.exception("flag_typosquats_for_engagement failed")
        out["errors"].append(str(e))
    return out
