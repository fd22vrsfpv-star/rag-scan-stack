#!/usr/bin/env python3
"""Review a year's CVE descriptions + writeups to improve the class reading hints.

Runs INSIDE the rag-api container (it imports api.py, which has no import-time
side effects -- every daemon starts from a startup hook):

    docker cp scripts/cve_hint_review.py rag-api:/tmp/cve_hint_review.py
    docker exec -d rag-api sh -c 'python /tmp/cve_hint_review.py --phase enrich \
        > /app/poc_logs/hint_review/enrich.log 2>&1'

PHASES (each resumable -- a CVE already recorded in the phase's JSONL is skipped,
so a rag-api restart costs nothing but the in-flight CVE):

  enrich   NVD description, CWE, refs and GHSA advisory PoC via
           _fetch_cve_details (cached in software_research_cache), then the
           CWE-first class. The DuckDuckGo writeup search is OFF here: it was
           80 of 82 s per CVE (~21 h for a year), and 3,000 back-to-back
           searches would get the search blocked.
  writeups DuckDuckGo writeup search, ONLY for exploitable CVEs that enrich
           found no advisory PoC for, paced at one CVE per --search-pause s.
  read     For each EXPLOITABLE class (writeups merged over enrich rows): _read_description_requirements with the
           class's reading hints, the advisory/writeup text as extra context.
           One LLM call per CVE. Yields the per-CVE exploit path.
  propose  Per class: aggregate the read requirements, then ONE LLM call that
           proposes additions to `reading_hints` recurring in >= --min-support
           CVEs and not already covered. Proposals only -- a human applies them
           to knowledge/vuln_classes.yaml.

Output: /app/poc_logs/hint_review/{enrich,read}.jsonl and proposals.json.
No traffic goes to any engagement target; the only network calls are NVD and
the public advisory pages _fetch_cve_details already reads.
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import sys
import time

OUT_DIR = os.environ.get("HINT_REVIEW_DIR", "/app/poc_logs/hint_review")
NVD_PAUSE_S = float(os.environ.get("HINT_REVIEW_NVD_PAUSE", "6.5"))
SEARCH_PAUSE_S = float(os.environ.get("HINT_REVIEW_SEARCH_PAUSE", "20"))


def _done(path, key="cve"):
    out = set()
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            for line in f:
                try:
                    out.add(json.loads(line)[key])
                except Exception:  # noqa: BLE001
                    continue
    return out


def _append(path, row):
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(row, ensure_ascii=False) + "\n")


def _rows(path):
    if not os.path.exists(path):
        return []
    out = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            try:
                out.append(json.loads(line))
            except Exception:  # noqa: BLE001
                continue
    return out


def _emit(event_type, data):
    try:
        from webhooks import emit_webhook
        emit_webhook(event_type, "hint_review", data)
    except Exception:  # noqa: BLE001
        pass


def _year_cves(api, year):
    with api.get_db() as conn, conn.cursor() as cur:
        cur.execute("SELECT id FROM cve WHERE id ILIKE %s ORDER BY published",
                    (f"CVE-{year}-%",))
        return [r[0] for r in cur.fetchall()]


def phase_enrich(api, year, limit):
    path = os.path.join(OUT_DIR, "enrich.jsonl")
    done = _done(path)
    todo = [c for c in _year_cves(api, year) if c not in done][: limit or None]
    print(f"enrich: {len(done)} done, {len(todo)} to go", flush=True)
    api._BUILD_POC_WEB_SEARCH = False      # see the module docstring
    vc = api._vc()
    for i, cve in enumerate(todo, 1):
        t0 = time.monotonic()
        row = {"cve": cve, "ok": False}
        try:
            d = api._fetch_cve_details(cve) or {}
            cls = api._vuln_class_from_cve(cve, d)
            row.update(
                ok=bool(d.get("description")),
                description=(d.get("description") or "")[:4000],
                cwe=d.get("cwe") or [],
                refs=(d.get("refs") or [])[:20],
                advisory_poc=(d.get("advisory_poc") or "")[:3000],
                vuln_class=cls,
                exploitable=bool(vc and vc.is_exploitable(cls)),
            )
        except Exception as e:  # noqa: BLE001
            # Unreachable is not absent: record the failure, do not record a
            # class, so a later run retries rather than trusting a blank.
            row["error"] = f"{type(e).__name__}: {e}"[:300]
        if row.get("error"):
            print(f"  {cve}: ERROR {row['error']}", flush=True)
        else:
            _append(path, row)
        if i % 25 == 0:
            print(f"  {i}/{len(todo)}", flush=True)
        # Only an uncached fetch costs NVD quota; a cache hit returns in ms.
        if time.monotonic() - t0 > 0.5:
            time.sleep(NVD_PAUSE_S)
    _emit("hint_review_phase_completed",
          {"phase": "enrich", "year": year, "processed": len(todo)})


def phase_writeups(api, limit, pause):
    src = [r for r in _rows(os.path.join(OUT_DIR, "enrich.jsonl"))
           if r.get("ok") and r.get("exploitable") and not r.get("advisory_poc")]
    path = os.path.join(OUT_DIR, "writeups.jsonl")
    done = _done(path)
    todo = [r for r in src if r["cve"] not in done][: limit or None]
    print(f"writeups: {len(done)} done, {len(todo)} to go", flush=True)
    api._BUILD_POC_WEB_SEARCH = True
    for i, r in enumerate(todo, 1):
        try:
            d = api._fetch_cve_details(r["cve"]) or {}
            _append(path, {"cve": r["cve"],
                           "advisory_poc": (d.get("advisory_poc") or "")[:3000],
                           "refs": (d.get("refs") or [])[:30]})
        except Exception as e:  # noqa: BLE001
            print(f"  {r['cve']}: ERROR {type(e).__name__}: {e}"[:300], flush=True)
        if i % 10 == 0:
            print(f"  {i}/{len(todo)}", flush=True)
        time.sleep(pause)
    _emit("hint_review_phase_completed", {"phase": "writeups", "processed": len(todo)})


def merged_rows(enrich_rows, writeup_rows):
    """Enrich rows with any writeup the search phase found merged in. Pure."""
    found = {w["cve"]: w for w in writeup_rows if w.get("advisory_poc")}
    out = []
    for r in enrich_rows:
        w = found.get(r.get("cve"))
        if w and not r.get("advisory_poc"):
            r = dict(r, advisory_poc=w["advisory_poc"], writeup_from="search")
        out.append(r)
    return out


def phase_read(api, limit):
    src = [r for r in merged_rows(_rows(os.path.join(OUT_DIR, "enrich.jsonl")),
                                  _rows(os.path.join(OUT_DIR, "writeups.jsonl")))
           if r.get("ok") and r.get("exploitable")]
    path = os.path.join(OUT_DIR, "read.jsonl")
    done = _done(path)
    todo = [r for r in src if r["cve"] not in done][: limit or None]
    print(f"read: {len(done)} done, {len(todo)} to go", flush=True)
    for i, r in enumerate(todo, 1):
        writeup = r.get("advisory_poc") or ""
        req = api._read_description_requirements(
            r["cve"], r.get("description") or "", r.get("vuln_class"),
            extra_text=("ADVISORY / WRITEUP:\n" + writeup) if writeup else "")
        _append(path, {"cve": r["cve"], "vuln_class": r.get("vuln_class"),
                       "had_writeup": bool(writeup), "requirements": req or {}})
        if i % 25 == 0:
            print(f"  {i}/{len(todo)}", flush=True)
    _emit("hint_review_phase_completed", {"phase": "read", "processed": len(todo)})


def aggregate(read_rows):
    """Per class: how often each requirement appears, plus sample values.
    Pure -- tested in tests/test_cve_hint_review.py."""
    out = {}
    for r in read_rows:
        cls = r.get("vuln_class") or "unknown"
        req = r.get("requirements") or {}
        a = out.setdefault(cls, {"cves": 0, "with_requirements": 0,
                                 "keys": collections.Counter(),
                                 "samples": collections.defaultdict(list)})
        a["cves"] += 1
        if req:
            a["with_requirements"] += 1
        for k, v in req.items():
            if v in (None, "", [], False):
                continue
            a["keys"][k] += 1
            if len(a["samples"][k]) < 12:
                a["samples"][k].append(v)
    return {c: {"cves": a["cves"], "with_requirements": a["with_requirements"],
                "keys": dict(a["keys"]), "samples": dict(a["samples"])}
            for c, a in out.items()}


def phase_propose(api, min_support):
    agg = aggregate(_rows(os.path.join(OUT_DIR, "read.jsonl")))
    vc = api._vc()
    proposals = {}
    for cls, a in sorted(agg.items(), key=lambda kv: -kv[1]["cves"]):
        if a["with_requirements"] < min_support:
            continue
        cur = vc.reading_hints(cls) if vc else {"look_for": [], "implies": []}
        prompt = (
            "You maintain READING HINTS for one vulnerability class: what to look "
            "for in a CVE description, and what each finding implies for building "
            "and proving the exploit.\n"
            f"CLASS: {cls}\nCURRENT look_for: {json.dumps(cur['look_for'])}\n"
            f"CURRENT implies: {json.dumps(cur['implies'])}\n"
            f"Requirements extracted from {a['with_requirements']} real CVE "
            f"descriptions of this class (counts per key, then samples):\n"
            f"{json.dumps(a['keys'])}\n{json.dumps(a['samples'])[:6000]}\n\n"
            f"Propose ONLY additions that recur in at least {min_support} of these "
            "CVEs and are NOT already covered by the current hints. Return ONE JSON "
            'object: {"look_for": ["..."], "implies": ["..."], "evidence": "<which '
            'keys/counts justify each>"}. Empty lists if nothing qualifies.')
        try:
            res = api._llm_for_model(prompt, caller="hint_review_propose")
            text = res.get("response", "") if isinstance(res, dict) else str(res or "")
            obj = api._poc_extract_json(text) or {}
        except Exception as e:  # noqa: BLE001
            obj = {"error": f"{type(e).__name__}: {e}"[:200]}
        proposals[cls] = {"support": a["with_requirements"], "cves": a["cves"],
                          "current": cur, "proposed": obj, "keys": a["keys"]}
        print(f"  {cls}: {a['with_requirements']} CVEs -> "
              f"{len(obj.get('look_for') or [])} look_for, "
              f"{len(obj.get('implies') or [])} implies", flush=True)
    with open(os.path.join(OUT_DIR, "proposals.json"), "w", encoding="utf-8") as f:
        json.dump(proposals, f, indent=2, ensure_ascii=False)
    _emit("hint_review_phase_completed",
          {"phase": "propose", "classes": len(proposals)})


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--phase", required=True,
                    choices=("enrich", "writeups", "read", "propose"))
    ap.add_argument("--search-pause", type=float, default=SEARCH_PAUSE_S)
    ap.add_argument("--year", default="2026")
    ap.add_argument("--limit", type=int, default=0, help="max CVEs this run (0 = all)")
    ap.add_argument("--min-support", type=int, default=3)
    args = ap.parse_args(argv)
    os.makedirs(OUT_DIR, exist_ok=True)
    sys.path[:0] = ["/app"]
    import api  # noqa: E402  -- side-effect free at import (see docstring)
    if args.phase == "enrich":
        phase_enrich(api, args.year, args.limit)
    elif args.phase == "writeups":
        phase_writeups(api, args.limit, args.search_pause)
    elif args.phase == "read":
        if not hasattr(api, "_read_description_requirements"):
            sys.exit("read phase needs the description-read step -- deploy it first")
        phase_read(api, args.limit)
    else:
        phase_propose(api, args.min_support)


if __name__ == "__main__":
    main()
