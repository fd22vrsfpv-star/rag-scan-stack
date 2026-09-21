"""Structure a tool's raw output, so a run can be judged.

WHY THIS EXISTS
---------------
`tool_executions.parsed_results` was NULL for every netexec run — and for most
other tools — because nothing ever computed it. `db_update_tool_execution()`
accepted it as an argument and no caller passed one.

The consequence reached all the way into the learning loop. A netexec run
against a legacy-SSH host exited **0** with a rendered Python traceback in 6,816
bytes of output; with no parser, `result_count` was unknown, the run was
"unmeasured", and it was recorded as a success that could have activated a rule
as proof the tool works.

WHAT IT IS
----------
A registry, not a parser. Each entry is a tool name and a pure function from
text to a dict. Adding a tool is one line here and one function next to the
existing `etl/parse_*.py` module for it.

A tool with no entry returns None — **not** an empty dict. "Nobody has written a
parser for this" and "the parser ran and found nothing" are different facts and
the learner acts differently on each: unknown teaches it nothing, whereas zero
results is a reason to try another tool.
"""
from __future__ import annotations

import logging
import os
import re
from typing import Any, Callable, Dict, Optional

log = logging.getLogger("tool_output_parsers")


def _netexec(output: str, error: str = "") -> Dict[str, Any]:
    try:
        from etl.parse_netexec import parse_netexec_output
    except ImportError:  # pragma: no cover - bare import from within etl/
        from parse_netexec import parse_netexec_output
    return parse_netexec_output(f"{output}\n{error}" if error else output)


def _nuclei(output: str, error: str = "") -> Dict[str, Any]:
    """nuclei -json / -jsonl output: one JSON object per finding.

    nuclei already had `etl/parse_nuclei.py`, but that one takes a FILE PATH and
    writes findings to the database — it is the ingest path. This registry needs
    a pure text->dict function, so a tool run recorded in `tool_executions` was
    left unparsed: every nuclei run had `parsed_results IS NULL`, ~7.8 MB of real
    output that nothing read. "It has a parser" was true and beside the point.

    Tolerant by design: nuclei interleaves banner/progress lines on stderr and
    occasionally a non-JSON line on stdout, so unparseable lines are skipped
    rather than failing the run.
    """
    import json as _json

    findings = []
    for line in (output or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            d = _json.loads(line)
        except ValueError:
            continue
        if not isinstance(d, dict) or not d.get("template-id"):
            continue
        info = d.get("info") if isinstance(d.get("info"), dict) else {}
        findings.append({
            "template_id": d.get("template-id"),
            "name": info.get("name"),
            "severity": (info.get("severity") or "unknown").lower(),
            "host": d.get("host"),
            "matched_at": d.get("matched-at"),
            "tags": info.get("tags"),
        })

    by_sev: Dict[str, int] = {}
    for f in findings:
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1

    return {
        "tool": "nuclei",
        "findings": findings,
        "counts": {"findings": len(findings), "by_severity": by_sev},
        # An `info`-only run found nothing actionable, but it DID run and read
        # the target — unlike netexec's banner lines, these are real matches, so
        # any finding counts as productive.
        "productive": bool(findings),
    }


# ── Four tools whose output nobody read ────────────────────────────────────
#
# `tool_executions` held 180 completed runs with `parsed_results IS NULL` for
# curl (172 runs, 482 KB), cewl (2), rmg (5) and showmount (1). Each parser
# below was written against the rows themselves, and the fixtures under
# tests/fixtures/ are those rows byte for byte.
#
# Each returns ONE key from `result_count`'s `meaningful` tuple — "results" —
# alongside descriptive counts that tuple does not contain. That is deliberate:
# `result_count` SUMS every meaningful key it finds, so a parser that emitted
# two would double-count its own run.

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_HTTP_STATUS_RE = re.compile(r"^HTTP/[\d.]+\s+(\d{3})(?:\s+(.*))?$")


def _curl(output: str, error: str = "") -> Dict[str, Any]:
    """curl: an HTTP response, or the reason there wasn't one.

    Three real shapes live in the column, all captured as fixtures:

      * `-I` / `-i` — a header block only (`HTTP/1.1 200 OK` + headers);
      * no `-i` — a bare body, where the status is genuinely UNKNOWN;
      * exit 2 with empty output and `/bin/sh: 1: Syntax error: Unterminated
        quoted string` on stderr — a command that never reached the network.

    The distinction that matters is the second and third against the first.
    Most of the 172 runs are probes (`?template=../../etc/passwd`), and the
    server answers a probe it does not like with a 200-shaped shell around
    `<title>404 Not Found</title>` and no status line at all. Counting that as a
    result is precisely how a probe that found nothing reports as a hit, so when
    no status line was sent the body's error-page title supplies the status, and
    `status_source` says which of the two it came from.
    """
    text = output or ""
    responses: list = []
    cur: Optional[Dict[str, Any]] = None
    in_headers = False
    body_lines: list = []

    for raw in text.splitlines():
        line = raw.rstrip("\r")
        m = _HTTP_STATUS_RE.match(line.strip()) if line.lstrip().startswith("HTTP/") else None
        if m:
            if cur is not None:
                cur["_body"] = "\n".join(body_lines)
            body_lines = []
            cur = {"status": int(m.group(1)), "reason": (m.group(2) or "").strip(),
                   "status_source": "header", "headers": {}, "_body": ""}
            responses.append(cur)
            in_headers = True
            continue
        if in_headers and cur is not None:
            if not line.strip():
                in_headers = False
                continue
            if ":" in line:
                k, v = line.split(":", 1)
                cur["headers"][k.strip().lower()] = v.strip()
                continue
            in_headers = False  # not a header line after all; fall through
        body_lines.append(raw)

    if cur is not None:
        cur["_body"] = "\n".join(body_lines)
    elif text.strip():
        # A bare body with no status line: curl fetched something and the caller
        # did not ask for headers. `status` stays None — "we did not see one" is
        # not the same claim as "it was 200".
        cur = {"status": None, "reason": "", "status_source": None,
               "headers": {}, "_body": text}
        responses.append(cur)

    parsed_responses = []
    for r in responses:
        body = r["_body"]
        title = None
        mt = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
        if mt:
            title = " ".join(mt.group(1).split())
        status, source = r["status"], r["status_source"]
        if status is None and title:
            mc = re.match(r"^(\d{3})\b", title)
            if mc:
                status, source = int(mc.group(1)), "body_title"
        h = r["headers"]
        parsed_responses.append({
            "status": status,
            "status_source": source,
            "reason": r["reason"] or None,
            "server": h.get("server"),
            "content_type": h.get("content-type"),
            "location": h.get("location"),
            "set_cookie": "set-cookie" in h,
            "www_authenticate": h.get("www-authenticate"),
            "header_count": len(h),
            "title": title,
            "body_bytes": len(body.encode("utf-8", "replace")),
        })

    def _succeeded(r: Dict[str, Any]) -> bool:
        if r["status"] is not None:
            return r["status"] < 400
        return r["body_bytes"] > 0

    succeeded = [r for r in parsed_responses if _succeeded(r)]

    errors = [ln.strip() for ln in (error or "").splitlines() if ln.strip()]
    curl_errors = [{"code": int(c), "message": m.strip()}
                   for c, m in re.findall(r"curl:\s*\((\d+)\)\s*(.*)", error or "")]

    return {
        "tool": "curl",
        "responses": parsed_responses,
        "errors": errors[:10],
        "curl_errors": curl_errors,
        "counts": {
            "responses": len(parsed_responses),
            "results": len(succeeded),
            "body_bytes": sum(r["body_bytes"] for r in parsed_responses),
        },
        # A 4xx/5xx-only run, and a run that died in the shell, both READ as
        # zero — measured, and zero. Only "no output and no error at all"
        # reaches parse_for's unmeasured/None path.
        "productive": bool(succeeded),
    }


def _cewl(output: str, error: str = "") -> Dict[str, Any]:
    """cewl: a wordlist, behind one banner line.

    Real output is `CeWL 6.2.1 (More Fixes) Robin Wood ...` followed by one word
    per line — 1,445 of them from demo.testfire.net. The banner is not a word,
    and a line carrying whitespace is not a word either: cewl's `-c` (with
    counts) and `-e` (email section) shapes are NOT in the captured output, so
    rather than guess at them those lines are kept verbatim in `other_lines` and
    left OUT of the count. Under-reporting is recoverable; a wordlist inflated
    by section headers is not.
    """
    words: list = []
    seen: set = set()
    other: list = []
    banner = None
    for raw in (output or "").splitlines():
        line = raw.strip()
        if not line:
            continue
        if banner is None and line.startswith("CeWL "):
            banner = line
            continue
        if re.fullmatch(r"\S+", line):
            if line not in seen:   # duplicates would count the same word twice
                seen.add(line)
                words.append(line)
        else:
            other.append(line)

    return {
        "tool": "cewl",
        "version": banner,
        # The wordlist IS the result, so it is stored — bounded, because a large
        # site can produce tens of thousands of words and this lands in a jsonb
        # column. `counts.words` stays the true total either way.
        "words": words[:2000],
        "truncated": len(words) > 2000,
        "other_lines": other[:20],
        "counts": {"words": len(words), "results": len(words),
                   "other_lines": len(other)},
        "productive": bool(words),
    }


def _showmount(output: str, error: str = "") -> Dict[str, Any]:
    """showmount -e: the NFS export list.

    Real captured output is two lines::

        Export list for 192.168.1.150:
        / *

    — the whole filesystem exported to every client, which is the finding. Only
    the `-e` shape is parsed; `-a` and `-d` print a different layout that is not
    in the captured output, so their lines land in `notes` uncounted rather than
    being guessed at.
    """
    exports: list = []
    notes: list = []
    host = None
    for raw in (output or "").splitlines():
        line = raw.strip()
        if not line:
            continue
        m = re.match(r"^Export list for (.+?):$", line)
        if m:
            host = m.group(1)
            continue
        if line.startswith("/"):
            parts = re.split(r"\s+", line, maxsplit=1)
            clients_raw = parts[1].strip() if len(parts) > 1 else ""
            clients = [c for c in re.split(r"[,\s]+", clients_raw) if c]
            exports.append({
                "path": parts[0],
                "clients": clients,
                # `*` is "any host may mount this" — the reason showmount is run.
                "world_readable": "*" in clients,
            })
        else:
            notes.append(line)

    for ln in (error or "").splitlines():
        if ln.strip():
            notes.append(ln.strip())

    return {
        "tool": "showmount",
        "host": host,
        "exports": exports,
        "notes": notes[:10],
        "counts": {"exports": len(exports), "results": len(exports),
                   "world_readable": sum(1 for e in exports if e["world_readable"])},
        # "Export list for X:" with nothing under it, and an RPC refusal, are
        # both a measured zero.
        "productive": bool(exports),
    }


def _rmg(output: str, error: str = "") -> Dict[str, Any]:
    """remote-method-guesser `enum`: what the RMI registry gave up.

    Real output is ANSI-coloured, `[+]`-prefixed, and organised as
    `<check> enumeration:` headers with `- ` detail lines under them. All five
    captured runs against 192.168.1.150 say the same thing: the registry
    answered, **no objects are bound to it**, and no check reported a
    vulnerability — while 5.6 KB of `java.lang.ClassNotFoundException` stack
    traces went to stderr, which is what makes "exit 0, lots of output" look
    like a productive run when it found nothing.

    So a bound name or a `Vulnerability Status: Vulnerable` is a result, and the
    enumeration sections on their own are not. Only the non-vulnerable status
    shape appears in the captured output, so the vulnerable test is deliberately
    narrow: the value must actually begin with "vulnerable", which "Non
    Vulnerable" does not.
    """
    text = _ANSI_RE.sub("", output or "")
    sections: list = []
    current: Optional[Dict[str, Any]] = None
    bound_names: list = []
    in_bound = False

    for raw in text.splitlines():
        line = raw
        if line[:3] in ("[+]", "[-]", "[*]"):
            line = line[3:]
        line = line.strip()
        if not line:
            continue
        if line.endswith(":") and not line.startswith("-"):
            current = {"name": line[:-1].strip(), "detail": []}
            sections.append(current)
            in_bound = current["name"].lower().startswith("rmi registry bound names")
            continue
        is_item = line.startswith("- ")
        item = line[2:].strip() if is_item else line
        if current is not None:
            current["detail"].append(item)
        if in_bound and is_item and item and not re.search(r"\s", item):
            # A bound name is a single token. The empty-registry case is the
            # sentence "No objects are bound to the registry.", which has spaces
            # and is therefore not mistaken for a name.
            bound_names.append(item)

    statuses = [{"kind": k.strip(), "value": v.strip()}
                for k, v in re.findall(r"^\s*(?:\[[-+*]\])?\s*([A-Za-z][A-Za-z ]*?)\s+Status:\s*(.+)$",
                                       text, re.M)]
    vulnerable = [s for s in statuses
                  if "vulnerab" in s["kind"].lower()
                  and s["value"].strip().lower().startswith("vulnerable")]

    err_text = _ANSI_RE.sub("", error or "")
    exceptions = [{"exception": e, "call": c}
                  for e, c in re.findall(r"Caught unexpected (\S+) during (\S+) call", err_text)]

    results = len(bound_names) + len(vulnerable)
    return {
        "tool": "rmg",
        "bound_names": bound_names,
        "checks": [s["name"] for s in sections],
        "statuses": statuses,
        "vulnerable": vulnerable,
        "exceptions": exceptions,
        "counts": {"bound_names": len(bound_names), "checks": len(sections),
                   "vulnerable": len(vulnerable), "exceptions": len(exceptions),
                   "results": results},
        # Sections ran and reported nothing: measured, zero. NOT unmeasured.
        "productive": results > 0,
    }



# tool name -> pure text->dict parser. Aliases are listed explicitly rather than
# normalised, because `nxc` and `netexec` are genuinely both used and a silent
# prefix match would claim tools this does not handle.
PARSERS: Dict[str, Callable[..., Dict[str, Any]]] = {
    "netexec": _netexec,
    "nxc": _netexec,
    "crackmapexec": _netexec,   # same line format; netexec is its successor
    "nuclei": _nuclei,
    "curl": _curl,
    "cewl": _cewl,
    "showmount": _showmount,
    "rmg": _rmg,
    "remote-method-guesser": _rmg,   # the project's name for the `rmg` binary
}


# ── The extractor specs, as a second tier of parser ────────────────────────
#
# knowledge/extractors/*.yaml already describes how to read fourteen tools, as
# named regexes over their output. Those specs are authored through the
# Extract & Learn surface from real captured output, which is exactly the
# "create a parser" path — so a tool with a spec is a tool with a parser, and
# wiring them in here is what makes authoring one actually close the gap.
#
# This APPLIES a spec; it does not author one. Authoring lives in
# app/rag-api/extractor_learn.py and is unchanged. The two implementations of
# "run the deterministic patterns" are pinned to each other by
# tests/test_post_enumeration.py::test_the_two_spec_runners_agree, because a
# duplicated rule that drifts is worse than one that was never shared.

SPEC_DIR = os.environ.get("EXTRACTOR_SPEC_DIR", "/knowledge/extractors")
_SPEC_CACHE: Dict[str, Optional[Dict[str, Any]]] = {}


def _spec_for(tool: str) -> Optional[Dict[str, Any]]:
    """The extractor spec for a tool, honouring `aliases:`."""
    tool = (tool or "").strip().lower()
    if not tool:
        return None
    if tool in _SPEC_CACHE:
        return _SPEC_CACHE[tool]
    found = None
    try:
        import yaml
        if os.path.isdir(SPEC_DIR):
            for fn in sorted(os.listdir(SPEC_DIR)):
                if not fn.endswith((".yaml", ".yml")) or fn.startswith("_"):
                    continue
                with open(os.path.join(SPEC_DIR, fn), encoding="utf-8") as fh:
                    spec = yaml.safe_load(fh) or {}
                names = [str(spec.get("tool") or "").lower()]
                names += [str(a).lower() for a in (spec.get("aliases") or [])]
                if tool in names and spec.get("enabled", True):
                    found = spec
                    break
    except Exception as e:  # noqa: BLE001
        log.debug("extractor spec lookup for %s failed: %s", tool, e)
    _SPEC_CACHE[tool] = found
    return found


def _from_spec(tool: str, output: str, error: str = "") -> Optional[Dict[str, Any]]:
    """Run a spec's deterministic patterns over the output."""
    import re as _re
    spec = _spec_for(tool)
    if not spec:
        return None
    text = f"{output}\n{error}" if error else output
    fields: Dict[str, Any] = {}
    for name, decl in (spec.get("deterministic") or {}).items():
        pattern = decl.get("pattern") if isinstance(decl, dict) else decl
        if not pattern:
            continue
        try:
            m = _re.search(pattern, text, _re.M | _re.I)
        except _re.error:
            continue
        if m:
            fields[name] = m.group(1) if m.groups() else m.group(0)
    return {
        "tool": tool, "parser": "extractor_spec",
        "spec": spec.get("tool"),
        "extracted": fields,
        "counts": {"fields": len(fields)},
        # A spec that matched nothing read the output and found nothing, which
        # is a measurement. That is the whole difference from having no parser.
        "productive": bool(fields),
    }


def parse_status(tool: str) -> Dict[str, Any]:
    """Whether this tool can be read at all, and by what.

    ``{"tool", "has_parser", "kind"}`` where kind is `registry`, `extractor` or
    None. The distinction is the point: "no parser exists for this tool" is a
    DIFFERENT state from "the parser found nothing", it is actionable in a way
    the other is not, and until now it was invisible.
    """
    name = (tool or "").strip().lower()
    if name in PARSERS:
        return {"tool": name, "has_parser": True, "kind": "registry"}
    if _spec_for(name):
        return {"tool": name, "has_parser": True, "kind": "extractor"}
    return {"tool": name, "has_parser": False, "kind": None}


def parse_for(tool: str, output: str = "", error: str = "") -> Optional[Dict[str, Any]]:
    """Structured results for this tool's output, or None if unparsed.

    Never raises: a parser defect must not fail a tool run that already
    completed, and returning None then is honest — the run really is unmeasured.
    """
    if not (output or "").strip() and not (error or "").strip():
        return None
    fn = PARSERS.get((tool or "").strip().lower())
    if fn:
        try:
            return fn(output or "", error or "")
        except Exception as e:  # noqa: BLE001
            log.warning("parser for %s failed: %s", tool, e)
            return None
    # Second tier: an extractor spec. Authoring one through Extract & Learn is
    # the supported way to close a parser gap, so a spec has to count as a
    # parser or authoring one would change nothing.
    return _from_spec(tool, output or "", error or "")


def result_count(parsed: Optional[Dict[str, Any]]) -> Optional[int]:
    """How many results a parse represents, or None when it cannot be judged.

    None propagates "unmeasured" rather than asserting zero, which is the
    distinction the learner needs: a tool nobody wrote a parser for must not be
    recorded as having found nothing.
    """
    if not isinstance(parsed, dict):
        return None
    counts = parsed.get("counts")
    if isinstance(counts, dict):
        # `productive` is the parser's own judgement about whether this run
        # achieved anything, and it is the authority — netexec prints a dozen
        # informational lines on first use, and counting those as results makes
        # an empty run look successful.
        if parsed.get("productive") is False:
            return 0
        meaningful = ("credentials", "shares", "findings", "command_output_lines",
                      "hosts", "results", "items", "vulnerabilities", "ports")
        total = sum(int(counts.get(k) or 0) for k in meaningful if k in counts)
        return total
    for key in ("findings", "results", "hosts", "credentials", "items"):
        v = parsed.get(key)
        if isinstance(v, list):
            return len(v)
    return None
