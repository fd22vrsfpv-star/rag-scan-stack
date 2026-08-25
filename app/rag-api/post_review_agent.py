"""Post-execution review: find the scans that produced nothing, and the work missed.

WHY THIS EXISTS
---------------
A broken invocation, an interrupted container and a genuinely empty result are
three different things that look **identical** in every report: status text and
an empty `output` column. Nothing distinguished them, so 1348 executions were
carrying real lost work that read as "we scanned it, nothing there".

What the measurement actually showed, and why counting is not the deliverable:

  * **157** executions failed with `exit_code IS NULL` and the error
    "interrupted: kali-listener restarted while this was running". Not one of
    them is a tool defect. The container restarted mid-run and the work simply
    vanished — 31 nmap, 23 hydra, 23 lftp, 23 ftp. Nothing ever re-ran them.
  * **75** of the 85 "completed, exit 0, no output" rows are `ftp`/`lftp`
    invoked with no command to run, so the client opened, found nothing to do
    and exited 0 silently. The catalogue has since been fixed, which makes the
    remedy *re-run*, not *fix the command*.
  * **10** of those 85 are nuclei and whatweb against live hosts. Those are
    real empty results and flagging them would be a false positive.
  * **143** timed out — smbmap 44, nmap 44, hydra 31 — and nothing noticed.

So the value here is the **classification and its remedy**, not the count. A
check that reported "228 executions produced no output" would be true and
useless, because a third of that number is correct behaviour and the rest need
three different fixes.

WHAT IT DOES NOT DO
-------------------
It proposes; it never dispatches. Re-runs land in `scan_recommendations` as
`status='pending'`, `source='post_review'`, for a human to press Run — the same
contract as `auto_queue` and the exploit approval gate. Proposed targets are
still put through the scope gate, because a proposal that names an
out-of-scope host is an authorization problem whether or not it ran.

Coverage gaps ("this service was never scanned at all") belong to `gap_agent`
and are deliberately not re-derived here. This module reviews work that RAN.
"""
import json
import os
import re
import uuid
from datetime import datetime, timezone

CATALOGUE = os.environ.get("SERVICE_TOOLS_YAML", "/knowledge/service_tools.yaml")

# ── categories ──────────────────────────────────────────────────────────────
# `remedy` is the whole point: each category needs a DIFFERENT action, which is
# why they cannot be collapsed into one "no output" number. `actionable=False`
# means correct behaviour — reporting it as a problem would be the bug.
CATEGORIES = {
    "interrupted": {
        "remedy": "rerun",
        "actionable": True,
        "why": "the runner died mid-execution; the work was lost, not performed",
    },
    "broken_invocation": {
        "remedy": "fix_command",
        "actionable": True,
        "why": "the tool rejected its arguments or a path in them is absent",
    },
    "silent_no_op": {
        "remedy": "fix_command",
        "actionable": True,
        "why": "an interactive client ran with no command, so it exited 0 saying nothing",
    },
    "timed_out": {
        "remedy": "rerun_scoped",
        "actionable": True,
        "why": "killed by the deadline; needs a longer budget or a narrower target",
    },
    "crashed": {
        "remedy": "rerun",
        "actionable": True,
        "why": "the process died on a signal or its own assertion; no verdict was reached",
    },
    "placeholder_target": {
        "remedy": "fix_command",
        "actionable": True,
        "why": "queried a stand-in domain instead of the target — someone else's host",
    },
    "output_despite_failure": {
        "remedy": "ingest",
        "actionable": True,
        "why": ("a non-zero exit that still produced real output. Check "
                "results_not_ingested before acting: that list checks ATTRIBUTION "
                "and is the authority on whether the data actually landed. "
                "ssh-audit's 17 rows appear here because it exits 3 when it FINDS "
                "something — their 23 vulns rows were parsed long ago, so the "
                "remedy for those is the exit-code semantics "
                "(kali_listener TOOL_SUCCESS_EXIT_CODES), not re-ingestion"),
    },
    "failed_other": {
        "remedy": "triage",
        "actionable": True,
        "why": "exited non-zero for a reason not recognised here; read the error",
    },
    "empty_result": {
        "remedy": "none",
        "actionable": False,
        "why": "ran correctly and found nothing — this is a result, not a defect",
    },
    "produced_output": {
        "remedy": "none",
        "actionable": False,
        "why": "output captured",
    },
}

# "interrupted" is recorded by the runner itself when it finds an execution row
# still open after a restart, so this matches OUR text, not a tool's.
_INTERRUPTED = re.compile(r"interrupted:|restarted while", re.I)

# Signals that the command could not run as written. Kept deliberately narrow:
# each pattern below was observed in real captured output, and a loose pattern
# here would reclassify genuine empty results as defects.
_BROKEN = (
    (re.compile(r"flag provided but not defined|unknown option|invalid option|"
                r"unrecognized option|illegal option", re.I), "bad option"),
    (re.compile(r"does not exist|no such file or directory|"
                r"error opening|cannot open|unable to open|"
                r"wordlist.*not found", re.I), "missing path"),
    (re.compile(r"command not found|not installed|executable file not found", re.I),
     "no binary"),
    (re.compile(r"could not resolve|name or service not known|"
                r"unknown host", re.I), "unresolvable target"),
)

# A process that died on a signal reached no verdict at all. 134 is SIGABRT (an
# assertion inside the tool — 44 nmap runs aborted in nse_nsock.cc), 137 is
# SIGKILL, 139 is SIGSEGV, and a negative code is how the runner reports a
# signal. None of these are scan results.
_CRASH_EXITS = {134, 137, 139}
_CRASH_TEXT = re.compile(r"assertion .*failed|^killed$|core dumped|"
                         r"segmentation fault", re.I | re.M)

# Stand-in domains. Only a defect when the execution's own target is something
# ELSE — an engagement whose scope really is example.com is not doing this
# wrong, and comparing against the target column is what makes that distinction
# instead of assuming.
_PLACEHOLDER = re.compile(
    r"\bexample\.(?:com|org|net)\b|\{(?:target|domain|host|url|port)\}", re.I)

# Below this, output is a banner or an error line rather than a result worth
# ingesting. ssh-audit's 17 non-zero exits carry 8.9-9.5 KB each; hydra's
# warnings carry 451-825 bytes.
_SUBSTANTIVE_OUTPUT_BYTES = 200

# Tools that do NOTHING useful unless the command supplies work for them, and
# the tokens that supply it. This is the ftp/lftp defect stated as a rule: 78
# lftp runs and 43 ftp runs exited 0 having connected and done nothing.
NEEDS_COMMANDS = {
    "ftp": ("printf", "<<", "-n"),
    "lftp": ("-e", "-c", "-f"),
    "sftp": ("-b",),
    "tftp": ("-c", "<<", "printf"),
    "telnet": ("printf", "<<", "timeout"),
    "mysql": ("-e", "<"),
    "psql": ("-c", "-f"),
    "smbclient": ("-c",),
    "redis-cli": ("-x", "info", "keys", "config"),
}


def _jsonify(obj):
    """Make a report storable in a jsonb column.

    The finder queries return uuid, datetime and Decimal (from `round()`), none
    of which json.dumps handles — and the failure surfaces at the UPDATE, after
    the whole review has already been computed, so the work is lost at the last
    step. Converted once here rather than remembered at each SELECT.
    """
    import decimal
    if isinstance(obj, dict):
        return {str(k): _jsonify(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [_jsonify(v) for v in obj]
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, (uuid.UUID,)):
        return str(obj)
    if isinstance(obj, decimal.Decimal):
        return float(obj)
    return obj


# ── how the command was actually called ─────────────────────────────────────

def _parse_options(command):
    """Structured view of an invocation: subcommands, flags, values, target.

    `exit_code` alone says a run failed; it cannot say WHICH invocation failed,
    and the raw command string cannot be grouped or aggregated. Extracting the
    flag set makes "which options correlate with which return code" a question
    with an answer — nmap has 4 distinct exit codes across 27 command forms and
    379 runs, so that question was previously unanswerable.

    Shell-aware only as far as it needs to be: a pipeline is reduced to the
    segment that actually runs the tool, because `printf ... | ftp -n host` is
    an ftp invocation, not a printf one.
    """
    import shlex
    raw = (command or "").strip()
    if not raw:
        return {"argv0": None, "subcommands": [], "flags": {}, "flag_names": [],
                "positional": [], "pipeline": False, "parse_ok": False}

    pipeline = bool(re.search(r"[|;]|&&", raw))
    segment = raw
    if pipeline:
        parts = [s.strip() for s in re.split(r"\||;|&&", raw) if s.strip()]
        # Prefer the segment naming a real binary over the one feeding it input.
        segment = next((s for s in parts
                        if not re.match(r"^(printf|echo|cat|yes)\b", s)), parts[-1])
    try:
        tokens = shlex.split(segment)
        parse_ok = True
    except ValueError:
        # Unbalanced quotes: fall back to whitespace so a weird command still
        # yields something, flagged so nobody treats it as exact.
        tokens = segment.split()
        parse_ok = False
    if not tokens:
        return {"argv0": None, "subcommands": [], "flags": {}, "flag_names": [],
                "positional": [], "pipeline": pipeline, "parse_ok": parse_ok}

    argv0, rest = tokens[0], tokens[1:]
    subcommands, flags, positional = [], {}, []
    seen_flag = False
    i = 0
    while i < len(rest):
        tok = rest[i]
        if tok.startswith("-") and tok != "-":
            seen_flag = True
            if "=" in tok:
                name, val = tok.split("=", 1)
                flags[name] = val
            else:
                nxt = rest[i + 1] if i + 1 < len(rest) else None
                if nxt is not None and not nxt.startswith("-"):
                    flags[tok] = nxt
                    i += 1
                else:
                    flags[tok] = True     # a bare switch
            seen_flag = True
        elif not seen_flag:
            # Leading bare words are subcommands (`gobuster dir`, `crackmapexec smb`)
            subcommands.append(tok)
        else:
            positional.append(tok)
        i += 1

    return {"argv0": argv0, "subcommands": subcommands, "flags": flags,
            "flag_names": sorted(flags), "positional": positional,
            "pipeline": pipeline, "parse_ok": parse_ok}


def option_signature(command):
    """A groupable key for an invocation form: subcommands + flag NAMES.

    Values are deliberately excluded — `-p 80` and `-p 443` are the same
    invocation form aimed at different things, and folding them together is
    what lets 379 nmap runs collapse into a handful of comparable forms.
    """
    o = _parse_options(command)
    parts = list(o["subcommands"]) + o["flag_names"]
    return " ".join(parts) if parts else "(no options)"


def _catalogue_commands(path=CATALOGUE):
    """{tool: [command, ...]} from knowledge/service_tools.yaml.

    Same adjacency parse as `scripts/check_tool_commands.py::extract_commands`
    (a `command:` belongs to the nearest preceding `- name:`), duplicated only
    because that script is not on this container's path.
    CLAUDE.md requires duplicated logic to be pinned: the agreement test is
    tests/test_post_review.py::test_catalogue_parse_agrees_with_command_checker.
    """
    out, name = {}, None
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                m = re.match(r"\s*-\s+name:\s*(\S+)", line)
                if m:
                    name = m.group(1).strip().strip("\"'")
                    continue
                m = re.match(r'\s*command:\s*"(.+)"\s*$', line)
                if m and name:
                    out.setdefault(name, []).append(m.group(1))
    except OSError:
        return {}
    return out


_PLACEHOLDER_TOKEN = re.compile(r"\{([a-z_]+)\}", re.I)


def _fill_command(template, row):
    """Substitute a catalogue template from the execution row.

    Returns (command, missing). A catalogue command is a TEMPLATE — proposing
    `dig @{target} -p {port} ANY {domain}` verbatim would dispatch the braces
    literally, which is the very defect that produced 57 placeholder_target
    rows. So anything still unfilled is reported as `missing` and the proposal
    is withheld rather than shipped broken.

    `{domain}` is the honest hard case: a DNS enumeration against a bare IP has
    no domain to enumerate, so those are withheld by design, not by oversight.
    """
    target = (row.get("target") or "").strip()
    is_ip = bool(re.fullmatch(r"[0-9.]+|[0-9a-f:]+", target))
    port = row.get("port")
    values = {
        "target": target or None,
        "host": target or None,
        "ip": target if is_ip else None,
        "port": str(port) if port else None,
        "domain": None if (is_ip or not target) else target,
        "service": (row.get("service") or "").strip() or None,
        "url": (f"http://{target}:{port}" if target and port
                else (f"http://{target}" if target else None)),
    }
    missing = []

    def sub(m):
        key = m.group(1).lower()
        val = values.get(key)
        if not val:
            missing.append(key)
            return m.group(0)
        return val

    return _PLACEHOLDER_TOKEN.sub(sub, template or ""), sorted(set(missing))


def _pick_catalogue_command(candidates, row):
    """The catalogue command for the ROW's service, not merely its tool.

    `candidates[0]` was used here, and the catalogue lists hydra once per
    service. So a VNC hydra timeout was re-proposed with the SSH template —
    `ssh://192.168.1.150:5900` — pointing an SSH attack at the VNC port. It
    looked right because the tool name matched.

    Matching is on evidence in the row: the protocol the original command used,
    then the row's `service`. If nothing matches, return None and keep the
    historical command rather than guessing which service was meant.
    """
    if not candidates:
        return None
    if len(candidates) == 1:
        return candidates[0]

    old_cmd = (row.get("command") or "").lower()
    service = (row.get("service") or "").strip().lower()
    port = row.get("port")

    # The scheme the failing command itself used is the strongest signal, then
    # medusa/ncrack's `-M <module>` form, which carries the same information
    # without a URL — missing it left the medusa proposal falling back to its
    # historical command, which still named rockyou.
    scheme = re.search(r"\b([a-z0-9-]+)://", old_cmd)
    # old_cmd is already lowercased, so the flag must be matched lowercase too:
    # searching for "-M" in a lowercased string never matches, which is why the
    # medusa proposal fell through to the verbatim-command net.
    module = re.search(r"-m\s+([a-z0-9-]+)", old_cmd)
    tokens = [t for t in (scheme.group(1) if scheme else None,
                          module.group(1) if module else None,
                          service) if t]

    for token in tokens:
        for cand in candidates:
            low = cand.lower()
            if f"{token}://" in low or f"-m {token}" in low or f" {token} " in low:
                return cand
    # A port in the candidate is weaker but still evidence, not a guess.
    if port:
        for cand in candidates:
            if f":{port}" in cand:
                return cand
    return None


def _cause_is_fixed(tool, command, catalogue):
    """True when the catalogue no longer emits the command that failed.

    This is what separates "still broken" from "already fixed, just never
    re-run" — and it is the difference between a bug report and a re-run queue.
    gobuster's missing wordlist and dnsrecon's hardcoded example.com are both
    repaired in the catalogue while 39 rows still record the old failure.
    """
    current = catalogue.get(tool)
    if not current:
        return False
    return command not in current


def classify_execution(row, catalogue=None):
    """Classify one `tool_executions` row. Pure — no database, no I/O.

    `row` needs: tool, command, status, exit_code, output, error.
    Returns category, remedy, evidence, actionable and cause_fixed.
    """
    catalogue = catalogue if catalogue is not None else {}
    tool = (row.get("tool") or "").strip()
    command = row.get("command") or ""
    status = (row.get("status") or "").strip().lower()
    output = row.get("output") or ""
    error = row.get("error") or ""
    haystack = f"{error}\n{output}"

    category, evidence = None, ""

    # Order is load-bearing, and each step is here because a later one would
    # have mislabelled it: an interrupted nmap often carries partial output, a
    # crashed nmap exits non-zero like a refusal, and a dig against
    # example.com succeeds from the tool's point of view.
    exit_code = row.get("exit_code")
    target = (row.get("target") or "").strip()
    ph = _PLACEHOLDER.search(command)

    if _INTERRUPTED.search(error):
        category = "interrupted"
        evidence = error.strip()[:200]
    elif ph and ph.group(0).lower() not in target.lower():
        category = "placeholder_target"
        evidence = (f"command names {ph.group(0)!r} while the target is "
                    f"{target or '(unset)'!r}")
    elif status == "timeout":
        # Checked BEFORE the crash heuristic on purpose. The deadline killer
        # uses SIGKILL, so every timeout also exits 137 and would otherwise be
        # reported as a crash — losing the one fact the runner actually knew.
        category = "timed_out"
        evidence = f"killed at the deadline; {len(output)} bytes captured"
    elif exit_code in _CRASH_EXITS or (exit_code is not None and exit_code < 0) \
            or _CRASH_TEXT.search(haystack):
        m = _CRASH_TEXT.search(haystack)
        category = "crashed"
        evidence = (f"exit={exit_code}"
                    + (f": {m.group(0).strip()[:80]}" if m else " (killed by signal)"))
    else:
        for pattern, label in _BROKEN:
            m = pattern.search(haystack)
            if m:
                category, evidence = "broken_invocation", f"{label}: {m.group(0)}"
                break
        if category is None and status == "failed" \
                and len(output.strip()) >= _SUBSTANTIVE_OUTPUT_BYTES:
            category = "output_despite_failure"
            evidence = (f"exit={exit_code} but {row.get('output_bytes') or len(output)}"
                        f" bytes of output — the result was produced, then dropped")

    if category is None and not output.strip():
        needs = NEEDS_COMMANDS.get(tool)
        if needs and not any(tok in command for tok in needs):
            category = "silent_no_op"
            evidence = (f"{tool} needs one of {', '.join(needs)} to do anything; "
                        f"command has none")
        elif status == "failed":
            category = "failed_other"
            evidence = (error.strip()[:200] or
                        f"failed with exit_code={row.get('exit_code')} and no error text")
        else:
            category = "empty_result"
            evidence = "ran, exited cleanly, produced nothing"
    elif category is None:
        category = "produced_output" if status != "failed" else "failed_other"
        evidence = (error.strip()[:200] if category == "failed_other"
                    else f"{len(output)} bytes")

    meta = CATEGORIES[category]
    # Two different questions, previously conflated:
    #
    #  superseded — the catalogue no longer emits the command that ran. True for
    #    ANY category, and it decides which command a re-run should use. A hydra
    #    timeout whose recorded command still names rockyou must not be
    #    re-proposed verbatim: that reruns the 243,854,783-candidate invocation
    #    the catalogue has already replaced.
    #  cause_fixed — superseded AND the failure was an invocation defect, so the
    #    remedy changes from "fix the command" to "run it again".
    superseded = bool(catalogue) and _cause_is_fixed(tool, command, catalogue)
    fixed = superseded and category in ("broken_invocation", "silent_no_op",
                                        "placeholder_target")
    return {
        "category": category,
        # A repaired catalogue turns "fix the command" into "run it again".
        "remedy": "rerun" if fixed else meta["remedy"],
        "actionable": meta["actionable"],
        "why": meta["why"],
        "evidence": evidence,
        "cause_fixed": fixed,
        "command_superseded": superseded,
    }


# ── database passes ─────────────────────────────────────────────────────────

DB_DSN = os.environ.get("DB_DSN", "postgresql://app:app@rag-postgres:5432/scans")


def _get_conn():
    import psycopg2
    return psycopg2.connect(DB_DSN)


def review_executions(cur, since_days=None, target=None, catalogue=None):
    """Classify every execution and group by category, then by tool.

    An `example` is carried on every group because a count with no evidence
    cannot be acted on — the operator needs to see the command that failed.
    """
    catalogue = _catalogue_commands() if catalogue is None else catalogue
    where, params = ["1=1"], []
    if since_days:
        where.append("started_at > now() - (%s || ' days')::interval")
        params.append(int(since_days))
    if target:
        where.append("target = %s")
        params.append(target)
    # FULL output, not a prefix. The crackmapexec share table begins ~1 KB in,
    # so a 400-byte read reported "no results" on output that named five shares.
    # 2.2 MB across the whole table, largest row 165 KB — affordable.
    cur.execute(f"""
        SELECT id, tool, command, target, port, service, status, exit_code,
               COALESCE(output, '')            AS output,
               COALESCE(error, '')             AS error,
               octet_length(COALESCE(output, '')) AS output_bytes,
               started_at
        FROM tool_executions
        WHERE {' AND '.join(where)}
        ORDER BY started_at DESC
    """, params)

    from output_analysis import analyse_output

    groups, reviewed, notable_index = {}, 0, {}
    for row in cur.fetchall():
        r = dict(row)
        verdict = classify_execution(r, catalogue)
        analysis = analyse_output(r["tool"], r["output"], r.get("exit_code"))
        reviewed += 1
        # Security facts sitting in output. Indexed by (id, tool, target) so the
        # report can answer "what did we already see and never store".
        for n in analysis["notable"]:
            key = (n["id"], r["tool"], r.get("target") or "")
            slot = notable_index.setdefault(key, {
                "id": n["id"], "tool": r["tool"], "target": r.get("target"),
                "severity": n["severity"], "title": n["title"],
                "detail": n.get("detail"), "evidence": n.get("evidence"),
                "seen_in": 0, "execution_ids": []})
            slot["seen_in"] += 1
            if len(slot["execution_ids"]) < 5:
                slot["execution_ids"].append(str(r["id"]))
        g = groups.setdefault(verdict["category"], {
            "category": verdict["category"],
            "remedy": verdict["remedy"],
            "actionable": verdict["actionable"],
            "why": verdict["why"],
            "count": 0, "cause_fixed": 0, "tools": {}, "examples": [],
            "exit_codes": {}, "output_verdicts": {}, "invocations": {},
        })
        g["count"] += 1
        if verdict["cause_fixed"]:
            g["cause_fixed"] += 1
        # The return code as its own dimension: "failed" is not one thing, and
        # nmap alone spans four exit codes across 27 command forms.
        ec = "null" if r.get("exit_code") is None else str(r["exit_code"])
        g["exit_codes"][ec] = g["exit_codes"].get(ec, 0) + 1
        g["output_verdicts"][analysis["verdict"]] = \
            g["output_verdicts"].get(analysis["verdict"], 0) + 1
        sig = f"{r['tool']} {option_signature(r['command'])}"
        inv = g["invocations"].setdefault(sig, {"signature": sig, "count": 0,
                                               "exit_codes": {}})
        inv["count"] += 1
        inv["exit_codes"][ec] = inv["exit_codes"].get(ec, 0) + 1
        t = g["tools"].setdefault(r["tool"], {"count": 0, "targets": set()})
        t["count"] += 1
        if r.get("target"):
            t["targets"].add(r["target"])
        if len(g["examples"]) < 3:
            opts = _parse_options(r["command"])
            g["examples"].append({
                # Full output is served per-execution by
                # GET /agent/post-review/executions/{id} rather than embedded —
                # 1,348 full outputs would be a 2.2 MB report row.
                "execution_id": str(r["id"]), "tool": r["tool"],
                "target": r.get("target"), "command": r["command"],
                "exit_code": r.get("exit_code"),
                "options": {"subcommands": opts["subcommands"],
                            "flags": {k: (True if v is True else str(v))
                                      for k, v in opts["flags"].items()},
                            "signature": option_signature(r["command"])},
                "evidence": verdict["evidence"],
                "output_verdict": analysis["verdict"],
                "output_bytes": r.get("output_bytes"),
                "notable_count": analysis["notable_count"],
                "cause_fixed": verdict["cause_fixed"],
                "started_at": r["started_at"].isoformat() if r.get("started_at") else None,
            })

    for g in groups.values():
        g["invocations"] = sorted(g["invocations"].values(),
                                  key=lambda i: -i["count"])[:12]
        g["tools"] = [
            {"tool": k, "count": v["count"], "targets": sorted(v["targets"])[:10]}
            for k, v in sorted(g["tools"].items(), key=lambda kv: -kv[1]["count"])
        ]
    ordered = sorted(groups.values(),
                     key=lambda g: (not g["actionable"], -g["count"]))
    # etl/severity.py is THE scale — a hand-written order here would be the
    # twelfth copy, and tests/test_severity_scale.py exists because the last
    # eleven disagreed with each other.
    from etl.severity import severity_rank

    # Whether each fact has actually LANDED. Without this the summary reported
    # "5 high or worse unstored" after they had all been ingested, because the
    # count was derived from output alone and never asked the database. A metric
    # named "unstored" that cannot tell is worse than no metric.
    for n in notable_index.values():
        cur.execute("""
            SELECT 1 FROM recon_findings
             WHERE lower(source) = lower(%s) AND finding_type = %s
               AND target = %s LIMIT 1
        """, (n["tool"], n["id"], n.get("target") or ""))
        n["stored"] = cur.fetchone() is not None

    notable = sorted(notable_index.values(),
                     key=lambda n: (n["stored"], -severity_rank(n["severity"]),
                                    -n["seen_in"]))
    return {"executions_reviewed": reviewed, "groups": ordered,
            "notable_in_output": notable}


def find_unparsed_output(cur, limit=50):
    """Executions that captured output which never became an artifact.

    The tool ran, said something, and nothing downstream read it — so the
    result exists only inside a text column no report queries. Distinct from an
    empty result: there IS data here, it just never landed.

    Floored at _SUBSTANTIVE_OUTPUT_BYTES. Without it, ntpq's 13 runs reported as
    lost data on a combined 13 bytes — one newline each, which is nothing to
    ingest and would have been a false positive at the top of the report.
    """
    cur.execute("""
        SELECT te.tool, count(*) AS runs,
               sum(octet_length(te.output)) AS bytes,
               min(te.target) AS example_target
        FROM tool_executions te
        WHERE octet_length(COALESCE(te.output, '')) >= %s
          AND te.status = 'completed'
          AND NOT EXISTS (SELECT 1 FROM raw_artifacts ra
                          WHERE ra.tool = te.tool AND ra.target = te.target)
        GROUP BY te.tool
        ORDER BY 2 DESC
        LIMIT %s
    """, (_SUBSTANTIVE_OUTPUT_BYTES, limit))
    rows = [dict(r) for r in cur.fetchall()]
    for r in rows:
        r["bytes"] = int(r["bytes"] or 0)
    return rows


def find_results_not_ingested(cur, limit=100):
    """Output that HAS results, where nothing attributable to that tool landed.

    This is the check the earlier `find_unparsed_output` could not make. That
    one asked "is there a raw_artifact"; this asks "did the findings reach a
    table anybody queries", which is the question that matters.

    Attribution uses the columns that actually record a tool:
    `web_findings.source`, `vulns.script` (stored as `tool:rule`),
    `credential_findings.source` and `recon_findings.source`.

    Three states, not two, because the interesting one sits in the middle:

      interpreted            a findings row with a REAL type and severity
      captured_uninterpreted the text is in the database, but only inside a
                             generic `tool_output` / `tool_table_row` dump with
                             `key_values` empty — nothing says what it means, so
                             it cannot be filtered, sorted or triaged
      absent                 no row references it at all

    Two earlier versions of this check were wrong in opposite directions. The
    first counted a `raw_artifacts` blob as success and reported zero gaps. The
    second used tool-level attribution — "does ANY row have source='crackmapexec'"
    — which marked all 51 crackmapexec runs as landed on the strength of 10
    generic dumps. Both hid the motivating case.

    The real number: **94.2% of recon_findings (98 of 104) are generic dumps**,
    from 17 tools. The stack captures text and calls it a finding.

    The motivating case: one crackmapexec run disclosed SMBv1 enabled, signing
    disabled, an accepted null session, five shares (one WRITABLE), the hostname
    and the Samba version. Zero rows were stored for any of it.
    """
    from output_analysis import analyse_output
    cur.execute("""
        SELECT te.id, te.tool, te.target, te.port, te.exit_code, te.command,
               COALESCE(te.output, '') AS output,
               octet_length(COALESCE(te.output, '')) AS output_bytes,
               EXISTS (SELECT 1 FROM web_findings wf
                        WHERE lower(wf.source) = lower(te.tool)) AS in_web,
               EXISTS (SELECT 1 FROM vulns v
                        WHERE v.script ILIKE te.tool || '%') AS in_vulns,
               EXISTS (SELECT 1 FROM credential_findings cf
                        WHERE lower(cf.source) = lower(te.tool)
                          AND host(cf.ip) = te.target) AS in_creds,
               -- INTERPRETED only: a generic dump is not an interpretation.
               EXISTS (SELECT 1 FROM recon_findings rf
                        WHERE lower(rf.source) = lower(te.tool)
                          AND rf.target = te.target
                          AND rf.finding_type NOT IN
                              ('tool_output', 'tool_table_row', 'tool_finding')) AS in_recon,
               EXISTS (SELECT 1 FROM recon_findings rf2
                        WHERE lower(rf2.source) = lower(te.tool)
                          AND rf2.target = te.target
                          AND rf2.finding_type IN
                              ('tool_output', 'tool_table_row', 'tool_finding')) AS dumped,
               EXISTS (SELECT 1 FROM raw_artifacts ra
                        WHERE ra.tool = te.tool
                          AND COALESCE(ra.target, '') = COALESCE(te.target, '')) AS raw_stored
        FROM tool_executions te
        WHERE octet_length(COALESCE(te.output, '')) > 0
        ORDER BY octet_length(COALESCE(te.output, '')) DESC
    """)
    gaps = []
    for row in cur.fetchall():
        r = dict(row)
        a = analyse_output(r["tool"], r["output"], r.get("exit_code"))
        if a["verdict"] != "results_found":
            continue
        # A findings row with real meaning. A generic dump does not count.
        if any((r["in_web"], r["in_vulns"], r["in_creds"], r["in_recon"])):
            continue
        state = "captured_uninterpreted" if (r["dumped"] or r["raw_stored"]) \
            else "absent"
        gaps.append({
            "execution_id": str(r["id"]), "tool": r["tool"],
            "target": r.get("target"), "port": r.get("port"),
            "exit_code": r.get("exit_code"),
            "options": option_signature(r["command"]),
            "output_bytes": r["output_bytes"],
            "state": state,
            "raw_artifact_stored": r["raw_stored"],
            "generic_dump_stored": r["dumped"],
            "indicators": a["indicators"],
            "notable_count": a["notable_count"],
            "notable": [{"id": n["id"], "severity": n["severity"],
                         "title": n["title"]} for n in a["notable"]],
        })
        if len(gaps) >= limit:
            break
    from etl.severity import severity_rank
    gaps.sort(key=lambda g: (
        -max([severity_rank(n["severity"]) for n in g["notable"]] or [0]),
        -g["notable_count"], -g["output_bytes"]))
    return gaps


def find_stuck_recommendations(cur, stale_hours=6):
    """Recommendations claimed as dispatched that produced no execution.

    `queued` means "handed to the runner". A queued row with no matching
    execution after hours means the hand-off was lost — the operator sees
    "dispatched" and no result, and there is nothing to explain the gap.
    """
    cur.execute("""
        SELECT sr.id, sr.scanner, host(sr.ip) AS target, sr.script, sr.status,
               sr.created_at,
               round(extract(epoch FROM now() - sr.created_at) / 3600.0, 1) AS age_hours
        FROM scan_recommendations sr
        WHERE sr.status IN ('queued', 'completed')
          AND sr.created_at < now() - (%s || ' hours')::interval
          AND NOT EXISTS (
              SELECT 1 FROM tool_executions te
              WHERE te.tool = sr.scanner AND te.target = host(sr.ip))
        ORDER BY sr.created_at
    """, (int(stale_hours),))
    return [dict(r) for r in cur.fetchall()]


# ── proposals ───────────────────────────────────────────────────────────────

# Categories whose remedy is simply "run it again". `broken_invocation` and
# `silent_no_op` qualify ONLY when the catalogue no longer emits the command
# that failed (cause_fixed) — re-running a command that is still wrong just
# reproduces the failure.
_RERUN_REMEDIES = ("rerun", "rerun_scoped")

# Tools whose re-run must never reuse the historical command.
_BRUTE_TOOLS = {"hydra", "medusa", "ncrack", "crowbar",
                "patator", "brutus"}


def propose_reruns(cur, catalogue=None, limit=100, dry_run=True,
                   engagement_id=None):
    """Queue one pending recommendation per (tool, target) worth re-running.

    This function does not dispatch: rows land `status='pending'`,
    `source='post_review'`.

    But "pending" is NOT inert in this stack, and assuming it was is an error
    worth recording. `dashboard/bff/services/recon_agent.py:117` selects
    `WHERE sr.status = 'pending'` with **no filter on `source`**, so the recon
    agent picks these up and dispatches them like any other in-scope
    recommendation. One gobuster proposal was dispatched 29 minutes after being
    queued — and recorded `completed` with NO row in `tool_executions`, because
    the auto-execute path is fire-and-forget and never collects its output.

    Whether that is correct is an operator decision, not a code default: these
    targets did pass the scope gate and the scans had already been authorised
    and attempted once. There is currently NO flag to hold them for approval.

    Every proposal still goes through the scope gate: a proposal naming an
    out-of-scope host is an authorization defect whether or not it executes,
    and the refusal is RECORDED rather than dropped so a wrongly-scoped target
    is visible instead of quietly missing.

    The unique index on the generated `fingerprint` makes this idempotent —
    running the review twice updates the same rows instead of stacking copies.
    """
    catalogue = _catalogue_commands() if catalogue is None else catalogue

    try:
        import sys
        if "/app" not in sys.path:
            sys.path.insert(0, "/app")
        from etl.scope_gate import check_dispatch, load_dispatch_scope
        # Returns (rows, source) — binding only `rows` here would make every
        # scope check iterate the pair instead of the targets.
        scope_rows, scope_source = load_dispatch_scope(cur, engagement_id)
        if scope_source == "unavailable":
            return {"proposed": 0, "inserted": 0, "refused": 0, "proposals": [],
                    "refusals": [], "dry_run": dry_run,
                    "error": "scope could not be loaded — refusing to propose"}
    except Exception as exc:            # noqa: BLE001 - gate must fail closed
        return {"proposed": 0, "refused": 0, "proposals": [], "refusals": [],
                "error": f"scope gate unavailable, refusing to propose: {exc}"}

    cur.execute("""
        SELECT DISTINCT ON (tool, target, command)
               id, tool, command, target, port, service, status, exit_code,
               left(COALESCE(output, ''), 400) AS output,
               COALESCE(error, '') AS error, started_at
        FROM tool_executions
        WHERE status IN ('failed', 'timeout')
           OR (status = 'completed' AND COALESCE(output, '') = '')
        ORDER BY tool, target, command, started_at DESC
    """)
    candidates = [dict(r) for r in cur.fetchall()]

    proposals, refusals, needs_input, seen = [], [], [], set()
    for row in candidates:
        if len(proposals) >= limit:
            break
        verdict = classify_execution(row, catalogue)
        if verdict["remedy"] not in _RERUN_REMEDIES:
            continue
        target = row.get("target") or ""
        # The command it should run now is the CURRENT catalogue form where one
        # exists — re-proposing the historical command would re-run the bug.
        current = catalogue.get(row["tool"]) or []
        missing = []
        chosen = _pick_catalogue_command(current, row) \
            if verdict.get("command_superseded") else None
        if chosen:
            # Whatever went wrong, run what we would run TODAY — for THIS service.
            script, missing = _fill_command(chosen, row)
        elif row["tool"] in _BRUTE_TOOLS and verdict.get("command_superseded"):
            # Never re-propose a credential attack verbatim. The historical
            # command is the one that ran rockyou for 15,875 hours; if no current
            # template can be matched to this service, that is a catalogue gap to
            # report, not a command to run again.
            needs_input.append({
                "tool": row["tool"], "target": target,
                "template": row["command"],
                "missing": ["catalogue_template_for_service"],
                "category": verdict["category"],
                "reason": ("the recorded command is superseded but no current "
                           "template matches this service — re-running it "
                           "verbatim would repeat the oversized attack")})
            continue
        else:
            script = row["command"]
        # {user_list}/{password_list} are filled from the database, not from the
        # execution row, so _fill_command cannot resolve them and would withhold
        # every brute-force proposal as "needs_input". Resolved here instead, and
        # the result carries the per-target lists: 35 discovered usernames plus
        # the service defaults, rather than the generic shortlist.
        try:
            import target_wordlists as _tw
            if _tw.needs_lists(script):
                resolved = _tw.resolve_command(
                    cur, script, target, port=row.get("port"),
                    service_hint=row.get("service") or "")
                script = resolved["command"]
                missing = [m for m in missing
                           if m not in ("user_list", "password_list")]
        except Exception:
            pass    # leave the placeholder; it is then withheld, never dispatched
        if missing:
            # Withheld, not dropped: an unfillable placeholder is reported so
            # "why was this never re-run" has an answer.
            needs_input.append({"tool": row["tool"], "target": target,
                                "template": current[0], "missing": missing,
                                "category": verdict["category"]})
            continue
        # A proposal that cannot possibly succeed is not worth an operator's
        # click. hydra cannot negotiate SSH with a server offering only legacy
        # MACs, so those proposals are withheld with the reason rather than
        # queued to fail.
        try:
            import scan_parameters as _sp
            futile = _sp.ssh_brute_force_viable(cur, target, row["tool"],
                                                script or "")
        except Exception:
            futile = None
        if futile:
            needs_input.append({
                "tool": row["tool"], "target": target, "template": script,
                "missing": ["compatible_ssh_mac"],
                "category": verdict["category"], "reason": futile})
            continue
        refusal = check_dispatch(target, scope_rows, command=script or "")
        if refusal:
            refusals.append({"tool": row["tool"], "target": target,
                             "reason": refusal})
            continue
        action = (f"Re-run {row['tool']}: "
                  f"{verdict['category'].replace('_', ' ')}")
        # Distinct historical commands can substitute down to the same current
        # one (two ftp variants both become the same printf form), so dedupe on
        # the key the generated `fingerprint` column actually uses. Without
        # this the count overstates the work while the DB correctly stores one.
        key = (row["tool"], target, script, action)
        if key in seen:
            continue
        seen.add(key)
        proposals.append({
            "tool": row["tool"], "target": target, "port": row.get("port"),
            "service": row.get("service"), "action": action, "script": script,
            "category": verdict["category"], "remedy": verdict["remedy"],
            "evidence": verdict["evidence"], "cause_fixed": verdict["cause_fixed"],
            "prior_execution_id": str(row["id"]),
        })

    inserted = 0
    if not dry_run and proposals:
        from psycopg2.extras import Json
        for p in proposals:
            cur.execute("""
                INSERT INTO scan_recommendations
                    (ip, service, scanner, action, script, source, priority,
                     status, engagement_id, extra)
                VALUES (%s,%s,%s,%s,%s,'post_review',%s,'pending',%s,%s)
                ON CONFLICT (fingerprint) DO UPDATE
                   SET updated_at = now(),
                       extra = scan_recommendations.extra || EXCLUDED.extra
                RETURNING (xmax = 0) AS inserted
            """, (p["target"] or None, p["service"], p["tool"], p["action"],
                  p["script"], 60, engagement_id,
                  Json({"post_review_category": p["category"],
                        "remedy": p["remedy"], "evidence": p["evidence"],
                        "cause_fixed": p["cause_fixed"],
                        "prior_execution_id": p["prior_execution_id"],
                        "queued_by": "post_review_agent"})))
            # The caller's cursor may be a RealDictCursor, where this row is
            # {'inserted': True} and a [0] index raises KeyError(0) — which
            # surfaced as the useless message "post review failed: 0". Only the
            # non-dry-run leg reaches here, so a dry run never showed it.
            got = cur.fetchone()
            if got is not None:
                was_new = got["inserted"] if isinstance(got, dict) else got[0]
                if was_new:
                    inserted += 1

    return {"proposed": len(proposals), "inserted": inserted,
            "refused": len(refusals), "dry_run": dry_run,
            "scope_source": scope_source, "needs_input": len(needs_input),
            "proposals": proposals[:limit], "refusals": refusals[:20],
            "needs_input_detail": needs_input[:20]}


# ── orchestration ───────────────────────────────────────────────────────────

def run_post_review(triggered_by="manual", since_days=None, target=None,
                    queue_reruns=False, engagement_id=None, conn=None):
    """Review executed work, store a report, and optionally queue the re-runs.

    Returns the report. Storage is best-effort in the sense that the review
    itself is the deliverable, but a failure to store is REPORTED rather than
    swallowed — a review nobody can read later is not a review.
    """
    from psycopg2.extras import Json, RealDictCursor
    owned = conn is None
    conn = conn or _get_conn()
    catalogue = _catalogue_commands()
    report_id = None
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                INSERT INTO post_review_reports (engagement_id, status, triggered_by)
                VALUES (%s, 'running', %s) RETURNING id
            """, (engagement_id, triggered_by))
            report_id = cur.fetchone()["id"]
            conn.commit()

            executions = review_executions(cur, since_days=since_days,
                                           target=target, catalogue=catalogue)
            unparsed = find_unparsed_output(cur)
            not_ingested = find_results_not_ingested(cur)
            stuck = find_stuck_recommendations(cur)
            reruns = propose_reruns(cur, catalogue=catalogue,
                                   dry_run=not queue_reruns,
                                   engagement_id=engagement_id)

            actionable = sum(g["count"] for g in executions["groups"]
                             if g["actionable"])
            report = {
                "catalogue_tools": len(catalogue),
                "executions": executions,
                "unparsed_output": unparsed,
                "results_not_ingested": not_ingested,
                "notable_in_output": executions.get("notable_in_output", []),
                "stuck_recommendations": stuck,
                "reruns": reruns,
                "summary": {
                    "executions_reviewed": executions["executions_reviewed"],
                    "actionable": actionable,
                    "correct_but_empty": sum(
                        g["count"] for g in executions["groups"]
                        if g["category"] == "empty_result"),
                    "unparsed_tools": len(unparsed),
                    "results_not_ingested": len(not_ingested),
                    "notable_facts_in_output": len(
                        executions.get("notable_in_output", [])),
                    "notable_facts_stored": sum(
                        1 for n in executions.get("notable_in_output", [])
                        if n.get("stored")),
                    "notable_facts_unstored": sum(
                        1 for n in executions.get("notable_in_output", [])
                        if not n.get("stored")),
                    "high_or_worse_unstored": sum(
                        1 for n in executions.get("notable_in_output", [])
                        if n["severity"] in ("critical", "high")
                        and not n.get("stored")),
                    "stuck_recommendations": len(stuck),
                    "reruns_proposed": reruns.get("proposed", 0),
                    "reruns_queued": reruns.get("inserted", 0),
                    "scope_refusals": reruns.get("refused", 0),
                },
            }
            report = _jsonify(report)
            cur.execute("""
                UPDATE post_review_reports
                   SET status='completed', report=%s, executions_reviewed=%s,
                       issues_found=%s, reruns_queued=%s, completed_at=now()
                 WHERE id=%s
            """, (Json(report), executions["executions_reviewed"],
                  actionable + len(unparsed) + len(stuck) + len(not_ingested),
                  reruns.get("inserted", 0), report_id))
            conn.commit()

        report["report_id"] = str(report_id)
        try:
            from webhooks import emit_webhook
            emit_webhook("post_review_completed", "post_review_agent", {
                "report_id": str(report_id), "engagement_id": engagement_id,
                **report["summary"],
            })
        except Exception:
            pass  # never fail a review because the webhook fan-out did
        return report
    except Exception as exc:            # noqa: BLE001
        try:
            conn.rollback()
            if report_id:
                with conn.cursor() as cur:
                    cur.execute("UPDATE post_review_reports SET status='failed', "
                                "report=%s, completed_at=now() WHERE id=%s",
                                (json.dumps({"error": str(exc)}), report_id))
                conn.commit()
        except Exception:
            pass
        raise
    finally:
        if owned:
            try:
                conn.close()
            except Exception:
                pass


# ── ingest: turn extracted facts into findings anybody can query ────────────

def ingest_extracted_facts(cur, dry_run=True, limit=4000, target=None):
    """Write extracted facts to `recon_findings` with a REAL finding_type.

    This is the `ingest` remedy. Until now extraction and storage were never
    joined: 100 executions were `captured_uninterpreted` — the text was in the
    database, but only inside generic `tool_output` / `tool_table_row` rows with
    `key_values` EMPTY, which is 94.2% of that table. Nothing said "SMBv1 is
    enabled", so nothing could filter, sort or triage it.

    Each fact becomes one row whose `finding_type` IS the fact id
    (`smb_null_session`, `e4l_users_enumerated`, ...) and whose severity is the
    one the extractor assigned.

    THE PAYLOAD MUST BE STABLE. `trg_recon_findings_dedup` fingerprints
    md5('recon|'||source||'|'||finding_type||'|'||target||'|'||data::text), so
    anything volatile in `data` forks the fingerprint on every run and the unique
    index stores both copies. That is why execution ids and per-run counts are
    NOT in the payload, and why it is serialised with sort_keys.

    The trigger is BEFORE INSERT and RETURNs NULL on a duplicate, so an INSERT
    reports zero rows and `ON CONFLICT` would be unreachable. Novelty is
    therefore checked BEFORE inserting, on the natural key.

    Usernames are deliberately NOT written to `credential_vault`. Its
    `credential_type` has no username-only value and `status` no "unverified",
    so 35 bare names would have to be stored as an `active` credential of type
    `other` — which is not what they are, and pollutes the credentials view. The
    names already reach the generated wordlists through
    `target_wordlists.harvest_usernames`, so nothing is lost by leaving them out.
    """
    from output_analysis import analyse_output
    from psycopg2.extras import Json

    where, params = ["octet_length(COALESCE(output, '')) > 0"], []
    if target:
        where.append("target = %s")
        params.append(target)
    params.append(int(limit))
    cur.execute(f"""
        SELECT id, tool, target, port, exit_code, COALESCE(output, '') AS output
          FROM tool_executions
         WHERE {' AND '.join(where)}
         ORDER BY started_at DESC
         LIMIT %s
    """, params)
    rows = [dict(r) for r in cur.fetchall()]

    seen_keys, planned, skipped_no_target = {}, [], 0
    for r in rows:
        tgt = (r.get("target") or "").strip()
        if not tgt:
            # recon_findings.target identifies the finding; without it the row
            # cannot be attributed or deduped, so it is counted rather than
            # stored under a guessed host.
            skipped_no_target += 1
            continue
        analysis = analyse_output(r["tool"], r["output"], r.get("exit_code"))
        for fact in analysis["notable"]:
            key = (r["tool"].lower(), fact["id"], tgt)
            if key in seen_keys:
                continue
            seen_keys[key] = True
            planned.append({
                "source": r["tool"], "finding_type": fact["id"], "target": tgt,
                "severity": fact["severity"],
                "data": {
                    "fact_id": fact["id"], "title": fact["title"],
                    "detail": (fact.get("detail") or "").strip(),
                    "evidence": (fact.get("evidence") or "")[:400],
                    "tool": r["tool"],
                    # Declared parameters, stored machine-readable. These are
                    # testing INPUTS — a lockout window, a minimum length — that
                    # later decisions read directly rather than parsing out of a
                    # title. They are inside the fingerprinted payload on
                    # purpose: a changed policy IS a different fact and should
                    # surface as one rather than silently overwrite the old.
                    **({"params": fact["params"]} if fact.get("params") else {}),
                },
            })

    new, existing = [], []
    for p in planned:
        cur.execute("""
            SELECT 1 FROM recon_findings
             WHERE lower(source) = lower(%s) AND finding_type = %s AND target = %s
             LIMIT 1
        """, (p["source"], p["finding_type"], p["target"]))
        (existing if cur.fetchone() else new).append(p)

    inserted = 0
    if not dry_run:
        for p in new:
            cur.execute("""
                INSERT INTO recon_findings
                       (source, finding_type, target, data, severity)
                VALUES (%s, %s, %s, %s, %s)
            """, (p["source"], p["finding_type"], p["target"],
                  Json(p["data"], dumps=lambda o: json.dumps(o, sort_keys=True)),
                  p["severity"]))
            inserted += 1
        cur.connection.commit()

    from etl.severity import severity_rank
    by_sev = {}
    for p in planned:
        by_sev[p["severity"]] = by_sev.get(p["severity"], 0) + 1
    return {
        "executions_read": len(rows),
        "facts_found": len(planned),
        "new": len(new),
        "already_stored": len(existing),
        "inserted": inserted,
        "dry_run": dry_run,
        "skipped_no_target": skipped_no_target,
        "by_severity": dict(sorted(by_sev.items(),
                                   key=lambda kv: -severity_rank(kv[0]))),
        "sample": sorted(new, key=lambda p: -severity_rank(p["severity"]))[:12],
    }
