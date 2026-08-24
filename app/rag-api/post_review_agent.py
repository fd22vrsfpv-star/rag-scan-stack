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
        "why": "a non-zero exit that still produced real output; the result exists but was discarded",
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
    fixed = bool(catalogue) \
        and category in ("broken_invocation", "silent_no_op", "placeholder_target") \
        and _cause_is_fixed(tool, command, catalogue)
    return {
        "category": category,
        # A repaired catalogue turns "fix the command" into "run it again".
        "remedy": "rerun" if fixed else meta["remedy"],
        "actionable": meta["actionable"],
        "why": meta["why"],
        "evidence": evidence,
        "cause_fixed": fixed,
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
    cur.execute(f"""
        SELECT id, tool, command, target, port, status, exit_code,
               left(COALESCE(output, ''), 400) AS output,
               COALESCE(error, '')             AS error,
               octet_length(COALESCE(output, '')) AS output_bytes,
               started_at
        FROM tool_executions
        WHERE {' AND '.join(where)}
        ORDER BY started_at DESC
    """, params)

    groups, reviewed = {}, 0
    for row in cur.fetchall():
        r = dict(row)
        # classify_execution reads `output` for emptiness; the SELECT truncates
        # to 400 bytes, which cannot turn a non-empty output into an empty one.
        verdict = classify_execution(r, catalogue)
        reviewed += 1
        g = groups.setdefault(verdict["category"], {
            "category": verdict["category"],
            "remedy": verdict["remedy"],
            "actionable": verdict["actionable"],
            "why": verdict["why"],
            "count": 0, "cause_fixed": 0, "tools": {}, "examples": [],
        })
        g["count"] += 1
        if verdict["cause_fixed"]:
            g["cause_fixed"] += 1
        t = g["tools"].setdefault(r["tool"], {"count": 0, "targets": set()})
        t["count"] += 1
        if r.get("target"):
            t["targets"].add(r["target"])
        if len(g["examples"]) < 3:
            g["examples"].append({
                "execution_id": str(r["id"]), "tool": r["tool"],
                "target": r.get("target"), "command": r["command"],
                "evidence": verdict["evidence"],
                "cause_fixed": verdict["cause_fixed"],
                "started_at": r["started_at"].isoformat() if r.get("started_at") else None,
            })

    for g in groups.values():
        g["tools"] = [
            {"tool": k, "count": v["count"], "targets": sorted(v["targets"])[:10]}
            for k, v in sorted(g["tools"].items(), key=lambda kv: -kv[1]["count"])
        ]
    ordered = sorted(groups.values(),
                     key=lambda g: (not g["actionable"], -g["count"]))
    return {"executions_reviewed": reviewed, "groups": ordered}


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


def propose_reruns(cur, catalogue=None, limit=100, dry_run=True,
                   engagement_id=None):
    """Queue one pending recommendation per (tool, target) worth re-running.

    Deliberately NOT a dispatch. Rows land `status='pending'`,
    `source='post_review'`, and wait for a human to press Run.

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
        if verdict["cause_fixed"] and current:
            script, missing = _fill_command(current[0], row)
        else:
            script = row["command"]
        if missing:
            # Withheld, not dropped: an unfillable placeholder is reported so
            # "why was this never re-run" has an answer.
            needs_input.append({"tool": row["tool"], "target": target,
                                "template": current[0], "missing": missing,
                                "category": verdict["category"]})
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
                "stuck_recommendations": stuck,
                "reruns": reruns,
                "summary": {
                    "executions_reviewed": executions["executions_reviewed"],
                    "actionable": actionable,
                    "correct_but_empty": sum(
                        g["count"] for g in executions["groups"]
                        if g["category"] == "empty_result"),
                    "unparsed_tools": len(unparsed),
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
                  actionable + len(unparsed) + len(stuck),
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
