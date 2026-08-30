#!/usr/bin/env python3
"""Verify every tool command the recommender can emit — at RUNTIME, outside pytest.

WHY THIS EXISTS
---------------
A broken invocation and an empty result look identical in every report. Two real
cases motivated this:

  * gobuster failed 20 of 20 runs on `-w /usr/share/wordlists/dirb/common.txt`,
    a path that does not exist in the kali-listener image. It had never once run,
    and nothing said so — not pytest, not the container healthcheck, not any
    report, because "no output" reads as "found nothing".
  * dnsrecon ran 19 times against a hardcoded `example.com`, querying someone
    else's domain through the target's resolver.

pytest can check that a path exists and that no stand-in domain is hardcoded. It
cannot check that a tool ACCEPTS the flags in its command — that needs the tool,
in its own image, at runtime. This does that by substituting a dead loopback
target and classifying the failure:

    flag provided but not defined  -> the options are wrong
    ... does not exist             -> a path in the command is missing
    connection refused / timeout   -> options accepted, the call path works

No traffic goes anywhere real: the probe target is hardcoded loopback, and a
command with no {target} to redirect is reported unverifiable rather than run.

A VERDICT IS PER IMAGE, and that matters twice over:

  * `no_binary` is not automatically a defect. Several catalogue tools live in
    another service — httpx, katana, naabu and tlsx are in pd-runner, not
    kali-listener — so run this against each image that actually dispatches, and
    read `no_binary` as "not here" rather than "missing everywhere".
  * A tool NAME can resolve to the WRONG PROGRAM. kali-listener's `httpx` is
    /usr/bin/httpx, the Python HTTP client, while pd-runner has ProjectDiscovery's
    /usr/local/bin/httpx. The catalogue's httpx flags are ProjectDiscovery's, so
    dispatching one to kali-listener silently runs a different tool that rejects
    them — which is worse than a missing binary, because the name resolves and
    the failure looks like a flag problem.

Usage:
    scripts/check_tool_commands.py                      # everything
    scripts/check_tool_commands.py gobuster hydra       # only these tools
    scripts/check_tool_commands.py --markdown knowledge/playbooks/tool_invocations.md

Exit codes: 0 all good · 1 something is broken · 2 could not run the check.
"""
import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
YAML = os.path.join(REPO, "knowledge", "service_tools.yaml")

# Verdicts that mean "this command cannot work". `unverifiable` is NOT one:
# it means we declined to probe it safely, which is a gap in coverage rather
# than a defect, and it is reported separately so it stays visible either way.
BROKEN = ("bad_option", "missing_path", "no_binary", "interactive")

LABEL = {
    "ok": "options accepted, call path works",
    "bad_option": "the tool rejected its own arguments",
    "missing_path": "names a file absent from the image",
    "no_binary": "tool not installed here",
    "interactive": "no commands supplied — would exit 0 silently",
    "unverifiable": "not probed (see reason)",
}
MARK = {"ok": "OK", "unverifiable": "SKIP"}


def extract_commands(path, only=()):
    """(tool, command) pairs. A `command:` belongs to the nearest preceding
    `- name:` — that adjacency is the file's own structure, and parsing it this
    way avoids a yaml dependency the host may not have."""
    name, seen, out = None, set(), []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            m = re.match(r"\s*-\s+name:\s*(\S+)", line)
            if m:
                name = m.group(1).strip().strip("\"'")
                continue
            m = re.match(r'\s*command:\s*"(.+)"\s*$', line)
            if m and name:
                cmd = m.group(1)
                if only and name not in only:
                    continue
                if (name, cmd) in seen:
                    continue
                seen.add((name, cmd))
                out.append({"tool": name, "command": cmd})
    return out


def verify(container, commands, timeout, batch, capture_help):
    """POST batches to /tools/verify inside the container.

    The payload goes over STDIN (`--data-binary @-`), never as a shell argument:
    these commands contain quotes, pipes and backslashes, and every one of them
    would have to survive a shell round-trip otherwise.
    """
    results, helps = [], {}
    for i in range(0, len(commands), batch):
        chunk = commands[i:i + batch]
        payload = json.dumps({"timeout": timeout, "commands": chunk,
                              "capture_help": bool(capture_help)})
        proc = subprocess.run(
            ["docker", "exec", "-i", container, "curl", "-sk",
             "--max-time", str(timeout * len(chunk) + 90),
             "-X", "POST", "https://127.0.0.1:8019/tools/verify",
             "-H", "Content-Type: application/json", "--data-binary", "@-"],
            input=payload, capture_output=True, text=True)
        if proc.returncode != 0 or not proc.stdout.strip():
            raise RuntimeError(
                f"batch {i // batch} failed: "
                f"{(proc.stderr or 'empty response').strip()[-200:]}")
        try:
            body = json.loads(proc.stdout)
        except ValueError as e:
            raise RuntimeError(f"batch {i // batch} unparsable: {e}") from None
        results.extend(body.get("results", []))
        helps.update(body.get("help") or {})
        print(f"  ...{min(i + batch, len(commands))}/{len(commands)}",
              file=sys.stderr)
    return results, helps


def report(results):
    buckets = {}
    for r in results:
        buckets.setdefault(r["verdict"], []).append(r)
    for verdict in ("ok", "bad_option", "missing_path", "no_binary",
                    "interactive", "unverifiable"):
        rows = buckets.get(verdict, [])
        if not rows:
            continue
        mark = MARK.get(verdict, "BROKEN")
        print(f"[{mark}] {LABEL.get(verdict, verdict)}  ({len(rows)})")
        if verdict != "ok":
            for r in rows:
                print(f"    {r['tool']:<16} {(r.get('detail') or '')[:58]}")
                print(f"    {'':<16} {r['command'][:100]}")
        print()
    broken = [r for r in results if r["verdict"] in BROKEN]
    unver = len(buckets.get("unverifiable", []))
    print("=" * 62)
    print(f"  checked: {len(results)}   broken: {len(broken)}   "
          f"unverifiable: {unver}")
    print("=" * 62)
    return broken


def write_markdown(path, results, helps, container="kali-listener"):
    """Emit a RAG-ingestible playbook.

    Lands in knowledge/commands/, ingested by

        POST /playbooks/ingest {"playbook_dir": "/knowledge/commands"}

    which chunks markdown on `###` headings — so one section per tool retrieves
    as a unit and an answer about gobuster cannot be assembled out of hydra's
    evidence. The endpoint takes the directory as a parameter, which is why this
    can live outside knowledge/playbooks without a code change.

    Records what was OBSERVED, not what is assumed: the exact invocation, the
    verdict, and the tool's own output. A reader (or a model) asking "how do I
    invoke gobuster here" gets the form that was actually accepted by the
    installed build, with the evidence attached.
    """
    by_tool = {}
    for r in results:
        by_tool.setdefault(r["tool"], []).append(r)

    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    ok = sum(1 for r in results if r["verdict"] == "ok")
    broken = [r for r in results if r["verdict"] in BROKEN]

    lines = [
        "# Verified Tool Invocations",
        "",
        "Generated by `scripts/check_tool_commands.py` — each command below was",
        "run against a dead loopback target in the kali-listener image and its",
        "failure classified. This records what the installed builds actually",
        "accept, not what the catalogue claims.",
        "",
        f"- Generated: {stamp}",
        f"- Image probed: `{container}`",
        f"- Commands checked: {len(results)}",
        f"- Verified working: {ok}",
        f"- Broken: {len(broken)}",
        "",
        "**A verdict is per image.** `no_binary` means \"not in the image probed\",",
        "not \"missing everywhere\": httpx, katana, naabu and tlsx live in",
        "pd-runner, not kali-listener. And a tool NAME can resolve to the WRONG",
        "PROGRAM — kali-listener's `httpx` is the Python HTTP client, while",
        "pd-runner has ProjectDiscovery's. The catalogue's httpx flags are",
        "ProjectDiscovery's, so dispatching one to kali-listener runs a different",
        "tool that rejects them.",
        "",
        "How to read a verdict:",
        "",
        "- **ok** — the tool accepted its arguments and reached the network.",
        "  `connection refused` against a dead port is the SUCCESS signal here:",
        "  it proves the options parsed and the call path works.",
        "- **bad_option** — the tool rejected its own flags. The command is wrong.",
        "- **missing_path** — the command names a file this image does not have.",
        "- **interactive** — no commands supplied, so it exits 0 saying nothing.",
        "- **unverifiable** — deliberately not probed (no `{target}` to redirect",
        "  to loopback), so running it might have contacted something real.",
        "",
    ]

    for tool in sorted(by_tool):
        rows = by_tool[tool]
        lines.append(f"### {tool}")
        lines.append("")
        for r in rows:
            v = r["verdict"]
            lines.append(f"- **{v}** — {r.get('detail') or ''}")
            lines.append(f"  - catalogue command: `{r['command']}`")
            if r.get("probe"):
                lines.append(f"  - probed as: `{r['probe']}`")
            head = (r.get("output_head") or "").strip()
            if head:
                first = " ".join(head.splitlines()[:2])[:200]
                lines.append(f"  - observed: `{first}`")
            lines.append("")
        if tool in helps:
            lines.append(f"Options this build of `{tool}` reports:")
            lines.append("")
            lines.append("```")
            lines.extend(helps[tool].splitlines()[:40])
            lines.append("```")
            lines.append("")

    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    print(f"markdown written: {path} ({len(lines)} lines)")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("tools", nargs="*", help="limit to these tool names")
    ap.add_argument("--container", default=os.environ.get(
        "TOOL_CHECK_CONTAINER", "kali-listener"))
    ap.add_argument("--timeout", type=int, default=int(os.environ.get(
        "TOOL_PROBE_TIMEOUT", "8")), help="per-command probe timeout")
    ap.add_argument("--batch", type=int, default=int(os.environ.get(
        "TOOL_CHECK_BATCH", "25")))
    ap.add_argument("--markdown", metavar="PATH", nargs="?",
                    const=os.path.join(REPO, "knowledge", "commands",
                                       "tool_invocations.md"),
                    help="write a RAG-ingestible record here (default: "
                         "knowledge/commands/tool_invocations.md)")
    args = ap.parse_args()

    if subprocess.run(["docker", "inspect", args.container],
                      capture_output=True).returncode != 0:
        print(f"{args.container} is not running — cannot verify at runtime.",
              file=sys.stderr)
        return 2
    if not os.path.exists(YAML):
        print(f"{YAML} not found", file=sys.stderr)
        return 2

    commands = extract_commands(YAML, only=set(args.tools))
    if not commands:
        print("no commands matched — nothing to check", file=sys.stderr)
        return 2
    print(f"Verifying {len(commands)} unique command(s) against "
          f"{args.container} (probe timeout {args.timeout}s)\n")

    try:
        results, helps = verify(args.container, commands, args.timeout,
                               args.batch, capture_help=bool(args.markdown))
    except RuntimeError as e:
        print(f"verification could not run: {e}", file=sys.stderr)
        return 2

    broken = report(results)
    if args.markdown:
        write_markdown(args.markdown, results, helps, args.container)
    return 1 if broken else 0


if __name__ == "__main__":
    sys.exit(main())
