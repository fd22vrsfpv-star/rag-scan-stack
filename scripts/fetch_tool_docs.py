#!/usr/bin/env python3
"""Fetch tool documentation from kali.org and record it for RAG ingestion.

WHY THIS EXISTS
---------------
`scripts/check_tool_commands.py` proved 63 of 243 catalogue commands cannot work
in the image they were probed against: 52 tools are not installed there, and 10
`httpx` commands carry flags belonging to a different program of the same name.
Deciding what to do about each needs to know what the tool IS — which package
provides it, whether Kali ships it, and what modes it has.

WHAT THE WEB DOCS DO AND DO NOT GIVE YOU
----------------------------------------
Measured against https://www.kali.org/tools/gobuster/ — the page yields the
description, the version, the SUBCOMMANDS (dir, vhost, dns, fuzz, tftp, s3, gcs)
and the GLOBAL options. It does **not** yield the per-subcommand flags, because
the page shows `gobuster --help` and gobuster's `-w` lives under
`gobuster dir --help`.

So the honest division of labour is:

  * **kali.org** — is this tool in Kali, what does it do, what modes does it
    have, which of those modes are we not using. Good for the 52 `no_binary`
    decisions: install it, or drop it from the catalogue.
  * **locally captured `--help`** (already recorded by check_tool_commands.py) —
    what the INSTALLED build accepts. Authoritative for this deployment, where
    kali.org documents upstream.
  * **the loopback probe** — whether a specific invocation actually parses. The
    only one of the three that can answer that.

None of them replaces the others, and the flag-level bugs are only findable by
the third.

REUSE, NOT REINVENTION
----------------------
Fetching goes through `scan_recommender/url_fetch.fetch_guide`, which already has
the parts that matter: scheme allowlist, SSRF protection via `_check_ip` (internal
addresses refused unless explicitly allowed), a 10 MB cap, a redirect cap, a hard
20-page crawl ceiling, a content-type allowlist, HTML→markdown extraction, and an
optional proxy so egress can follow the operator's profile.

It runs inside scan-recommender because that is where `url_fetch` lives and where
egress is configured. knowledge/ is mounted READ-ONLY there, deliberately, so the
service cannot rewrite its own knowledge base — this script writes on the host,
the same split `/kb/url/convert` uses.

Usage:
    scripts/fetch_tool_docs.py gobuster hydra
    scripts/fetch_tool_docs.py --missing        # the tools the runtime check
                                                # found absent from the image
    scripts/fetch_tool_docs.py --missing --proxy http://127.0.0.1:8080
"""
import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
CHECK_MD = os.path.join(REPO, "knowledge", "commands", "tool_invocations.md")
OUT_MD = os.path.join(REPO, "knowledge", "commands", "kali_tool_docs.md")
BASE = "https://www.kali.org/tools/{tool}/"

# Fetched inside the container so url_fetch's guards and the operator's egress
# configuration both apply. Written on the host because knowledge/ is read-only
# to the service.
_FETCH_SNIPPET = r'''
import json, sys
sys.path.insert(0, "/app")
from url_fetch import fetch_guide, UrlFetchError
url, proxy = sys.argv[1], (sys.argv[2] or None)
try:
    r = fetch_guide(url, depth=0, max_pages=1, proxy=proxy)
    print(json.dumps({"ok": True, "markdown": r.get("markdown") or "",
                      "title": r.get("title") or ""}))
except UrlFetchError as e:
    print(json.dumps({"ok": False, "refused": str(e)}))
except Exception as e:
    print(json.dumps({"ok": False, "error": f"{type(e).__name__}: {e}"}))
'''


def tools_missing_from_image(path=CHECK_MD):
    """Tools the runtime check reported as absent from the probed image.

    Read out of the generated record rather than re-probing: the record already
    states which image it was produced against, and re-running the probe here
    would make this script's answer depend on a second live sweep.
    """
    if not os.path.exists(path):
        return []
    out, tool = [], None
    for line in open(path, encoding="utf-8"):
        m = re.match(r"^### (\S+)", line)
        if m:
            tool = m.group(1)
            continue
        if tool and "**no_binary**" in line:
            out.append(tool)
            tool = None
    return sorted(set(out))


# The index, fetched as RAW HTML on purpose. extract_markdown() converts links
# to text, which destroys exactly what an index page is made of — the first
# attempt at this returned 12,577 characters of prose and zero slugs.
_INDEX_SNIPPET = r'''
import json, re, sys
sys.path.insert(0, "/app")
from url_fetch import fetch_url
proxy = (sys.argv[1] or None)
r = fetch_url("https://www.kali.org/tools/", proxy=proxy)
slugs = sorted(set(re.findall(r"/tools/([a-z0-9][a-z0-9._+-]*)/", r["html"])))
print(json.dumps({"status": r["status"], "slugs": slugs}))
'''


def kali_tool_index(container, proxy=""):
    """Every tool slug kali.org publishes (421 at time of writing).

    Needed because kali.org is indexed by PACKAGE/tool name while our catalogue
    uses BINARY names, and the two differ often enough to matter: ncat ships
    inside nmap, upnpc inside miniupnpc, testssl is published as testssl.sh.
    Guessing the URL from the binary name failed for 33 of 50 tools.
    """
    proc = subprocess.run(
        ["docker", "exec", "-i", container, "python3", "-c", _INDEX_SNIPPET, proxy],
        capture_output=True, text=True, timeout=180)
    if proc.returncode != 0 or not proc.stdout.strip():
        return []
    try:
        return json.loads(proc.stdout.strip().splitlines()[-1]).get("slugs", [])
    except ValueError:
        return []


def resolve_slug(tool, slugs):
    """(slug, how) for a binary name, or (None, reason).

    Deliberately conservative: an ambiguous match is REPORTED, not picked. A
    wrong page is worse than no page, because it reads as authoritative
    documentation for a tool it does not describe.
    """
    if tool in slugs:
        return tool, "exact"
    # testssl -> testssl.sh, upnpc -> upnpc-something
    pref = [s for s in slugs if s.startswith(tool + ".") or s.startswith(tool + "-")]
    if len(pref) == 1:
        return pref[0], f"prefix of {pref[0]}"
    if len(pref) > 1:
        return None, f"ambiguous: {pref[:4]}"
    # ncat -> nmap is NOT derivable by string matching; say so rather than guess
    contained = [s for s in slugs if tool.startswith(s) and len(s) > 3]
    if len(contained) == 1:
        return contained[0], f"binary of {contained[0]}"
    if len(contained) > 1:
        return None, f"ambiguous: {contained[:4]}"
    return None, "no kali.org page under this name"


def fetch_one(container, tool, proxy="", slug=None):
    url = BASE.format(tool=slug or tool)
    proc = subprocess.run(
        ["docker", "exec", "-i", container, "python3", "-c", _FETCH_SNIPPET,
         url, proxy],
        capture_output=True, text=True, timeout=180)
    if proc.returncode != 0 or not proc.stdout.strip():
        return {"ok": False, "error": (proc.stderr or "no output").strip()[-160:]}
    try:
        return json.loads(proc.stdout.strip().splitlines()[-1])
    except ValueError as e:
        return {"ok": False, "error": f"unparsable: {e}"}


SUBCOMMAND_HEADINGS = ("COMMANDS:", "Commands:", "SUBCOMMANDS:",
                       "Available Commands:", "Available commands:")


def detect_subcommands(body):
    """Subcommands a tool requires before its flags, from its own help text.

    This is the same fact that makes `--help` grepping useless for flag
    validation: gobuster's `-w` is not in `gobuster --help`, it is in
    `gobuster dir --help`. A tool with a COMMANDS: block is subcommand-first,
    and a catalogue command that omits the subcommand cannot work.
    """
    for head in SUBCOMMAND_HEADINGS:
        i = body.find(head)
        if i < 0:
            continue
        tail = body[i + len(head):i + len(head) + 700]
        subs = []
        for line in tail.splitlines():
            if not line.strip():
                if subs:
                    break
                continue
            if not line.startswith((" ", "\t")):
                break
            m = re.match(r"\s+([a-z][a-z0-9_-]{1,24})(?:,\s*\S+)?\s{2,}\S", line)
            if m:
                subs.append(m.group(1))
        subs = [x for x in subs if x not in ("help", "h", "completion")]
        if subs:
            return sorted(set(subs))
    return []


def catalogue_commands(yaml_path):
    """(tool -> [command]) from the service catalogue, for cross-checking."""
    out, name = {}, None
    if not os.path.exists(yaml_path):
        return out
    for line in open(yaml_path, encoding="utf-8"):
        m = re.match(r"\s*-\s+name:\s*(\S+)", line)
        if m:
            name = m.group(1).strip().strip("\"'")
            continue
        m = re.match(r'\s*command:\s*"(.+)"\s*$', line)
        if m and name:
            out.setdefault(name, []).append(m.group(1))
    return out


def check_subcommand_use(tool, subs, commands):
    """Catalogue commands for a subcommand-first tool that omit the subcommand.

    This is the actionable half: `gobuster dir -u ... -w ...` is right,
    `gobuster -u ... -w ...` cannot work, and the difference is invisible in a
    yaml diff.
    """
    bad = []
    for cmd in commands:
        parts = cmd.split()
        if len(parts) < 2:
            bad.append(cmd)
            continue
        if parts[1].lstrip("-") != parts[1]:      # a flag came first
            bad.append(cmd)
        elif parts[1] not in subs:
            bad.append(cmd)
    return bad


def write_markdown(path, fetched, missing_page, failed, resolved=None,
                   yaml_path=None):
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        "# Kali Tool Documentation",
        "",
        "Fetched from https://www.kali.org/tools/ by `scripts/fetch_tool_docs.py`",
        "via `scan_recommender/url_fetch.fetch_guide` (scheme allowlist, SSRF",
        "guard, size and redirect caps, HTML→markdown).",
        "",
        f"- Generated: {stamp}",
        f"- Tools documented: {len(fetched)}",
        f"- No kali.org page: {len(missing_page)}",
        f"- Fetch failed: {len(failed)}",
        "",
        "**What this source can and cannot tell you.** These pages carry the",
        "description, version, SUBCOMMANDS and GLOBAL options — they show",
        "`<tool> --help`. They do **not** carry per-subcommand flags: gobuster's",
        "`-w` lives under `gobuster dir --help`, not on this page. So use this to",
        "decide whether a tool belongs in the catalogue and which modes exist,",
        "and use `tool_invocations.md` — captured from the installed build — for",
        "what a specific invocation actually accepts.",
        "",
    ]
    if resolved:
        lines += ["**Binary → package**. kali.org is indexed by package name, so",
                  "these were resolved through the index rather than guessed:", ""]
        lines += [f"- `{t}` → `{v}`" for t, v in sorted(resolved.items())] + [""]
    cat = catalogue_commands(yaml_path) if yaml_path else {}
    subcommand_first = {}
    for tool in sorted(fetched):
        body = fetched[tool].strip()
        # Drop the extractor's own H1 AND the inner `### <tool>` it already
        # carries — without this every tool got two sections and two Source
        # lines, which defeats one-section-per-tool chunking.
        body = re.sub(r"^#\s+Packages and Binaries:\s*$", "", body, flags=re.M)
        # Demote every inner heading to level 4 rather than stripping them.
        #
        # A kali.org PACKAGE page can document several binaries: the nmap page
        # carries sections for ncat, ndiff, nmap and zenmap. Removing only the
        # heading that matches the fetched tool left the others at `###`, so
        # `ncat` and `nmap` each produced two top-level sections and chunking
        # could assemble an answer from half of one tool and half of another.
        # Demoting keeps the fact that the page covers several binaries while
        # leaving exactly one `###` per fetched tool.
        body = re.sub(r"^#{1,3}(\s+)", r"####\1", body, flags=re.M)
        body = re.sub(r"^Source:\s*http\S+$", "", body, flags=re.M).strip()

        subs = detect_subcommands(body)
        src = (resolved.get(tool, "").split(" ")[0] or tool) if resolved else tool
        lines.append(f"### {tool}")
        lines.append("")
        lines.append(f"Source: {BASE.format(tool=src)}")
        lines.append("")
        if subs:
            subcommand_first[tool] = subs
            lines.append(f"**Invocation: subcommand-first.** `{tool}` requires one "
                         f"of these before its flags: {', '.join(subs)}.")
            lines.append(f"So `{tool} <subcommand> [flags]`, never `{tool} [flags]` "
                         "— its per-subcommand flags do not appear in "
                         f"`{tool} --help`.")
            bad = check_subcommand_use(tool, subs, cat.get(tool, []))
            if bad:
                lines.append("")
                lines.append("Catalogue commands that OMIT the subcommand and "
                             "therefore cannot work:")
                lines.append("")
                lines.extend(f"- `{c}`" for c in bad)
            lines.append("")
        lines.extend(body.splitlines())
        lines.append("")

    if subcommand_first:
        lines += ["### tools that require a subcommand", "",
                  "Flagged so a caller — or a model drafting one — puts the",
                  "subcommand before the flags:", ""]
        lines += [f"- `{t}`: {', '.join(v)}" for t, v in sorted(subcommand_first.items())]
        lines.append("")

    if missing_page:
        lines += ["### tools with no kali.org page", "",
                  "Not documented upstream — decide per tool whether it belongs "
                  "in the catalogue at all:", ""]
        lines += [f"- {t}" for t in sorted(missing_page)] + [""]
    if failed:
        lines += ["### tools whose fetch failed", "",
                  "Reported rather than dropped: a silent omission here reads as "
                  "\"no such tool\".", ""]
        lines += [f"- {t}: {why}" for t, why in sorted(failed.items())] + [""]

    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    return len(lines)


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("tools", nargs="*", help="tool names to document")
    ap.add_argument("--missing", action="store_true",
                    help="use the tools the runtime check found absent")
    ap.add_argument("--catalogue", action="store_true",
                    help="use every tool the service catalogue invokes — needed "
                         "to flag subcommand-first tools we DO have installed, "
                         "like gobuster")
    ap.add_argument("--container", default=os.environ.get(
        "DOC_FETCH_CONTAINER", "scan-recommender"))
    ap.add_argument("--proxy", default="",
                    help="egress proxy, e.g. http://127.0.0.1:8080")
    ap.add_argument("--out", default=OUT_MD)
    ap.add_argument("--limit", type=int, default=80)
    args = ap.parse_args()

    tools = list(args.tools)
    if args.missing:
        tools += tools_missing_from_image()
    if args.catalogue:
        tools += list(catalogue_commands(
            os.path.join(REPO, "knowledge", "service_tools.yaml")))
    tools = sorted(set(t for t in tools if re.match(r"^[a-zA-Z0-9_.-]+$", t)))
    if not tools:
        print("no tools given. Pass names, or --missing to use the runtime "
              "check's no_binary list.", file=sys.stderr)
        return 2
    tools = tools[:args.limit]

    if subprocess.run(["docker", "inspect", args.container],
                      capture_output=True).returncode != 0:
        print(f"{args.container} is not running — url_fetch lives there.",
              file=sys.stderr)
        return 2

    print(f"Fetching docs for {len(tools)} tool(s) via {args.container}"
          f"{' through ' + args.proxy if args.proxy else ''}")
    slugs = kali_tool_index(args.container, args.proxy)
    print(f"kali.org publishes {len(slugs)} tool pages\n" if slugs else
          "could not read the kali.org index — falling back to name guessing\n")

    fetched, missing_page, failed, resolved = {}, [], {}, {}
    for i, tool in enumerate(tools, 1):
        slug, how = (tool, "unresolved")
        if slugs:
            slug, how = resolve_slug(tool, slugs)
            if not slug:
                # The index page is INCOMPLETE — 421 slugs, but `whois` has a
                # page that is not among them. So an index miss is not proof of
                # absence: try the direct URL before concluding anything. Being
                # "more correct" with the index alone lost two tools the naive
                # URL guess had found.
                slug, how = tool, "index miss, tried direct"
            elif how != "exact":
                resolved[tool] = f"{slug} ({how})"
        r = fetch_one(args.container, tool, args.proxy, slug=slug)
        if r.get("ok") and len((r.get("markdown") or "").strip()) > 200:
            fetched[tool] = r["markdown"]
            state = "ok"
        elif r.get("ok"):
            # Fetched, but essentially empty: kali.org returns a soft 404 page
            # rather than an error status for an unknown tool.
            missing_page.append(f"{tool} — page was empty")
            state = "no page"
        else:
            failed[tool] = r.get("refused") or r.get("error") or "unknown"
            state = f"FAILED ({failed[tool][:40]})"
        print(f"  [{i}/{len(tools)}] {tool:<20} {state}")

    n = write_markdown(args.out, fetched, missing_page, failed, resolved,
                       yaml_path=os.path.join(REPO, 'knowledge', 'service_tools.yaml'))
    print(f"\ndocumented {len(fetched)}, no page {len(missing_page)}, "
          f"failed {len(failed)}")
    print(f"markdown written: {args.out} ({n} lines)")
    print("\nIngest with:")
    print('  docker exec scan-recommender curl -sk -X POST '
          'https://127.0.0.1:8013/rag/playbooks/ingest \\\n'
          '    -H "Content-Type: application/json" '
          '-d \'{"playbook_dir":"/knowledge/commands"}\'')
    return 0 if fetched else 1


if __name__ == "__main__":
    sys.exit(main())
