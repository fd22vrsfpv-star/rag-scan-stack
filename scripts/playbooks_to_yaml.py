#!/usr/bin/env python3
"""Turn the methodology playbooks into machine-readable steps.

    python3 scripts/playbooks_to_yaml.py [--check] [--out DIR]

WHY THIS EXISTS
---------------
`knowledge/playbooks/*.md` holds 3,896 lines of real methodology — SSH, SMB,
databases, lateral movement, persistence, AD — and every line of it was prose.
It was ingested for RAG context and nothing else: nothing could execute a step,
nothing could say which steps applied to a host, and nothing recorded whether
any of them had been done. `ssh_methodology.md` had a "Post-Exploitation / If
Access Gained" checklist that no code path could reach.

This extracts the structure that is already there — `##` sections are phases,
`###`/`####` headings are steps, fenced blocks are commands, and the bullets
after a fence are what to look for — into `knowledge/playbooks/*.yaml`.

THE MARKDOWN STAYS AUTHORITATIVE
--------------------------------
The prose is what a human reads and what RAG ingests, so it is not replaced and
not generated from the YAML. The YAML is an EXTRACT, and `--check` verifies it
still matches: every command in the YAML must appear verbatim in the markdown.
That makes drift a test failure rather than a slow divergence, and it means the
extractor can never invent a command that is not in the methodology.

WHAT IS NOT INFERRED
--------------------
`access_required` is a heuristic — a command mentioning a username/password flag
or sitting under a "post-access" heading needs something the recon phase does not
have. It is recorded so a consumer can filter, NOT so anything can decide to run:
authorisation stays with the scope gate and the engagement's approval, and a
playbook step is a suggestion the operator or a gated dispatcher acts on.
"""
from __future__ import annotations

import argparse
import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PLAYBOOKS = os.path.join(REPO, "knowledge", "playbooks")

# Language tags that hold something a machine could run. `cpp`, `asm`, `html`
# and friends are illustrative source in the exploitation write-ups, not steps.
RUNNABLE_LANGS = {"bash", "sh", "shell", "powershell", "ps1", "cmd", "sql", ""}

# A fence with no language is ambiguous — most are shell, some are output. Kept,
# because dropping them loses roughly half the commands in these files, and
# marked so a consumer can treat them with suspicion.
#
# Prompt stripping is per-language and NOT applied to PowerShell. A bare `$`
# prefix means "shell prompt" in bash and "variable" in PowerShell, and stripping
# it turned `$Filter = Set-WmiInstance ...` into `Filter = Set-WmiInstance ...`
# in 21 extracted commands — syntactically broken, and it would have looked like
# methodology.
_SHELL_LANGS = {"bash", "sh", "shell", ""}
_PROMPTS = (
    re.compile(r"^\s*\$\s+"),                       # "$ nmap ..."  (space required)
    re.compile(r"^\s*[\w.-]+@[\w.-]+:[^\s]*\s*[#$]\s+"),  # "root@kali:~# nmap ..."
    re.compile(r"^\s*>\s+"),                         # "> command"
    re.compile(r"^\s*PS\s+[A-Za-z]:\\[^>]*>\s*"),      # "PS C:\Users\x> "
    re.compile(r"^\s*C:\\[^>]*>\s*"),                  # "C:\Windows> "
)

# Access classification. Heuristic and deliberately conservative: anything that
# looks like it carries a credential, or sits under a post-access heading, is
# marked as needing one. Over-marking costs a filter; under-marking would put a
# post-exploitation command in front of a recon consumer.
_CRED_FLAGS = re.compile(
    r"(?:^|\s)-(?:u|p|P|U)\s|--user|--pass|--username|--password|"
    r"PGPASSWORD|-pw\s|/user:|/pass:", re.I)
_POST_ACCESS_HEADING = re.compile(
    r"post[- ]?(?:access|exploit|exploitation|enum)|if access gained|"
    r"after (?:access|compromise)|privilege escalation|persistence|"
    r"lateral movement|credential dumping", re.I)

# Does the step CHANGE the target? The methodology legitimately documents
# persistence and evasion — adding an authorized_keys line, `useradd backdoor`,
# writing a Run key — and those are not the same kind of thing as `sudo -l`.
#
# This platform collects data for a tester to act on. A consumer that queues
# steps automatically must be able to exclude the ones that modify a host, and
# the only safe default is to exclude them. Conservative on purpose: a false
# "mutates" costs a filter, a false "read-only" writes to someone's server.
_MUTATING_PHASE = re.compile(
    r"persistence|defen[cs]e evasion|backdoor|implant|anti[- ]forensic|"
    r"covering tracks|cleanup", re.I)
_MUTATING_CMD = re.compile(
    r">>|(?<![0-9])>(?!&)|\buseradd\b|\busermod\b|\bchpasswd\b|\bpasswd\b|"
    r"\bmkdir\b|\brm\b|\bmv\b|\bcp\b|\bchmod\b|\bchown\b|\bcrontab\b|"
    r"\bschtasks\b|\bsc(?:\.exe)?\s+create|\breg\s+add\b|\bnet\s+user\b|"
    r"New-Item|Set-ItemProperty|New-Service|Register-ScheduledTask|"
    r"Set-WmiInstance|Add-MpPreference|Set-MpPreference|Invoke-WebRequest\s+-OutFile|"
    r"\bcurl\b[^|]*\s-[oO]\b|\bwget\b|\btee\b|\bdd\b\s+of=|\binsmod\b|"
    r"\bsystemctl\s+(?:enable|start|restart)\b|\bupdate-rc\.d\b", re.I)

_SLUG = re.compile(r"[^a-z0-9]+")


def slug(text: str, limit: int = 60) -> str:
    return _SLUG.sub("-", (text or "").strip().lower()).strip("-")[:limit] or "step"


def _strip_numbering(title: str) -> str:
    return re.sub(r"^\s*\d+[.)]\s*", "", title).strip()


def parse(path: str) -> dict:
    """One playbook markdown file -> a structured playbook dict."""
    with open(path, encoding="utf-8") as fh:
        lines = fh.read().splitlines()

    doc = {"name": os.path.basename(path)[:-3], "source": os.path.basename(path),
           "title": "", "overview": "", "phases": []}
    phase = None
    step = None
    last_heading = ""
    in_fence = False
    fence_lang = ""
    fence_body: list[str] = []
    fence_start = 0
    pending_bullets: list[str] = []

    def close_step():
        """Attach trailing bullets to the step they describe."""
        nonlocal step, pending_bullets
        if step is not None and pending_bullets:
            step["checks"].extend(pending_bullets)
        pending_bullets = []

    def new_step(title: str, lineno: int, parent: str = ""):
        nonlocal step
        close_step()
        step = {"id": "", "title": _strip_numbering(title), "line": lineno,
                "commands": [], "checks": [], "access_required": "none",
                # Carried so _classify can see the heading a numbered sub-step
                # sits under: "If Access Gained" is what makes `sudo -l` a
                # post-access step rather than a recon one.
                "parent": parent}
        if phase is not None:
            phase["steps"].append(step)

    for i, raw in enumerate(lines, 1):
        line = raw.rstrip()

        # Fences may be INDENTED — six of them are, all in ssh_methodology.md
        # under the numbered "If Access Gained" checklist, and requiring column
        # zero silently dropped exactly the post-exploitation steps this work
        # exists to reach.
        stripped_line = line.lstrip()
        if stripped_line.startswith("```"):
            if not in_fence:
                in_fence = True
                fence_lang = stripped_line[3:].strip().lower()
                fence_body, fence_start = [], i
            else:
                in_fence = False
                if fence_lang in RUNNABLE_LANGS and step is not None:
                    for cmd in _commands_from(fence_body, fence_lang):
                        step["commands"].append(
                            {"lang": fence_lang or "unknown", "command": cmd,
                             "line": fence_start})
            continue
        if in_fence:
            fence_body.append(line)
            continue

        if line.startswith("# ") and not doc["title"]:
            doc["title"] = line[2:].strip()
        elif line.startswith("## "):
            close_step()
            step = None
            name = line[3:].strip()
            phase = {"id": slug(name), "name": name, "line": i, "steps": []}
            doc["phases"].append(phase)
        elif line.startswith("### ") or line.startswith("#### "):
            if phase is None:      # a heading before any ## — give it a home
                phase = {"id": "general", "name": "General", "line": i, "steps": []}
                doc["phases"].append(phase)
            last_heading = line.lstrip("#").strip()
            new_step(last_heading, i)
        elif re.match(r"^\s*\d+[.)]\s+\*\*", line):
            # "1. **Enumerate sudo rights**" — a bolded numbered item is a step
            # in these files, not a bullet. Treating it as prose collapsed four
            # distinct SSH post-access checks into one unnamed blob.
            title = re.sub(r"^\s*\d+[.)]\s*", "", line).strip().strip("*").strip()
            new_step(title, i, parent=last_heading)
        elif re.match(r"^\s*[-*]\s+", line):
            pending_bullets.append(re.sub(r"^\s*[-*]\s+", "", line).strip())
        elif not line.strip():
            close_step()
        elif phase is not None and phase["name"].lower() == "overview" and not doc["overview"]:
            doc["overview"] = line.strip()

    close_step()

    # Ids and access classification, after the tree is built so a step can see
    # the phase it belongs to.
    for ph in doc["phases"]:
        seen: dict[str, int] = {}
        for st in ph["steps"]:
            base = f"{ph['id']}.{slug(st['title'])}"
            seen[base] = seen.get(base, 0) + 1
            st["id"] = base if seen[base] == 1 else f"{base}-{seen[base]}"
            st["access_required"] = _classify(ph, st)
            st["mutates"] = _mutates(ph, st)
    doc["phases"] = [p for p in doc["phases"]
                     if p["name"].lower() != "overview" and p["steps"]]
    # A file the extractor could not structure must SAY so. An empty phase list
    # with no explanation reads as "this playbook has no steps", which is a
    # different claim from "this file is a scraped page with no headings and
    # terminal transcripts instead of commands" — and the second is actionable.
    if not doc["phases"]:
        doc["unstructured"] = _why_unstructured(lines)
    return doc


def _why_unstructured(lines: list[str]) -> str:
    heads = sum(1 for ln in lines if ln.startswith("### ") or ln.startswith("## "))
    if heads == 0:
        return ("no ## or ### headings — flat prose (usually an imported web "
                "page). Add headings to the markdown and re-run.")
    return ("headings present but no runnable fenced commands under them — the "
            "code blocks are output or illustrative source, not steps.")


def _commands_from(body: list[str], lang: str = "") -> list[str]:
    """Runnable lines from a fence body, joining shell continuations.

    Comment lines are dropped — these files use `# Nmap scripts` as a label
    inside the fence, which is also why anything reading these files has to
    track fence state: those lines look exactly like markdown headings.
    """
    out: list[str] = []
    buf = ""
    comment = "#" if lang in _SHELL_LANGS or lang in ("powershell", "ps1") else "::"
    for line in body:
        s = line.strip()
        if not s:
            continue
        # `#` is a comment in shell and PowerShell but a legitimate character
        # elsewhere; `::` is the cmd comment. `#!` is a shebang, not a label.
        if s.startswith(comment) and not s.startswith("#!"):
            continue
        if lang in ("cmd",) and s.lower().startswith("rem "):
            continue
        for rx in _PROMPTS:
            stripped = rx.sub("", s)
            if stripped != s:
                s = stripped
                break
        if not s:
            continue
        if buf:
            buf += " " + s
        else:
            buf = s

        # A shell line ending in a backslash continues on the next one.
        if buf.endswith("\\"):
            buf = buf[:-1].rstrip()
            continue

        # A PowerShell hashtable or script block spans lines with no
        # continuation marker at all:
        #
        #     $Filter = Set-WmiInstance ... -Arguments @{
        #         Name = "EvilFilter"
        #         Query = "SELECT ..."
        #     }
        #
        # Emitting each line separately produced `Name = "EvilFilter"` as a
        # standalone "command" — syntactically meaningless, and indistinguishable
        # from methodology to anyone reading the queue. Join until the braces
        # balance.
        if _unbalanced(buf):
            continue

        out.append(buf)
        buf = ""
    if buf:
        out.append(buf)
    return out


def _unbalanced(text: str) -> bool:
    """True while braces/parens opened in `text` are still unclosed.

    Ignores anything inside quotes, because a Query string routinely contains a
    brace and counting it would swallow the rest of the fence.
    """
    depth = 0
    quote = ""
    prev = ""
    for ch in text:
        if quote:
            if ch == quote and prev != "\\":
                quote = ""
        elif ch in "\"'":
            quote = ch
        elif ch in "{(":
            depth += 1
        elif ch in "})":
            depth -= 1
        prev = ch
    return depth > 0


def _classify(phase: dict, step: dict) -> str:
    """`none` | `credential` | `shell` — what a step needs before it is useful."""
    heading = f"{phase['name']} {step.get('parent', '')} {step['title']}"
    text = " ".join(c["command"] for c in step["commands"])
    if _POST_ACCESS_HEADING.search(heading):
        return "shell"
    if _CRED_FLAGS.search(text):
        return "credential"
    return "none"


def _mutates(phase: dict, step: dict) -> bool:
    """True when the step writes to the target rather than reading from it."""
    if _MUTATING_PHASE.search(f"{phase['name']} {step.get('parent','')} {step['title']}"):
        return True
    return any(_MUTATING_CMD.search(c["command"]) for c in step["commands"])


def render(doc: dict) -> str:
    import yaml
    payload = {
        "name": doc["name"],
        "title": doc["title"],
        "source": doc["source"],
        "generated_by": "scripts/playbooks_to_yaml.py",
        **({"unstructured": doc["unstructured"]} if doc.get("unstructured") else {}),
        "phases": [
            {"id": p["id"], "name": p["name"],
             "steps": [
                 {"id": s["id"], "title": s["title"],
                  "access_required": s["access_required"],
                  "mutates": s["mutates"],
                  "source_line": s["line"],
                  **({"commands": [{"lang": c["lang"], "command": c["command"]}
                                   for c in s["commands"]]} if s["commands"] else {}),
                  **({"checks": s["checks"]} if s["checks"] else {})}
                 for s in p["steps"]]}
            for p in doc["phases"]],
    }
    header = (
        "# GENERATED from {src} by scripts/playbooks_to_yaml.py — do not hand-edit.\n"
        "#\n"
        "# The markdown stays authoritative: it is what a human reads and what RAG\n"
        "# ingests. This is an EXTRACT of the steps in it, so that something other\n"
        "# than a language model can act on them. Re-generate after editing the\n"
        "# markdown; tests/test_playbooks.py fails if the two drift.\n"
        "#\n"
        "# access_required is a conservative heuristic, recorded so a consumer can\n"
        "# FILTER — never so anything can decide to run. Authorisation stays with\n"
        "# the scope gate and the engagement's approval.\n"
    ).format(src=doc["source"])
    return header + yaml.safe_dump(payload, sort_keys=False, allow_unicode=True,
                                   default_flow_style=False, width=100)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true",
                    help="verify the YAML matches the markdown; write nothing")
    ap.add_argument("--out", default=PLAYBOOKS)
    args = ap.parse_args()

    mds = sorted(f for f in os.listdir(PLAYBOOKS) if f.endswith(".md"))
    if not mds:
        print("no playbooks found", file=sys.stderr)
        return 1

    drift, unstructured = [], []
    totals = {"files": 0, "phases": 0, "steps": 0, "commands": 0}
    for md in mds:
        doc = parse(os.path.join(PLAYBOOKS, md))
        out_path = os.path.join(args.out, md[:-3] + ".yaml")
        text = render(doc)
        totals["files"] += 1
        if doc.get("unstructured"):
            unstructured.append((md, doc["unstructured"]))
        totals["phases"] += len(doc["phases"])
        totals["steps"] += sum(len(p["steps"]) for p in doc["phases"])
        totals["commands"] += sum(len(s["commands"])
                                  for p in doc["phases"] for s in p["steps"])
        if args.check:
            if not os.path.exists(out_path):
                drift.append(f"{md}: no YAML")
            elif open(out_path, encoding="utf-8").read() != text:
                drift.append(f"{md}: YAML is stale")
        else:
            with open(out_path, "w", encoding="utf-8") as fh:
                fh.write(text)
            print(f"  {md:<46} {len(doc['phases']):>2} phases  "
                  f"{sum(len(p['steps']) for p in doc['phases']):>3} steps  "
                  f"{sum(len(s['commands']) for p in doc['phases'] for s in p['steps']):>3} commands")

    if args.check and drift:
        print("playbook YAML is out of date:", file=sys.stderr)
        for d in drift:
            print("  " + d, file=sys.stderr)
        print("\nRun: python3 scripts/playbooks_to_yaml.py", file=sys.stderr)
        return 1
    print(f"\n{totals['files']} playbooks, {totals['phases']} phases, "
          f"{totals['steps']} steps, {totals['commands']} commands")
    if unstructured:
        print(f"\n{len(unstructured)} could not be structured — reported, not "
              f"silently empty:")
        for name, why in unstructured:
            print(f"  {name}: {why}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
