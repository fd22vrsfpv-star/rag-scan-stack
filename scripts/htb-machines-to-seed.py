#!/usr/bin/env python3
"""Turn the HTB machine CATALOGUES into service-scoped knowledge.

    python3 scripts/htb-machines-to-seed.py /path/to/htb-writeups \
        --out knowledge/seed/htb-attack-paths.yaml

WHY A SEPARATE CONVERTER
------------------------
`scripts/walkthrough-to-seed.sh` is the right tool for a NARRATIVE writeup: it
asks an LLM to pull out the technique that generalises. These files are not
narratives — `machines/{easy,medium,hard,insane}/README.md` are markdown TABLES:

    | # | Machine | OS | Key Vulnerability / Technique | Attack Path Summary | Writeup |

Already-structured input does not need a model to destructure it, and a
deterministic parse is reviewable, re-runnable and cannot hallucinate. (It is
also not subject to the rate limits that have been intermittently throttling the
configured backend.)

THE FILTER — Docs/KNOWLEDGE_BASE_GUIDE.md, "Turning a lab walkthrough into
knowledge". Keep what applies to a DIFFERENT host running the same thing:

    Machine name ("Lame")      DROP  — box-specific, the definition of not-knowledge
    Writeup links              DROP  — 4-5 URLs per row, 359 rows; noise in a prompt
    OS                         KEEP  — narrows applicability
    Key Vulnerability          KEEP  — "Samba 3.0.20 RCE (CVE-2007-2447)"
    Attack Path Summary        KEEP  — "exploit the username map script command
                                       injection for a root shell"

Each row becomes one line of "when you see X, this is the known path". Rows are
grouped by the service the technology belongs to, so the result is retrievable
as Layer 4 (service-scoped) knowledge rather than one undifferentiated blob.

Unmapped rows go to a `general` document rather than being dropped silently —
what the classifier missed should be visible, not invisible.
"""
import argparse
import pathlib
import re
import sys

# service <- keywords in the "Key Vulnerability / Technique" text.
# Ordered: the first family whose keyword appears wins, so put the specific
# technologies before the generic ones (a "Drupal RCE" is web, not "rce").
SERVICE_KEYWORDS = [
    ("smb", ["samba", "smb", "ms17-010", "eternalblue", "ms08-067", "netapi",
             "cifs", "netbios", "printnightmare", "petitpotam", "zerologon"]),
    # AD/LDAP. "as-rep" and "ad enum" are spelled several ways in the corpus,
    # and a bare "ad" substring would match "load"/"read"/"upload" — hence the
    # word-boundary entries handled in classify().
    ("ldap", ["active directory", "kerberos", "kerberoast", "asrep", "as-rep",
              "ad cs", "adcs", "ldap", "bloodhound", "dcsync", "golden ticket",
              "silver ticket", "ntds", "laps", "winrm", "password spray",
              "seimpersonate", "sebackupprivilege", "constrained delegation",
              "unconstrained delegation", "rbcd", "gpp password"]),
    ("http", ["http", "web", "drupal", "wordpress", "joomla", "iis", "apache",
              "nginx", "tomcat", "php", "cgi", "shellshock", "coldfusion",
              "jenkins", "struts", "webdav", "lfi", "rfi", "sqli",
              "sql injection", "xss", "ssti", "ssrf", "upload", "cms",
              "nibbleblog", "hfs", "httpfileserver", "magento", "grafana",
              "jira", "confluence", "gitlab", "django", "flask", "node",
              "deserial", "xxe", "prototype pollution", "graphql", "api",
              "log4j", "spring", "wildcard", "webshell", "cve-2021-44228"]),
    ("mysql", ["mysql", "mariadb"]),
    ("mssql", ["mssql", "sql server", "ms sql"]),
    ("ftp", ["ftp", "vsftpd", "proftpd"]),
    ("ssh", ["ssh", "openssh"]),
    ("smtp", ["smtp", "exim", "postfix", "mail server"]),
    ("dns", ["dns", "bind", "zone transfer"]),
    ("snmp", ["snmp"]),
    ("nfs", ["nfs"]),
    ("redis", ["redis"]),
    ("mongodb", ["mongo"]),
    ("rsync", ["rsync"]),
    ("rdp", ["rdp", "bluekeep", "ms-wbt"]),
    ("docker", ["docker", "kubernetes", "k8s", "container escape"]),
]

ROW = re.compile(r"^\|\s*\d+\s*\|(.+)$")

# Sub-headings WITHIN a service document. These matter more than they look:
# `_chunk_markdown` splits on markdown headers, so without them a service became
# ONE chunk — the http document was 34,366 characters under a single embedding
# vector, and since the recommendation context truncates a chunk to 600 chars,
# 33,700 of them could never be retrieved at all. Grouping by product also makes
# each vector mean one thing, so a "drupal" query matches the Drupal group
# instead of an average over 210 unrelated paths.
PRODUCT_GROUPS = [
    "drupal", "wordpress", "joomla", "magento", "prestashop", "opencart",
    "moodle", "roundcube", "iis", "apache", "nginx", "tomcat", "jboss",
    "weblogic", "websphere", "wildfly", "jenkins", "struts", "spring",
    "log4j", "coldfusion", "sharepoint", "exchange", "gitlab", "gitea",
    "gogs", "jira", "confluence", "grafana", "kibana", "elastic", "zabbix",
    "cacti", "webmin", "jupyter", "sonarqube", "rocket.chat", "django",
    "flask", "laravel", "node", "php", "asp.net",
]

# Fallback grouping when no product is named: the class of weakness.
CLASS_GROUPS = [
    ("SQL injection", ["sqli", "sql injection"]),
    ("Local/Remote file inclusion", ["lfi", "rfi", "file inclusion"]),
    ("Command injection", ["command injection", "os injection", "rce via"]),
    ("Deserialization", ["deserial", "pickle", "yaml load"]),
    ("Server-side template injection", ["ssti", "template injection"]),
    ("Server-side request forgery", ["ssrf"]),
    ("XML external entity", ["xxe"]),
    ("File upload", ["upload"]),
    ("Cross-site scripting", ["xss"]),
    ("Authentication bypass", ["auth bypass", "authentication bypass",
                               "default cred", "weak cred", "credential"]),
    ("Path traversal", ["traversal", "directory traversal"]),
]


def group_for(vuln: str, attack: str) -> str:
    """A sub-heading: the product if one is named, else the weakness class."""
    low = f"{vuln} {attack}".lower()
    for product in PRODUCT_GROUPS:
        if product in low:
            return product.title()
    for label, keys in CLASS_GROUPS:
        if any(k in low for k in keys):
            return label
    return "Other paths"


# Word-boundary keywords: substring matching would fire on "load", "read",
# "upload" for a bare "ad".
WORD_KEYWORDS = {"ldap": [r"\bad\b", r"\bdc\b"]}


def classify(text: str) -> str:
    low = text.lower()
    for service, keywords in SERVICE_KEYWORDS:
        if any(k in low for k in keywords):
            return service
        if any(re.search(pat, low) for pat in WORD_KEYWORDS.get(service, [])):
            return service
    return "general"


def clean(cell: str) -> str:
    """Strip markdown emphasis and links, keeping the link TEXT."""
    cell = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", cell)   # [text](url) -> text
    cell = cell.replace("**", "").replace("`", "")
    return " ".join(cell.split()).strip()


def parse(repo: pathlib.Path):
    rows, files = [], sorted((repo / "machines").rglob("*.md"))
    for path in files:
        difficulty = path.parent.name
        for line in path.read_text(encoding="utf-8").splitlines():
            m = ROW.match(line)
            if not m:
                continue
            cells = [clean(c) for c in m.group(1).split("|")]
            # machine, os, vuln, attack path, writeup(s)
            if len(cells) < 4:
                continue
            _machine, os_name, vuln, attack = cells[0], cells[1], cells[2], cells[3]
            if not vuln or not attack:
                continue
            rows.append({"difficulty": difficulty, "os": os_name,
                         "vuln": vuln, "attack": attack})
    return rows


def build_docs(rows):
    by_service = {}
    for r in rows:
        svc = classify(f"{r['vuln']} {r['attack']}")
        by_service.setdefault(svc, []).append(r)
    return by_service


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("repo", help="path to a clone of momenbasel/htb-writeups")
    ap.add_argument("--out", default="knowledge/seed/htb-attack-paths.yaml")
    ap.add_argument("--min-rows", type=int, default=3,
                    help="skip services with fewer than this many entries")
    args = ap.parse_args()

    repo = pathlib.Path(args.repo)
    if not (repo / "machines").is_dir():
        sys.exit(f"no machines/ directory under {repo}")

    rows = parse(repo)
    if not rows:
        sys.exit("parsed 0 machine rows — the table format changed")
    by_service = build_docs(rows)

    import yaml

    class Block(str):
        pass

    yaml.add_representer(Block, lambda d, s: d.represent_scalar(
        "tag:yaml.org,2002:str", s, style="|"))

    docs = []
    for svc, items in sorted(by_service.items(),
                             key=lambda kv: -len(kv[1])):
        if len(items) < args.min_rows:
            continue
        lines = [
            f"# Known attack paths seen against {svc} (HTB machine corpus)",
            "",
            "Each line is a technology or weakness and the path that worked "
            "against it. Machine names and writeup links are deliberately "
            "omitted: the box is not the knowledge, the path is. Use these to "
            "recognise a familiar stack and to choose what to test — not as "
            "evidence that a given host is vulnerable.",
            "",
        ]
        seen, grouped = set(), {}
        for r in sorted(items, key=lambda x: x["vuln"].lower()):
            key = (r["vuln"].lower(), r["attack"].lower())
            if key in seen:
                continue
            seen.add(key)
            grouped.setdefault(group_for(r["vuln"], r["attack"]), []).append(r)

        # Largest groups first, "Other paths" last however big it is.
        def order(kv):
            return (kv[0] == "Other paths", -len(kv[1]), kv[0])

        for heading, entries in sorted(grouped.items(), key=order):
            lines.append(f"## {heading}")
            lines.append("")
            for r in entries:
                os_tag = f" [{r['os']}]" if r["os"] else ""
                lines.append(f"- **{r['vuln']}**{os_tag} — {r['attack']}")
            lines.append("")
        docs.append({
            "title": f"HTB known attack paths — {svc}",
            "service": svc,
            "doc_kind": "training",
            "content": Block("\n".join(lines) + "\n"),
        })

    header = f"""# HTB machine attack paths -> Layer 4 service-scoped knowledge.
#
# GENERATED by scripts/htb-machines-to-seed.py from a clone of
# https://github.com/momenbasel/htb-writeups (MIT). Regenerate rather than
# hand-editing:
#   python3 scripts/htb-machines-to-seed.py <clone> --out {args.out}
#
# Source rows: {len(rows)} machines across easy/medium/hard/insane.
# Machine names and writeup links are dropped on purpose (box-specific);
# OS, the key vulnerability and the attack path are kept and grouped by service.
#
# Import (idempotent):
#   ./scripts/import-knowledge.sh --file {args.out} --dry-run
#   ./scripts/import-knowledge.sh --file {args.out}
"""
    out = pathlib.Path(args.out)
    out.write_text(header + yaml.dump({"service_docs": docs}, sort_keys=False,
                                      allow_unicode=True, width=100))
    total = sum(len(d["content"].splitlines()) - 5 for d in docs)
    print(f"parsed {len(rows)} machine rows")
    for svc, items in sorted(by_service.items(), key=lambda kv: -len(kv[1])):
        mark = "" if len(items) >= args.min_rows else "  (skipped, below --min-rows)"
        print(f"  {svc:10} {len(items):>4}{mark}")
    print(f"wrote {out} — {len(docs)} service documents, ~{total} attack paths")


if __name__ == "__main__":
    main()
