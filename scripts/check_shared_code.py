#!/usr/bin/env python3
"""Verify per-service copies of shared modules match their canonical version.

    python3 scripts/check_shared_code.py            # exit 1 on drift
    python3 scripts/check_shared_code.py --list     # show what is compared

Several services carry their own copy of a shared module because each has its
own Docker build context. That is survivable only if the copies stay identical,
and they do not stay identical on their own: nmap_scanner's
`sanitize_command_arg` gained a `max_len` parameter — because the hardcoded
1000-character cap rejected nmap's top-1000 port specification (3,808 characters
expanded) — and the fix sat in one service while the other six kept the bug.

Run from post-install-check.sh, from CI, and from tests/test_shared_code.py, so
the same comparison enforces at deploy time, on every push, and in the suite.
Comparison ignores docstrings and comments: a reworded explanation is not drift,
a changed default or an added parameter is.
"""
import argparse
import ast
import hashlib
import os
import sys

REPO = os.path.realpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

# canonical path -> (basename copies are found under, functions to compare)
# Functions are named explicitly rather than "everything in the file": a service
# is allowed to ADD a local helper; it is not allowed to redefine a shared one.
SHARED_MODULES = {
    "common/validation.py": (
        "validation.py",
        ("sanitize_scan_id", "sanitize_filename", "validate_output_path",
         "sanitize_port", "validate_cidr", "sanitize_url_path",
         "sanitize_command_arg"),
    ),
    # No per-service copies exist today — pd_runner and osint_runner import this
    # from the rag-common base image. Listed so that if someone re-copies it
    # (the exact thing that happened to validation.py), the drift is caught
    # instead of quietly accumulating for months.
    "common/tool_job.py": (
        "tool_job.py",
        ("run_tool_job", "_count_findings", "_cleanup"),
    ),
}

SKIP_DIRS = {"__pycache__", "node_modules", ".git", "tests", ".venv", "venv"}


def function_hashes(path, names):
    """name -> hash of (signature + body), docstrings excluded."""
    out = {}
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            tree = ast.parse(fh.read())
    except (OSError, SyntaxError):
        return out
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in names:
            body = [n for n in node.body
                    if not (isinstance(n, ast.Expr) and isinstance(n.value, ast.Constant)
                            and isinstance(n.value.value, str))]
            payload = ast.dump(node.args) + ast.dump(ast.Module(body=body, type_ignores=[]))
            out[node.name] = hashlib.md5(payload.encode()).hexdigest()[:12]
    return out


def find_copies(basename, canonical_abs):
    found = []
    for root, dirs, files in os.walk(REPO):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fn in files:
            if fn != basename:
                continue
            path = os.path.join(root, fn)
            if os.path.realpath(path) != canonical_abs:
                found.append(path)
    return sorted(found)


def check(verbose=False):
    problems, compared = [], 0
    for canonical_rel, (basename, names) in SHARED_MODULES.items():
        canonical = os.path.join(REPO, canonical_rel)
        if not os.path.exists(canonical):
            problems.append(f"canonical module missing: {canonical_rel}")
            continue
        canon = function_hashes(canonical, names)
        missing_canon = [n for n in names if n not in canon]
        if missing_canon:
            problems.append(f"{canonical_rel} does not define: {', '.join(missing_canon)}")
        copies = find_copies(basename, os.path.realpath(canonical))
        if verbose:
            print(f"  canonical: {canonical_rel} ({len(canon)} function(s))")
        if not copies:
            # Not an error — it means the duplication is gone, which is the goal.
            print(f"  ok     {canonical_rel}: no per-service copies remain")
            continue
        for copy in copies:
            rel = os.path.relpath(copy, REPO)
            theirs = function_hashes(copy, names)
            drifted = sorted(n for n, h in theirs.items() if n in canon and canon[n] != h)
            absent = sorted(n for n in canon if n not in theirs)
            compared += 1
            if drifted or absent:
                detail = []
                if drifted:
                    detail.append("diverged: " + ", ".join(drifted))
                if absent:
                    detail.append("missing: " + ", ".join(absent))
                problems.append(f"{rel} — " + "; ".join(detail))
            elif verbose:
                print(f"  ok     {rel}")
    return problems, compared


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--list", action="store_true", help="show every file compared")
    args = ap.parse_args()

    problems, compared = check(verbose=args.list)
    if problems:
        print("\nShared-module drift detected:\n")
        for p in problems:
            print(f"  ✗ {p}")
        print("\nThese modules are duplicated per Docker build context and must stay")
        print("identical. Port the change into the canonical file, copy it to every")
        print("service, and rebuild those images. For validation.py in particular a")
        print("weaker sanitizer in one service is a real hole, not untidiness.")
        return 1
    print(f"✅ shared modules consistent ({compared} copy/copies compared)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
