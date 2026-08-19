#!/usr/bin/env python3
"""Is the code in each running container the code in this working tree?

WHY THIS EXISTS

Most services bake their source into the image — only `etl/` and a couple of
others are bind-mounted. `docker compose restart` therefore re-runs the OLD code
with no error and no warning. A scope-enforcement fix was committed, reviewed
and believed live for hours while the container kept ingesting out-of-scope
hosts, because osint_runner.py is baked and the image was never rebuilt.

Nothing in the stack reported that. This does.

    python3 scripts/check_image_freshness.py            # every running service
    python3 scripts/check_image_freshness.py rag-api    # just one

Exit code 1 if any service is stale, so it can gate a deploy or a test run.
"""
import hashlib
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# service -> build context. Only services that BAKE their source; bind-mounted
# ones (etl/) cannot go stale.
SERVICES = {
    "rag-api": "app/rag-api",
    "pentest-dashboard": "dashboard/bff",
    "autogen-agents": "autogen_agents",
    "osint-runner": "osint_runner",
    "pd-runner": "pd_runner",
    "web-scanner": "web_scanner",
    "nuclei-runner": "nuclei",
    "nmap_scanner": "nmap_scanner",
    "scan-recommender": "scan_recommender",
    "playwright-scanner": "playwright_scanner",
    "brutus-runner": "brutus_runner",
    "exploit-runner": "exploit_runner",
    "kali-listener": "kali_listener",
    "node-manager": "node_manager",
    "news-runner": "news_runner",
}

# Directories inside an image that are never our source. Matching on basename
# alone is wrong — an image holds dozens of main.py/util.py under site-packages,
# and taking the first hit reports a false STALE. Paths are matched by suffix.
SKIP = ("/proc/", "/__pycache__/", "/site-packages/", "/dist-packages/",
        "/usr/lib/python", "/usr/local/lib/python", "/node_modules/")

FIND = (
    "find / -name '*.py' -type f "
    "-not -path '*/proc/*' -not -path '*/__pycache__/*' "
    "-not -path '*/site-packages/*' -not -path '*/dist-packages/*' "
    "2>/dev/null | xargs -r md5sum 2>/dev/null"
)


def _sh(args, timeout=120):
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return r.stdout
    except Exception:
        return ""


def running():
    return set(_sh(["docker", "ps", "--format", "{{.Names}}"]).split())


def container_hashes(svc):
    """path -> md5 for every source file in the image, skipping vendored code."""
    out = _sh(["docker", "exec", svc, "sh", "-c", FIND])
    table = {}
    for line in out.splitlines():
        parts = line.split("  ", 1)
        if len(parts) != 2:
            continue
        digest, path = parts[0].strip(), parts[1].strip()
        if any(s in path for s in SKIP):
            continue
        table[path] = digest
    return table


def md5(path):
    return hashlib.md5(path.read_bytes()).hexdigest()


def _resolve_layout(host_files, ctx_dir, table):
    """Where this build context landed, and in what shape.

    Returns (root, flattened, hits) or None.

    Two shapes exist in this repo:

      structured  host `bff/main.py`      -> container `/app/bff/main.py`
      flattened   host `node_manager.py`  -> container `/app/node_manager.py`
                  (node_manager/Dockerfile COPYs each file to /app/<name>.py)

    Scoring beats requiring a unique anchor. node-manager's image contains the
    source TWICE — once flattened by the Dockerfile at /app/*.py and once via a
    bind mount at /app/node_manager/* — so every anchor had two candidates and
    the earlier version refused to guess, leaving the service unchecked.

    Which copy is right is not a toss-up: `uvicorn node_manager:app` imports
    /app/node_manager.py, and /app/node_manager/ has no __init__.py so it is
    never imported. Preferring the root that matches the MOST files, and
    breaking ties toward the shallower root, lands on the code that actually
    runs.
    """
    rels = [f.relative_to(ctx_dir).as_posix() for f in host_files]
    roots = {}
    for path in table:
        for rel in rels:
            if path.endswith("/" + rel):
                roots.setdefault(path[: -len(rel)], set()).add(("structured", rel))
            elif path.endswith("/" + rel.rsplit("/", 1)[-1]) and "/" not in rel:
                roots.setdefault(path.rsplit("/", 1)[0] + "/", set()).add(("flat", rel))
    if not roots:
        return None

    def score(item):
        root, hits = item
        return (len(hits), -root.count("/"))       # most files, then shallowest

    root, hits = max(roots.items(), key=score)
    flattened = all(kind == "flat" for kind, _ in hits)
    return root, flattened, len(hits)


def check(svc, ctx, live):
    if svc not in live:
        return None
    ctx_dir = ROOT / ctx
    if not ctx_dir.is_dir():
        return None

    table = container_hashes(svc)
    if not table:
        print(f"?      {svc}: could not read source from the container")
        return None

    host_files = [f for f in sorted(ctx_dir.rglob("*.py"))
                  if "__pycache__" not in f.parts]
    if not host_files:
        return None

    layout = _resolve_layout(host_files, ctx_dir, table)
    if layout is None:
        print(f"?      {svc}: could not locate this build context inside the image")
        return None
    root, flattened, _ = layout

    drift, checked = [], 0
    for f in host_files:
        rel = f.relative_to(ctx_dir).as_posix()
        key = root + (rel.rsplit("/", 1)[-1] if flattened else rel)
        digest = table.get(key)
        if digest is None:
            continue          # not shipped in this image; not drift
        checked += 1
        if md5(f) != digest:
            drift.append(rel)

    shape = "flattened" if flattened else "structured"
    if drift:
        print(f"STALE  {svc} — {len(drift)} of {checked} file(s) differ from the image")
        for d in drift[:8]:
            print(f"         {d}")
        if len(drift) > 8:
            print(f"         ... and {len(drift) - 8} more")
        print(f"       fix: docker compose build {svc} && docker compose up -d {svc}")
    else:
        print(f"ok     {svc} ({checked} file(s) match, root {root} {shape})")
    return bool(drift)


def main():
    want = sys.argv[1] if len(sys.argv) > 1 else None
    live = running()
    if not live:
        print("No running containers — nothing to compare.")
        return 0

    results = []
    for svc, ctx in SERVICES.items():
        if want and svc != want:
            continue
        r = check(svc, ctx, live)
        if r is not None:
            results.append((svc, r))

    stale = [s for s, bad in results if bad]
    print()
    if stale:
        print(f"{len(stale)} service(s) running stale code: {', '.join(stale)}")
        print("A restart will NOT fix this — these images must be rebuilt.")
        return 1
    print(f"All {len(results)} running built service(s) match this working tree.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
